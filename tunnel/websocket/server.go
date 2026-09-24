package websocket

import (
	"bufio"
	"context"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/net/websocket"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// Fake response writer
// Websocket ServeHTTP method uses Hijack method to get the ReadWriter
type fakeHTTPResponseWriter struct {
	http.Hijacker
	http.ResponseWriter

	ReadWriter *bufio.ReadWriter
	Conn       net.Conn
}

func (w *fakeHTTPResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.Conn, w.ReadWriter, nil
}

type Server struct {
	underlay  tunnel.Server
	hostname  string
	path      string
	enabled   bool
	redirAddr net.Addr
	redir     *redirector.Redirector
	ctx       context.Context
	cancel    context.CancelFunc
	timeout   time.Duration
	connChan  chan tunnel.Conn
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

// acceptLoop accepts connections from the underlying layer and performs the
// websocket handshake for each of them concurrently. Handshaking inline would
// let a single slow or broken client stall every other incoming connection.
func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			log.Error(common.NewError("websocket failed to accept connection from underlying server").Base(err))
			continue
		}
		go func(conn tunnel.Conn) {
			wsConn, err := s.handshake(conn)
			if err != nil {
				log.Debug(err)
				return
			}
			select {
			case s.connChan <- wsConn:
			case <-s.ctx.Done():
				wsConn.Close()
			}
		}(conn)
	}
}

func (s *Server) handshake(conn tunnel.Conn) (tunnel.Conn, error) {
	if !s.enabled {
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: conn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("websocket is disabled. redirecting http request from " + conn.RemoteAddr().String())
	}
	// bound the time a client may take to complete the upgrade request
	conn.SetDeadline(time.Now().Add(s.timeout))
	rewindConn := common.NewRewindConn(conn)
	rewindConn.SetBufferSize(512)
	defer rewindConn.StopBuffering()
	rw := bufio.NewReadWriter(bufio.NewReader(rewindConn), bufio.NewWriter(rewindConn))
	req, err := http.ReadRequest(rw.Reader)
	if err != nil {
		log.Debug("invalid http request")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		conn.SetDeadline(time.Time{})
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("not a valid http request: " + conn.RemoteAddr().String()).Base(err)
	}
	if strings.ToLower(req.Header.Get("Upgrade")) != "websocket" || req.URL.Path != s.path {
		log.Debug("invalid http websocket handshake request")
		rewindConn.Rewind()
		rewindConn.StopBuffering()
		conn.SetDeadline(time.Time{})
		s.redir.Redirect(&redirector.Redirection{
			InboundConn: rewindConn,
			RedirectTo:  s.redirAddr,
		})
		return nil, common.NewError("not a valid websocket handshake request: " + conn.RemoteAddr().String())
	}

	url := "wss://" + s.hostname + s.path
	origin := "https://" + s.hostname
	wsConfig, err := websocket.NewConfig(url, origin)
	if err != nil {
		conn.Close()
		return nil, common.NewError("failed to create websocket config").Base(err)
	}
	// buffered, so that a late handshake never blocks the handler goroutine forever
	handshake := make(chan *websocket.Conn, 1)
	ctx, cancel := context.WithCancel(s.ctx)

	wsServer := websocket.Server{
		Config: *wsConfig,
		Handler: func(wsConn *websocket.Conn) {
			wsConn.PayloadType = websocket.BinaryFrame // treat it as a binary websocket

			log.Debug("websocket obtained")
			handshake <- wsConn
			// this function SHOULD NOT return unless the connection is ended
			// or the websocket will be closed by ServeHTTP method
			<-ctx.Done()
			log.Debug("websocket closed")
		},
		Handshake: func(wsConfig *websocket.Config, httpRequest *http.Request) error {
			log.Debug("websocket url", httpRequest.URL, "origin", httpRequest.Header.Get("Origin"))
			return nil
		},
	}

	respWriter := &fakeHTTPResponseWriter{
		Conn:       conn,
		ReadWriter: rw,
	}
	served := make(chan struct{})
	go func() {
		wsServer.ServeHTTP(respWriter, req)
		close(served)
	}()

	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	select {
	case wsConn := <-handshake:
		conn.SetDeadline(time.Time{})
		return &InboundConn{
			OutboundConn: OutboundConn{
				tcpConn: conn,
				Conn:    wsConn,
			},
			ctx:    ctx,
			cancel: cancel,
		}, nil
	case <-served:
		// ServeHTTP returned without calling the handler: the upgrade was rejected
	case <-timer.C:
	case <-s.ctx.Done():
	}
	cancel()
	conn.Close()
	return nil, common.NewError("websocket failed to handshake with " + conn.RemoteAddr().String())
}

func (s *Server) AcceptConn(tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("websocket server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	return nil, common.NewError("not supported")
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	if cfg.Websocket.Enabled {
		if !strings.HasPrefix(cfg.Websocket.Path, "/") {
			return nil, common.NewError("websocket path must start with \"/\"")
		}
	}
	if cfg.RemoteHost == "" {
		log.Warn("empty websocket redirection hostname")
		cfg.RemoteHost = cfg.Websocket.Host
	}
	if cfg.RemotePort == 0 {
		log.Warn("empty websocket redirection port")
		cfg.RemotePort = 80
	}
	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		enabled:   cfg.Websocket.Enabled,
		hostname:  cfg.Websocket.Host,
		path:      cfg.Websocket.Path,
		ctx:       ctx,
		cancel:    cancel,
		underlay:  underlay,
		timeout:   time.Second * time.Duration(rand.Intn(10)+5),
		redir:     redirector.NewRedirector(ctx),
		redirAddr: tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
		connChan:  make(chan tunnel.Conn, 32),
	}
	go server.acceptLoop()
	log.Debug("websocket server created")
	return server, nil
}
