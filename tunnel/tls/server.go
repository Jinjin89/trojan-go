package tls

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/redirector"
	"github.com/p4gefau1t/trojan-go/tunnel"
	"github.com/p4gefau1t/trojan-go/tunnel/tls/fingerprint"
	"github.com/p4gefau1t/trojan-go/tunnel/transport"
	"github.com/p4gefau1t/trojan-go/tunnel/websocket"
)

// Server is a tls server
type Server struct {
	fallbackAddress    *tunnel.Address
	verifySNI          bool
	sni                string
	alpn               []string
	PreferServerCipher bool
	keyPair            []tls.Certificate
	keyPairLock        sync.RWMutex
	httpResp           []byte
	cipherSuite        []uint16
	sessionTicket      bool
	curve              []tls.CurveID
	keyLogger          io.WriteCloser
	connChan           chan tunnel.Conn
	wsChan             chan tunnel.Conn
	redir              *redirector.Redirector
	ctx                context.Context
	cancel             context.CancelFunc
	underlay           tunnel.Server
	nextHTTP           int32
	portOverrider      map[string]int
}

func (s *Server) Close() error {
	s.cancel()
	if s.keyLogger != nil {
		s.keyLogger.Close()
	}
	return s.underlay.Close()
}

// handshakeTimeout bounds the time an inbound connection may spend in the TLS
// handshake and in sending its first request. Without it, idle or malicious
// connections pin goroutines and file descriptors forever.
const handshakeTimeout = 15 * time.Second

func isDomainNameMatched(pattern string, domainName string) bool {
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[2:]
		domainPrefixLen := len(domainName) - len(suffix) - 1
		return strings.HasSuffix(domainName, suffix) && domainPrefixLen > 0 && !strings.Contains(domainName[:domainPrefixLen], ".")
	}
	return pattern == domainName
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil {
			select {
			case <-s.ctx.Done():
			default:
				log.Fatal(common.NewError("transport accept error" + err.Error()))
			}
			return
		}
		go func(conn net.Conn) {
			tlsConfig := &tls.Config{
				CipherSuites:             s.cipherSuite,
				PreferServerCipherSuites: s.PreferServerCipher,
				SessionTicketsDisabled:   !s.sessionTicket,
				NextProtos:               s.alpn,
				KeyLogWriter:             s.keyLogger,
				GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					s.keyPairLock.RLock()
					defer s.keyPairLock.RUnlock()
					sni := s.keyPair[0].Leaf.Subject.CommonName
					dnsNames := s.keyPair[0].Leaf.DNSNames
					if s.sni != "" {
						sni = s.sni
					}
					matched := isDomainNameMatched(sni, hello.ServerName)
					for _, name := range dnsNames {
						if isDomainNameMatched(name, hello.ServerName) {
							matched = true
							break
						}
					}
					// clients without SNI (e.g. connecting by IP) get the default certificate,
					// just like a normal web server would serve its default site
					if s.verifySNI && !matched && hello.ServerName != "" {
						return nil, common.NewError("sni mismatched: " + hello.ServerName + ", expected: " + sni)
					}
					return &s.keyPair[0], nil
				},
			}

			// ------------------------ WAR ZONE ----------------------------

			handshakeRewindConn := common.NewRewindConn(conn)
			handshakeRewindConn.SetBufferSize(2048)

			tlsConn := tls.Server(handshakeRewindConn, tlsConfig)
			conn.SetDeadline(time.Now().Add(handshakeTimeout))
			err := tlsConn.Handshake()
			handshakeRewindConn.StopBuffering()

			if err != nil {
				if strings.Contains(err.Error(), "first record does not look like a TLS handshake") {
					// not a valid tls client hello
					handshakeRewindConn.Rewind()
					conn.SetDeadline(time.Time{})
					log.Debug(common.NewError("failed to perform tls handshake with " + tlsConn.RemoteAddr().String() + ", redirecting").Base(err))
					switch {
					case s.fallbackAddress != nil:
						s.redir.Redirect(&redirector.Redirection{
							InboundConn: handshakeRewindConn,
							RedirectTo:  s.fallbackAddress,
						})
					case s.httpResp != nil:
						handshakeRewindConn.Write(s.httpResp)
						handshakeRewindConn.Close()
					default:
						handshakeRewindConn.Close()
					}
				} else {
					// in other cases, simply close it. these are almost always scanners
					// or broken clients, so keep them out of the error log
					tlsConn.Close()
					log.Debug(common.NewError("tls handshake failed from " + conn.RemoteAddr().String()).Base(err))
				}
				return
			}

			log.Info("tls connection from", conn.RemoteAddr())
			state := tlsConn.ConnectionState()
			log.Trace("tls handshake", tls.CipherSuiteName(state.CipherSuite), state.DidResume, state.NegotiatedProtocol)

			// we use a real http header parser to mimic a real http server
			rewindConn := common.NewRewindConn(tlsConn)
			rewindConn.SetBufferSize(1024)
			r := bufio.NewReader(rewindConn)
			httpReq, err := http.ReadRequest(r)
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// real clients send their request right after the handshake
				log.Debug("tls connection from", conn.RemoteAddr(), "sent nothing, closing")
				tlsConn.Close()
				return
			}
			rewindConn.Rewind()
			rewindConn.StopBuffering()
			// the upper layers set their own deadlines
			conn.SetDeadline(time.Time{})
			var ch chan tunnel.Conn
			if err != nil {
				// this is not a http request. pass it to trojan protocol layer for further inspection
				ch = s.connChan
			} else {
				if atomic.LoadInt32(&s.nextHTTP) != 1 {
					// there is no websocket layer waiting for connections, redirect it
					log.Debug("incoming http request, but no websocket server is listening")
					s.redir.Redirect(&redirector.Redirection{
						InboundConn: rewindConn,
						RedirectTo:  s.fallbackAddress,
					})
					return
				}
				// this is a http request, pass it to websocket protocol layer
				log.Debug("http req: ", httpReq)
				ch = s.wsChan
			}
			select {
			case ch <- &transport.Conn{Conn: rewindConn}:
			case <-s.ctx.Done():
				rewindConn.Close()
			}
		}(conn)
	}
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	if _, ok := overlay.(*websocket.Tunnel); ok {
		atomic.StoreInt32(&s.nextHTTP, 1)
		log.Debug("next proto http")
		// websocket overlay
		select {
		case conn := <-s.wsChan:
			return conn, nil
		case <-s.ctx.Done():
			return nil, common.NewError("transport server closed")
		}
	}
	// trojan overlay
	select {
	case conn := <-s.connChan:
		return conn, nil
	case <-s.ctx.Done():
		return nil, common.NewError("transport server closed")
	}
}

func (s *Server) AcceptPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) checkKeyPairLoop(checkRate time.Duration, keyPath string, certPath string, password string) {
	var lastKeyBytes, lastCertBytes []byte
	ticker := time.NewTicker(checkRate)

	defer ticker.Stop()

	check := func() {
		log.Debug("checking cert...")
		keyBytes, err := ioutil.ReadFile(keyPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check key").Base(err))
			return
		}
		certBytes, err := ioutil.ReadFile(certPath)
		if err != nil {
			log.Error(common.NewError("tls failed to check cert").Base(err))
			return
		}
		if !bytes.Equal(keyBytes, lastKeyBytes) || !bytes.Equal(lastCertBytes, certBytes) {
			log.Info("new key pair detected")
			keyPair, err := loadKeyPair(keyPath, certPath, password)
			if err != nil {
				log.Error(common.NewError("tls failed to load new key pair").Base(err))
				return
			}
			s.keyPairLock.Lock()
			s.keyPair = []tls.Certificate{*keyPair}
			s.keyPairLock.Unlock()
			lastKeyBytes = keyBytes
			lastCertBytes = certBytes
		}
	}

	for {
		check()
		select {
		case <-ticker.C:
			continue
		case <-s.ctx.Done():
			log.Debug("exiting")
			return
		}
	}
}

func loadKeyPair(keyPath string, certPath string, password string) (*tls.Certificate, error) {
	if password != "" {
		keyFile, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return nil, common.NewError("failed to load key file").Base(err)
		}
		keyBlock, _ := pem.Decode(keyFile)
		if keyBlock == nil {
			return nil, common.NewError("failed to decode key file")
		}
		decryptedKey, err := x509.DecryptPEMBlock(keyBlock, []byte(password))
		if err != nil {
			return nil, common.NewError("failed to decrypt key").Base(err)
		}

		certFile, err := ioutil.ReadFile(certPath)
		if err != nil {
			return nil, common.NewError("failed to load cert file").Base(err)
		}
		// tls.X509KeyPair expects PEM input for both arguments
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: keyBlock.Type, Bytes: decryptedKey})
		keyPair, err := tls.X509KeyPair(certFile, keyPEM)
		if err != nil {
			return nil, err
		}
		keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
		if err != nil {
			return nil, common.NewError("failed to parse leaf certificate").Base(err)
		}

		return &keyPair, nil
	}
	keyPair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, common.NewError("failed to load key pair").Base(err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, common.NewError("failed to parse leaf certificate").Base(err)
	}
	return &keyPair, nil
}

// NewServer creates a tls layer server
func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)

	var fallbackAddress *tunnel.Address
	var httpResp []byte
	if cfg.TLS.FallbackPort != 0 {
		if cfg.TLS.FallbackHost == "" {
			cfg.TLS.FallbackHost = cfg.RemoteHost
			log.Warn("empty tls fallback address")
		}
		fallbackAddress = tunnel.NewAddressFromHostPort("tcp", cfg.TLS.FallbackHost, cfg.TLS.FallbackPort)
		fallbackConn, err := net.DialTimeout("tcp", fallbackAddress.String(), 5*time.Second)
		if err != nil {
			log.Warn(common.NewError("tls fallback address is not reachable now: " + fallbackAddress.String()).Base(err))
		} else {
			fallbackConn.Close()
		}
	} else {
		log.Warn("empty tls fallback port")
		if cfg.TLS.HTTPResponseFileName != "" {
			httpRespBody, err := ioutil.ReadFile(cfg.TLS.HTTPResponseFileName)
			if err != nil {
				return nil, common.NewError("invalid response file").Base(err)
			}
			httpResp = httpRespBody
		} else {
			log.Warn("empty tls http response")
		}
	}

	keyPair, err := loadKeyPair(cfg.TLS.KeyPath, cfg.TLS.CertPath, cfg.TLS.KeyPassword)
	if err != nil {
		return nil, common.NewError("tls failed to load key pair").Base(err)
	}

	var keyLogger io.WriteCloser
	if cfg.TLS.KeyLogPath != "" {
		log.Warn("tls key logging activated. USE OF KEY LOGGING COMPROMISES SECURITY. IT SHOULD ONLY BE USED FOR DEBUGGING.")
		file, err := os.OpenFile(cfg.TLS.KeyLogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return nil, common.NewError("failed to open key log file").Base(err)
		}
		keyLogger = file
	}

	var cipherSuite []uint16
	if len(cfg.TLS.Cipher) != 0 {
		cipherSuite = fingerprint.ParseCipher(strings.Split(cfg.TLS.Cipher, ":"))
	}

	ctx, cancel := context.WithCancel(ctx)
	server := &Server{
		underlay:           underlay,
		fallbackAddress:    fallbackAddress,
		httpResp:           httpResp,
		verifySNI:          cfg.TLS.VerifyHostName,
		sni:                cfg.TLS.SNI,
		alpn:               cfg.TLS.ALPN,
		PreferServerCipher: cfg.TLS.PreferServerCipher,
		sessionTicket:      cfg.TLS.ReuseSession,
		connChan:           make(chan tunnel.Conn, 32),
		wsChan:             make(chan tunnel.Conn, 32),
		redir:              redirector.NewRedirector(ctx),
		keyPair:            []tls.Certificate{*keyPair},
		keyLogger:          keyLogger,
		cipherSuite:        cipherSuite,
		ctx:                ctx,
		cancel:             cancel,
	}

	go server.acceptLoop()
	if cfg.TLS.CertCheckRate > 0 {
		go server.checkKeyPairLoop(
			time.Second*time.Duration(cfg.TLS.CertCheckRate),
			cfg.TLS.KeyPath,
			cfg.TLS.CertPath,
			cfg.TLS.KeyPassword,
		)
	}

	log.Debug("tls server created")
	return server, nil
}
