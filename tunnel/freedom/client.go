package freedom

import (
	"context"
	"net"
	"time"

	"github.com/txthinking/socks5"
	"golang.org/x/net/proxy"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

// dialTimeout bounds outbound connection attempts. The OS default can be
// several minutes, which keeps clients waiting on unreachable targets.
const dialTimeout = 10 * time.Second

// ipv6Probes are well-known anycast addresses used to check ipv6 connectivity
var ipv6Probes = []string{
	"[2606:4700:4700::1111]:443", // Cloudflare DNS
	"[2001:4860:4860::8888]:443", // Google DNS
}

// ipv6Works reports whether this host can actually reach the internet over
// ipv6. Many servers have ipv6 addresses and a default route but no working
// connectivity; dialing ipv6 targets there only adds latency and failures.
func ipv6Works() bool {
	hasGlobal := false
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok && ipNet.IP.To4() == nil && ipNet.IP.IsGlobalUnicast() {
				hasGlobal = true
				break
			}
		}
	}
	if !hasGlobal {
		return false
	}
	result := make(chan bool, len(ipv6Probes))
	for _, addr := range ipv6Probes {
		go func(addr string) {
			conn, err := net.DialTimeout("tcp6", addr, 2*time.Second)
			if err == nil {
				conn.Close()
			}
			result <- err == nil
		}(addr)
	}
	for range ipv6Probes {
		if <-result {
			return true
		}
	}
	return false
}

type Client struct {
	preferIPv4   bool
	noDelay      bool
	keepAlive    bool
	ctx          context.Context
	cancel       context.CancelFunc
	forwardProxy bool
	proxyAddr    *tunnel.Address
	username     string
	password     string
}

func (c *Client) DialConn(addr *tunnel.Address, _ tunnel.Tunnel) (tunnel.Conn, error) {
	// forward proxy
	if c.forwardProxy {
		var auth *proxy.Auth
		if c.username != "" {
			auth = &proxy.Auth{
				User:     c.username,
				Password: c.password,
			}
		}
		dialer, err := proxy.SOCKS5("tcp", c.proxyAddr.String(), auth, proxy.Direct)
		if err != nil {
			return nil, common.NewError("freedom failed to init socks dialer")
		}
		conn, err := dialer.Dial("tcp", addr.String())
		if err != nil {
			return nil, common.NewError("freedom failed to dial target address via socks proxy " + addr.String()).Base(err)
		}
		return &Conn{
			Conn: conn,
		}, nil
	}
	network := "tcp"
	if c.preferIPv4 {
		network = "tcp4"
	}
	dialer := &net.Dialer{Timeout: dialTimeout}
	tcpConn, err := dialer.DialContext(c.ctx, network, addr.String())
	if err != nil {
		return nil, common.NewError("freedom failed to dial " + addr.String()).Base(err)
	}

	tcpConn.(*net.TCPConn).SetKeepAlive(c.keepAlive)
	tcpConn.(*net.TCPConn).SetNoDelay(c.noDelay)
	return &Conn{
		Conn: tcpConn,
	}, nil
}

func (c *Client) DialPacket(tunnel.Tunnel) (tunnel.PacketConn, error) {
	if c.forwardProxy {
		socksClient, err := socks5.NewClient(c.proxyAddr.String(), c.username, c.password, 0, 0)
		common.Must(err)
		if err := socksClient.Negotiate(&net.TCPAddr{}); err != nil {
			return nil, common.NewError("freedom failed to negotiate socks").Base(err)
		}
		a, addr, port, err := socks5.ParseAddress("1.1.1.1:53") // useless address
		common.Must(err)
		resp, err := socksClient.Request(socks5.NewRequest(socks5.CmdUDP, a, addr, port))
		if err != nil {
			return nil, common.NewError("freedom failed to dial udp to socks").Base(err)
		}
		// TODO fix hardcoded localhost
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, common.NewError("freedom failed to listen udp").Base(err)
		}
		socksAddr, err := net.ResolveUDPAddr("udp", resp.Address())
		if err != nil {
			return nil, common.NewError("freedom recv invalid socks bind addr").Base(err)
		}
		return &SocksPacketConn{
			PacketConn:  packetConn,
			socksAddr:   socksAddr,
			socksClient: socksClient,
		}, nil
	}
	network := "udp"
	if c.preferIPv4 {
		network = "udp4"
	}
	udpConn, err := net.ListenPacket(network, "")
	if err != nil {
		return nil, common.NewError("freedom failed to listen udp socket").Base(err)
	}
	return &PacketConn{
		UDPConn:    udpConn.(*net.UDPConn),
		preferIPv4: c.preferIPv4,
	}, nil
}

func (c *Client) Close() error {
	c.cancel()
	return nil
}

func NewClient(ctx context.Context, _ tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	addr := tunnel.NewAddressFromHostPort("tcp", cfg.ForwardProxy.ProxyHost, cfg.ForwardProxy.ProxyPort)
	ctx, cancel := context.WithCancel(ctx)
	preferIPv4 := cfg.TCP.PreferIPV4
	if !preferIPv4 && !cfg.ForwardProxy.Enabled && !ipv6Works() {
		log.Info("ipv6 connectivity is not available on this host, preferring ipv4 for outbound connections")
		preferIPv4 = true
	}
	return &Client{
		ctx:          ctx,
		cancel:       cancel,
		noDelay:      cfg.TCP.NoDelay,
		keepAlive:    cfg.TCP.KeepAlive,
		preferIPv4:   preferIPv4,
		forwardProxy: cfg.ForwardProxy.Enabled,
		proxyAddr:    addr,
		username:     cfg.ForwardProxy.Username,
		password:     cfg.ForwardProxy.Password,
	}, nil
}
