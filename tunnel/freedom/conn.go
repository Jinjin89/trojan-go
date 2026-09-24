package freedom

import (
	"bytes"
	"net"

	"github.com/txthinking/socks5"

	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/tunnel"
)

const MaxPacketSize = 1024 * 8

type Conn struct {
	net.Conn
}

func (c *Conn) Metadata() *tunnel.Metadata {
	return nil
}

// maxResolveCacheSize bounds the per-session cache of resolved udp targets
const maxResolveCacheSize = 256

type PacketConn struct {
	*net.UDPConn
	preferIPv4 bool
	// resolved caches domain name lookups, so that a udp session does not
	// query DNS for every single packet. only the writing goroutine uses it.
	resolved map[string]*net.UDPAddr
}

func (c *PacketConn) WriteWithMetadata(p []byte, m *tunnel.Metadata) (int, error) {
	return c.WriteTo(p, m.Address)
}

func (c *PacketConn) ReadWithMetadata(p []byte) (int, *tunnel.Metadata, error) {
	n, addr, err := c.ReadFrom(p)
	if err != nil {
		return 0, nil, err
	}
	address, err := tunnel.NewAddressFromAddr("udp", addr.String())
	if err != nil {
		return 0, nil, err
	}
	metadata := &tunnel.Metadata{
		Address: address,
	}
	return n, metadata, nil
}

func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		return c.WriteToUDP(p, udpAddr)
	}
	address, ok := addr.(*tunnel.Address)
	if !ok {
		return 0, common.NewError("unsupported udp address type " + addr.String())
	}
	network := "udp"
	if c.preferIPv4 {
		// the socket is udp4, so the target must resolve to an ipv4 address
		network = "udp4"
	}
	key := address.String()
	udpAddr, found := c.resolved[key]
	if !found {
		var err error
		udpAddr, err = net.ResolveUDPAddr(network, key)
		if err != nil {
			return 0, err
		}
		if c.resolved == nil || len(c.resolved) >= maxResolveCacheSize {
			c.resolved = make(map[string]*net.UDPAddr)
		}
		c.resolved[key] = udpAddr
	}
	return c.WriteToUDP(p, udpAddr)
}

type SocksPacketConn struct {
	net.PacketConn
	socksAddr   *net.UDPAddr
	socksClient *socks5.Client
}

func (c *SocksPacketConn) WriteWithMetadata(payload []byte, metadata *tunnel.Metadata) (int, error) {
	buf := bytes.NewBuffer(make([]byte, 0, MaxPacketSize))
	buf.Write([]byte{0, 0, 0}) // RSV, FRAG
	common.Must(metadata.Address.WriteTo(buf))
	buf.Write(payload)
	_, err := c.PacketConn.WriteTo(buf.Bytes(), c.socksAddr)
	if err != nil {
		return 0, err
	}
	log.Debug("sent udp packet to " + c.socksAddr.String() + " with metadata " + metadata.String())
	return len(payload), nil
}

func (c *SocksPacketConn) ReadWithMetadata(payload []byte) (int, *tunnel.Metadata, error) {
	buf := make([]byte, MaxPacketSize)
	n, from, err := c.PacketConn.ReadFrom(buf)
	if err != nil {
		return 0, nil, err
	}
	log.Debug("recv udp packet from " + from.String())
	addr := new(tunnel.Address)
	r := bytes.NewBuffer(buf[3:n])
	if err := addr.ReadFrom(r); err != nil {
		return 0, nil, common.NewError("socks5 failed to parse addr in the packet").Base(err)
	}
	length, err := r.Read(payload)
	if err != nil {
		return 0, nil, err
	}
	return length, &tunnel.Metadata{
		Address: addr,
	}, nil
}

func (c *SocksPacketConn) Close() error {
	c.socksClient.Close()
	return c.PacketConn.Close()
}
