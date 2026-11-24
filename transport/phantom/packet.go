package phantom

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"
)

var _ net.PacketConn = (*PacketConn)(nil)

// PacketConn adapts a CmdUDP TunnelConn stream into a net.PacketConn using PhantomTLS
// length-delimited UDPDatagram framing for domains, IPv4, and IPv6 targets.
type PacketConn struct {
	conn    *TunnelConn
	readMu  sync.Mutex
	writeMu sync.Mutex
}

// NewPacketConn wraps an established CmdUDP TunnelConn as a net.PacketConn.
func NewPacketConn(conn *TunnelConn) *PacketConn {
	return &PacketConn{conn: conn}
}

func (pc *PacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		return 0, errors.New("phantom udp write: nil target addr")
	}

	var host string
	var port uint16
	switch a := addr.(type) {
	case *net.UDPAddr:
		if a.IP != nil {
			host = a.IP.String()
		}
		port = uint16(a.Port)
	default:
		h, pStr, err := net.SplitHostPort(addr.String())
		if err != nil {
			return 0, err
		}
		pNum, err := strconv.ParseUint(pStr, 10, 16)
		if err != nil {
			return 0, err
		}
		host = h
		port = uint16(pNum)
	}

	if host == "" || port == 0 {
		return 0, errors.New("phantom udp write: invalid target host or port")
	}

	addrType, normAddr := ParseTargetAddr(host)
	pc.writeMu.Lock()
	err := WriteUDPDatagram(pc.conn, UDPDatagram{
		AddrType: addrType,
		Addr:     normAddr,
		Port:     port,
		Data:     b,
	})
	pc.writeMu.Unlock()
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (pc *PacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	pc.readMu.Lock()
	d, err := ReadUDPDatagram(pc.conn)
	pc.readMu.Unlock()
	if err != nil {
		return 0, nil, err
	}

	var raddr net.Addr
	if ip := net.ParseIP(d.Addr); ip != nil {
		raddr = &net.UDPAddr{IP: ip, Port: int(d.Port)}
	} else {
		raddr = &udpDomainAddr{host: d.Addr, port: d.Port}
	}

	n := copy(b, d.Data)
	return n, raddr, nil
}

func (pc *PacketConn) Close() error                       { return pc.conn.Close() }
func (pc *PacketConn) LocalAddr() net.Addr                { return pc.conn.LocalAddr() }
func (pc *PacketConn) SetDeadline(t time.Time) error      { return pc.conn.SetDeadline(t) }
func (pc *PacketConn) SetReadDeadline(t time.Time) error  { return pc.conn.SetReadDeadline(t) }
func (pc *PacketConn) SetWriteDeadline(t time.Time) error { return pc.conn.SetWriteDeadline(t) }

type udpDomainAddr struct {
	host string
	port uint16
}

func (a *udpDomainAddr) Network() string { return "udp" }
func (a *udpDomainAddr) String() string  { return net.JoinHostPort(a.host, strconv.Itoa(int(a.port))) }
