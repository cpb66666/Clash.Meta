package phantom

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	FrameData        byte = 0x01
	FrameCloseAlert  byte = 0x02
	FrameDummyTicket byte = 0x03

	CmdTCP byte = 0x01
	CmdUDP byte = 0x02

	AddrTypeIPv4   byte = 0x01
	AddrTypeDomain byte = 0x03
	AddrTypeIPv6   byte = 0x04

	ShapedPacketsLimit = 6
	MaxFramePayload    = 16363
	MinFastChunk       = 12000
	MaxShapedPadding   = 256
	MinShapedPadding   = 16
)

var recordBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 5+MaxTLSRecordPayload+256)
		return &b
	},
}

var (
	ErrInvalidRecord = errors.New("invalid tunnel TLS record")
	ErrInvalidFrame  = errors.New("invalid tunnel inner frame")
	ErrInvalidHeader = errors.New("invalid request header")
)

// RequestHeader is carried inside the first encrypted application payload from client to server.
type RequestHeader struct {
	Cmd      byte
	AddrType byte
	Addr     string
	Port     uint16
}

// TargetAddress formats Addr:Port cleanly for net.Dial.
func (h RequestHeader) TargetAddress() string {
	return net.JoinHostPort(h.Addr, strconv.Itoa(int(h.Port)))
}

// EncodeRequestHeader encodes RequestHeader followed by optional initialPayload.
func EncodeRequestHeader(h RequestHeader, initialPayload []byte) ([]byte, error) {
	addrBytes, err := encodeAddress(h.AddrType, h.Addr)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 1+len(addrBytes)+2+len(initialPayload))
	out[0] = h.Cmd
	copy(out[1:], addrBytes)
	off := 1 + len(addrBytes)
	binary.BigEndian.PutUint16(out[off:off+2], h.Port)
	copy(out[off+2:], initialPayload)
	return out, nil
}

// DecodeRequestHeader decodes RequestHeader from buf and returns any trailing initial payload.
func DecodeRequestHeader(buf []byte) (RequestHeader, []byte, error) {
	var h RequestHeader
	if len(buf) < 4 {
		return h, nil, ErrInvalidHeader
	}
	h.Cmd = buf[0]
	if h.Cmd != CmdTCP && h.Cmd != CmdUDP {
		return h, nil, ErrInvalidHeader
	}
	addrType, addr, consumed, err := decodeAddress(buf[1:])
	if err != nil {
		return h, nil, err
	}
	off := 1 + consumed
	if off+2 > len(buf) {
		return h, nil, ErrInvalidHeader
	}
	h.AddrType = addrType
	h.Addr = addr
	h.Port = binary.BigEndian.Uint16(buf[off : off+2])
	return h, buf[off+2:], nil
}

// ReadRequestHeader reads exact self-delimiting RequestHeader bytes from stream r,
// leaving any subsequent payload bytes unread on r.
func ReadRequestHeader(r io.Reader) (RequestHeader, error) {
	var h RequestHeader
	var head [2]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return h, err
	}
	h.Cmd = head[0]
	if h.Cmd != CmdTCP && h.Cmd != CmdUDP {
		return h, ErrInvalidHeader
	}
	h.AddrType = head[1]
	switch h.AddrType {
	case AddrTypeIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return h, err
		}
		h.Addr = net.IP(ip[:]).String()
	case AddrTypeIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return h, err
		}
		h.Addr = net.IP(ip[:]).String()
	case AddrTypeDomain:
		var l [1]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return h, err
		}
		if l[0] == 0 {
			return h, ErrInvalidHeader
		}
		dom := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, dom); err != nil {
			return h, err
		}
		h.Addr = string(dom)
	default:
		return h, ErrInvalidHeader
	}
	var portBuf [2]byte
	if _, err := io.ReadFull(r, portBuf[:]); err != nil {
		return h, err
	}
	h.Port = binary.BigEndian.Uint16(portBuf[:])
	return h, nil
}

// ParseTargetAddr converts host into AddrType and normalized Addr string.
func ParseTargetAddr(host string) (byte, string) {
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			return AddrTypeIPv4, ip4.String()
		}
		return AddrTypeIPv6, ip.String()
	}
	return AddrTypeDomain, host
}

func encodeAddress(addrType byte, addr string) ([]byte, error) {
	switch addrType {
	case AddrTypeIPv4:
		ip := net.ParseIP(addr).To4()
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid ipv4 %q", ErrInvalidHeader, addr)
		}
		out := make([]byte, 5)
		out[0] = AddrTypeIPv4
		copy(out[1:5], ip)
		return out, nil
	case AddrTypeIPv6:
		ip := net.ParseIP(addr).To16()
		if ip == nil {
			return nil, fmt.Errorf("%w: invalid ipv6 %q", ErrInvalidHeader, addr)
		}
		out := make([]byte, 17)
		out[0] = AddrTypeIPv6
		copy(out[1:17], ip)
		return out, nil
	case AddrTypeDomain:
		if len(addr) == 0 || len(addr) > 255 {
			return nil, fmt.Errorf("%w: invalid domain length", ErrInvalidHeader)
		}
		out := make([]byte, 2+len(addr))
		out[0] = AddrTypeDomain
		out[1] = byte(len(addr))
		copy(out[2:], addr)
		return out, nil
	default:
		return nil, fmt.Errorf("%w: unknown addr type %d", ErrInvalidHeader, addrType)
	}
}

func decodeAddress(buf []byte) (addrType byte, addr string, consumed int, err error) {
	if len(buf) < 1 {
		return 0, "", 0, ErrInvalidHeader
	}
	addrType = buf[0]
	switch addrType {
	case AddrTypeIPv4:
		if len(buf) < 5 {
			return 0, "", 0, ErrInvalidHeader
		}
		return addrType, net.IP(buf[1:5]).String(), 5, nil
	case AddrTypeIPv6:
		if len(buf) < 17 {
			return 0, "", 0, ErrInvalidHeader
		}
		return addrType, net.IP(buf[1:17]).String(), 17, nil
	case AddrTypeDomain:
		if len(buf) < 2 {
			return 0, "", 0, ErrInvalidHeader
		}
		dlen := int(buf[1])
		if dlen == 0 || len(buf) < 2+dlen {
			return 0, "", 0, ErrInvalidHeader
		}
		return addrType, string(buf[2 : 2+dlen]), 2 + dlen, nil
	default:
		return 0, "", 0, ErrInvalidHeader
	}
}

// UDPDatagram represents a single UDP packet routed through the tunnel.
type UDPDatagram struct {
	AddrType byte
	Addr     string
	Port     uint16
	Data     []byte
}

// WriteUDPDatagram writes a length-prefixed UDP datagram over stream w.
func WriteUDPDatagram(w io.Writer, d UDPDatagram) error {
	addrBytes, err := encodeAddress(d.AddrType, d.Addr)
	if err != nil {
		return err
	}
	bodyLen := len(addrBytes) + 2 + len(d.Data)
	if bodyLen > 65535 {
		return errors.New("udp datagram too large")
	}
	pkt := make([]byte, 2+bodyLen)
	binary.BigEndian.PutUint16(pkt[0:2], uint16(bodyLen))
	copy(pkt[2:], addrBytes)
	off := 2 + len(addrBytes)
	binary.BigEndian.PutUint16(pkt[off:off+2], d.Port)
	copy(pkt[off+2:], d.Data)
	_, err = w.Write(pkt)
	return err
}

// ReadUDPDatagram reads a length-prefixed UDP datagram from stream r.
func ReadUDPDatagram(r io.Reader) (UDPDatagram, error) {
	var d UDPDatagram
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return d, err
	}
	bodyLen := int(binary.BigEndian.Uint16(lenBuf[:]))
	if bodyLen < 4 {
		return d, ErrInvalidFrame
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return d, err
	}
	addrType, addr, consumed, err := decodeAddress(body)
	if err != nil {
		return d, err
	}
	if consumed+2 > len(body) {
		return d, ErrInvalidFrame
	}
	d.AddrType = addrType
	d.Addr = addr
	d.Port = binary.BigEndian.Uint16(body[consumed : consumed+2])
	d.Data = body[consumed+2:]
	return d, nil
}

// TunnelConn wraps a net.Conn with TLS 1.3 ApplicationData AEAD framing,
// dynamic first-6-packet shaping, and zero-padding fast path from packet 7 onward.
type TunnelConn struct {
	raw net.Conn

	readMu   sync.Mutex
	readAEAD cipher.AEAD
	readSeq  uint64
	readBuf  []byte
	peerEOF  bool
	readPads []int

	writeMu       sync.Mutex
	writeAEAD     cipher.AEAD
	writeSeq      uint64
	writePktCount uint64
	shapedCount   uint64
	fastCount     uint64
	writePads     []int
	prngState     uint64
	writeClosed   bool
}

func newAEADByCipher(key [32]byte, cipherID uint8) (cipher.AEAD, error) {
	switch cipherID {
	case CipherAES128GCM:
		block, err := aes.NewCipher(key[:16])
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return chacha20poly1305.New(key[:])
	}
}

// NewTunnelConn constructs a TunnelConn unpacking cipher selection from packedShapeSeed.
func NewTunnelConn(raw net.Conn, readKey [32]byte, writeKey [32]byte, packedShapeSeed uint32) (*TunnelConn, error) {
	seed28, cipherID := UnpackShapeSeed(packedShapeSeed)
	return NewTunnelConnWithCipher(raw, readKey, writeKey, seed28, cipherID)
}

// NewTunnelConnWithCipher constructs a TunnelConn with explicit directional AEAD keys, seed, and cipherID.
func NewTunnelConnWithCipher(raw net.Conn, readKey [32]byte, writeKey [32]byte, shapeSeed uint32, cipherID uint8) (*TunnelConn, error) {
	rAEAD, err := newAEADByCipher(readKey, cipherID)
	if err != nil {
		return nil, err
	}
	wAEAD, err := newAEADByCipher(writeKey, cipherID)
	if err != nil {
		return nil, err
	}
	seed := uint64(shapeSeed) | (uint64(shapeSeed^0x9e3779b9) << 32)
	if seed == 0 {
		seed = 0xdeadbeefcafebabe
	}
	return &TunnelConn{
		raw:       raw,
		readAEAD:  rAEAD,
		writeAEAD: wAEAD,
		prngState: seed,
	}, nil
}

func makeDataNonce(seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], "phdt")
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

func (c *TunnelConn) nextPRNG() uint64 {
	c.prngState += 0x9e3779b97f4a7c15
	z := c.prngState
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (c *TunnelConn) fillDeterministicBytes(dst []byte) {
	var v uint64
	for i := 0; i < len(dst); i++ {
		if i&7 == 0 {
			v = c.nextPRNG()
		}
		dst[i] = byte(v)
		v >>= 8
	}
}

// Write encrypts and sends p as one or more TLS 1.3 ApplicationData records.
func (c *TunnelConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeClosed {
		return 0, net.ErrClosed
	}

	written := 0
	rem := p
	for len(rem) > 0 {
		chunkLen := len(rem)
		padLen := 0

		if c.writePktCount < ShapedPacketsLimit {
			maxShapedPayload := MaxFramePayload - MaxShapedPadding
			if chunkLen > maxShapedPayload {
				chunkLen = maxShapedPayload
			}
			if chunkLen > 400 {
				limit := chunkLen
				if limit > 1000 {
					limit = 1000
				}
				minPart := 140
				maxPart := limit - 120
				if maxPart > minPart {
					chunkLen = minPart + int(c.nextPRNG()%uint64(maxPart-minPart+1))
				}
			}
			padLen = MinShapedPadding + int(c.nextPRNG()%uint64(MaxShapedPadding-MinShapedPadding+1))
			c.shapedCount++
		} else {
			if chunkLen > MinFastChunk {
				limit := MinFastChunk + int(c.nextPRNG()%uint64(MaxFramePayload-MinFastChunk+1))
				if chunkLen > limit {
					chunkLen = limit
				}
			}
			c.fastCount++
		}

		if err := c.writeFrameLocked(FrameData, rem[:chunkLen], padLen, true); err != nil {
			return written, err
		}
		if len(c.writePads) < 16 {
			c.writePads = append(c.writePads, padLen)
		}
		written += chunkLen
		rem = rem[chunkLen:]
	}
	return written, nil
}

// SendDummySessionTicket emits a 181..261B encrypted TLS 1.3 ApplicationData frame immediately
// after handshake completion to mimic real server NewSessionTicket emission with zero extra RTT.
func (c *TunnelConn) SendDummySessionTicket() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return net.ErrClosed
	}
	padLen := 160 + int(c.nextPRNG()%81)
	return c.writeFrameLocked(FrameDummyTicket, nil, padLen, false)
}

func (c *TunnelConn) writeFrameLocked(frameType byte, payload []byte, padLen int, countPkt bool) error {
	ptLen := 5 + len(payload) + padLen
	recLen := ptLen + c.writeAEAD.Overhead()

	bufPtr := recordBufPool.Get().(*[]byte)
	defer recordBufPool.Put(bufPtr)
	out := (*bufPtr)[:5+recLen]

	out[0] = RecordTypeApplicationData
	out[1] = 0x03
	out[2] = 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(recLen))

	pt := out[5 : 5+ptLen]
	pt[0] = frameType
	binary.BigEndian.PutUint16(pt[1:3], uint16(padLen))
	binary.BigEndian.PutUint16(pt[3:5], uint16(len(payload)))
	copy(pt[5:5+len(payload)], payload)
	if padLen > 0 {
		c.fillDeterministicBytes(pt[5+len(payload):])
	}

	nonce := makeDataNonce(c.writeSeq)
	c.writeSeq++
	if countPkt {
		c.writePktCount++
	}

	c.writeAEAD.Seal(out[:5], nonce[:], pt, out[:5])

	_, err := c.raw.Write(out)
	return err
}

// Read reads and decrypts application data from the TLS 1.3 ApplicationData tunnel stream.
func (c *TunnelConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for len(c.readBuf) == 0 {
		if c.peerEOF {
			return 0, io.EOF
		}

		var hdr [5]byte
		if _, err := io.ReadFull(c.raw, hdr[:]); err != nil {
			return 0, err
		}
		if hdr[0] != RecordTypeApplicationData || hdr[1] != 0x03 {
			return 0, ErrInvalidRecord
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen < c.readAEAD.Overhead()+3 || recLen > MaxTLSRecordPayload+256 {
			return 0, ErrInvalidRecord
		}

		bufPtr := recordBufPool.Get().(*[]byte)
		ct := (*bufPtr)[:recLen]
		if _, err := io.ReadFull(c.raw, ct); err != nil {
			recordBufPool.Put(bufPtr)
			return 0, err
		}

		nonce := makeDataNonce(c.readSeq)
		c.readSeq++

		pt, err := c.readAEAD.Open(ct[:0], nonce[:], ct, hdr[:])
		if err != nil || len(pt) < 3 {
			recordBufPool.Put(bufPtr)
			return 0, ErrInvalidFrame
		}

		if len(pt) == 3 && pt[0] == FrameCloseAlert {
			recordBufPool.Put(bufPtr)
			c.peerEOF = true
			return 0, io.EOF
		}
		if len(pt) < 5 {
			recordBufPool.Put(bufPtr)
			return 0, ErrInvalidFrame
		}

		frameType := pt[0]
		padLen := int(binary.BigEndian.Uint16(pt[1:3]))
		payLen := int(binary.BigEndian.Uint16(pt[3:5]))
		if 5+payLen+padLen != len(pt) {
			recordBufPool.Put(bufPtr)
			return 0, ErrInvalidFrame
		}

		switch frameType {
		case FrameDummyTicket:
			recordBufPool.Put(bufPtr)
			continue
		case FrameCloseAlert:
			recordBufPool.Put(bufPtr)
			c.peerEOF = true
			return 0, io.EOF
		case FrameData:
			if len(c.readPads) < 16 {
				c.readPads = append(c.readPads, padLen)
			}
			if payLen > 0 {
				if len(b) >= payLen {
					n := copy(b, pt[5:5+payLen])
					recordBufPool.Put(bufPtr)
					return n, nil
				}
				c.readBuf = append(c.readBuf[:0], pt[5:5+payLen]...)
			}
			recordBufPool.Put(bufPtr)
		default:
			recordBufPool.Put(bufPtr)
			return 0, ErrInvalidFrame
		}
	}

	n := copy(b, c.readBuf)
	if n == len(c.readBuf) {
		c.readBuf = c.readBuf[:0]
	} else {
		c.readBuf = c.readBuf[n:]
	}
	return n, nil
}

// CloseWrite sends a compact 3-byte encrypted CloseAlert frame (19B total record payload).
func (c *TunnelConn) CloseWrite() error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.writeClosed {
		return nil
	}
	c.writeClosed = true

	const ptLen = 3
	recLen := ptLen + c.writeAEAD.Overhead()
	bufPtr := recordBufPool.Get().(*[]byte)
	defer recordBufPool.Put(bufPtr)
	out := (*bufPtr)[:5+recLen]

	out[0] = RecordTypeApplicationData
	out[1] = 0x03
	out[2] = 0x03
	binary.BigEndian.PutUint16(out[3:5], uint16(recLen))

	pt := out[5 : 5+ptLen]
	pt[0] = FrameCloseAlert
	pt[1] = 0x01
	pt[2] = 0x00

	nonce := makeDataNonce(c.writeSeq)
	c.writeSeq++
	c.writeAEAD.Seal(out[:5], nonce[:], pt, out[:5])

	_, err := c.raw.Write(out)
	return err
}

func (c *TunnelConn) Close() error {
	_ = c.raw.SetWriteDeadline(time.Now().Add(200 * time.Millisecond))
	_ = c.CloseWrite()
	return c.raw.Close()
}

func (c *TunnelConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *TunnelConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *TunnelConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *TunnelConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *TunnelConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
