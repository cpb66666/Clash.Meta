package phantom

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	utls "github.com/metacubex/utls"
)

const (
	RecordTypeChangeCipherSpec byte = 0x14
	RecordTypeAlert            byte = 0x15
	RecordTypeHandshake        byte = 0x16
	RecordTypeApplicationData  byte = 0x17

	HandshakeTypeClientHello byte = 0x01
	HandshakeTypeServerHello byte = 0x02

	ExtServerName        uint16 = 0x0000
	ExtSupportedVersions uint16 = 0x002b
	ExtKeyShare          uint16 = 0x0033

	CurveX25519  uint16 = 0x001d
	TLSVersion13 uint16 = 0x0304

	MaxTLSRecordPayload = 16384
)

var (
	ErrNotTLSClientHello = errors.New("not a TLS ClientHello record")
	ErrTruncatedRecord   = errors.New("truncated TLS record")
)

// ParsedClientHello holds key fields extracted non-destructively from a TLS ClientHello record.
type ParsedClientHello struct {
	Random         [32]byte
	SessionID      []byte
	CipherSuites   []uint16
	SNI            string
	X25519KeyShare [32]byte
	HasX25519      bool
	SupportsTLS13  bool
	RawRecord      []byte
}

// ReadFirstTLSRecordOrRaw reads the initial data from a client connection while capturing every
// received byte in rawBuf for lossless fallback.
func ReadFirstTLSRecordOrRaw(r io.Reader) (rawBuf []byte, isTLS bool, err error) {
	hdr := make([]byte, 5)
	readSoFar := 0
	for readSoFar < 5 {
		n, rErr := r.Read(hdr[readSoFar:])
		if n > 0 {
			readSoFar += n
			if readSoFar >= 1 && hdr[0] != RecordTypeHandshake {
				return append([]byte(nil), hdr[:readSoFar]...), false, nil
			}
			if readSoFar >= 2 && hdr[1] != 0x03 {
				return append([]byte(nil), hdr[:readSoFar]...), false, nil
			}
		}
		if rErr != nil {
			return append([]byte(nil), hdr[:readSoFar]...), false, rErr
		}
	}

	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen < 42 || recLen > MaxTLSRecordPayload {
		return append([]byte(nil), hdr[:5]...), false, nil
	}

	rawBuf = make([]byte, 5+recLen)
	copy(rawBuf[:5], hdr)
	payloadRead := 0
	for payloadRead < recLen {
		n, rErr := r.Read(rawBuf[5+payloadRead:])
		if n > 0 {
			payloadRead += n
		}
		if rErr != nil {
			return rawBuf[:5+payloadRead], false, rErr
		}
	}

	return rawBuf, true, nil
}

// ParseClientHelloRecord parses a complete initial TLS ClientHello record without mutating rawRecord.
func ParseClientHelloRecord(rawRecord []byte) (*ParsedClientHello, error) {
	if len(rawRecord) < 5+4+38 {
		return nil, ErrTruncatedRecord
	}
	if rawRecord[0] != RecordTypeHandshake || rawRecord[1] != 0x03 {
		return nil, ErrNotTLSClientHello
	}
	recLen := int(binary.BigEndian.Uint16(rawRecord[3:5]))
	if len(rawRecord) < 5+recLen || recLen < 42 {
		return nil, ErrTruncatedRecord
	}

	body := rawRecord[5 : 5+recLen]
	if body[0] != HandshakeTypeClientHello {
		return nil, ErrNotTLSClientHello
	}
	hsLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
	if 4+hsLen > len(body) || hsLen < 38 {
		return nil, ErrTruncatedRecord
	}

	p := body[4 : 4+hsLen]
	off := 0

	if off+2 > len(p) {
		return nil, ErrTruncatedRecord
	}
	off += 2

	if off+32 > len(p) {
		return nil, ErrTruncatedRecord
	}
	res := &ParsedClientHello{
		RawRecord: rawRecord,
	}
	copy(res.Random[:], p[off:off+32])
	off += 32

	if off+1 > len(p) {
		return nil, ErrTruncatedRecord
	}
	sidLen := int(p[off])
	off++
	if off+sidLen > len(p) {
		return nil, ErrTruncatedRecord
	}
	if sidLen > 0 {
		res.SessionID = make([]byte, sidLen)
		copy(res.SessionID, p[off:off+sidLen])
	}
	off += sidLen

	if off+2 > len(p) {
		return nil, ErrTruncatedRecord
	}
	csBytesLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if csBytesLen%2 != 0 || off+csBytesLen > len(p) {
		return nil, ErrTruncatedRecord
	}
	res.CipherSuites = make([]uint16, csBytesLen/2)
	for i := 0; i < len(res.CipherSuites); i++ {
		res.CipherSuites[i] = binary.BigEndian.Uint16(p[off+i*2 : off+i*2+2])
	}
	off += csBytesLen

	if off+1 > len(p) {
		return nil, ErrTruncatedRecord
	}
	compLen := int(p[off])
	off++
	if off+compLen > len(p) {
		return nil, ErrTruncatedRecord
	}
	off += compLen

	if off == len(p) {
		return res, nil
	}
	if off+2 > len(p) {
		return nil, ErrTruncatedRecord
	}
	extTotalLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+extTotalLen > len(p) {
		return nil, ErrTruncatedRecord
	}

	extEnd := off + extTotalLen
	for off < extEnd {
		if off+4 > extEnd {
			return nil, ErrTruncatedRecord
		}
		extType := binary.BigEndian.Uint16(p[off : off+2])
		extLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return nil, ErrTruncatedRecord
		}
		extData := p[off : off+extLen]
		off += extLen

		switch extType {
		case ExtServerName:
			sni, ok := parseSNIExtension(extData)
			if ok {
				res.SNI = sni
			}
		case ExtSupportedVersions:
			if len(extData) >= 1 {
				listLen := int(extData[0])
				if 1+listLen <= len(extData) && listLen%2 == 0 {
					for i := 1; i+1 < 1+listLen; i += 2 {
						if binary.BigEndian.Uint16(extData[i:i+2]) == TLSVersion13 {
							res.SupportsTLS13 = true
							break
						}
					}
				}
			}
		case ExtKeyShare:
			if xpub, ok := parseX25519KeyShare(extData); ok {
				res.X25519KeyShare = xpub
				res.HasX25519 = true
			}
		}
	}

	return res, nil
}

func parseSNIExtension(data []byte) (string, bool) {
	if len(data) < 2 {
		return "", false
	}
	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+listLen > len(data) {
		return "", false
	}
	pos := 2
	end := 2 + listLen
	for pos+3 <= end {
		nameType := data[pos]
		nameLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		pos += 3
		if pos+nameLen > end {
			return "", false
		}
		if nameType == 0x00 {
			return string(data[pos : pos+nameLen]), true
		}
		pos += nameLen
	}
	return "", false
}

func parseX25519KeyShare(data []byte) ([32]byte, bool) {
	var pub [32]byte
	if len(data) < 2 {
		return pub, false
	}
	sharesLen := int(binary.BigEndian.Uint16(data[0:2]))
	if 2+sharesLen > len(data) {
		return pub, false
	}
	pos := 2
	end := 2 + sharesLen
	for pos+4 <= end {
		group := binary.BigEndian.Uint16(data[pos : pos+2])
		klen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+klen > end {
			return pub, false
		}
		if group == CurveX25519 && klen == 32 {
			copy(pub[:], data[pos:pos+32])
			return pub, true
		}
		pos += klen
	}
	return pub, false
}

// ChromeHelloTemplate holds a uTLS Chrome ClientHello state ready for stego injection.
type ChromeHelloTemplate struct {
	uconn        *utls.UConn
	CipherSuites []uint16
}

// PrepareChromeHelloTemplate builds a realistic Chrome TLS 1.3 ClientHello template using uTLS
// (pure X25519 Chrome 120 fingerprint to ensure 1:1 ServerHello KeyShare parity with X25519 dests),
// injects the caller's ephemeral X25519 public key into its KeyShare extension, and exposes
// the exact CipherSuites list for AAD calculation before marshaling.
func PrepareChromeHelloTemplate(sni string, x25519Pub [32]byte) (*ChromeHelloTemplate, error) {
	uconn := utls.UClient(&nopConn{}, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_120)

	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, fmt.Errorf("utls build handshake state: %w", err)
	}

	hello := uconn.HandshakeState.Hello
	if hello == nil {
		return nil, errors.New("utls handshake hello is nil")
	}

	foundX25519 := false
	for _, ext := range uconn.Extensions {
		if kse, ok := ext.(*utls.KeyShareExtension); ok {
			for i := range kse.KeyShares {
				if kse.KeyShares[i].Group == utls.X25519 {
					buf := make([]byte, 32)
					copy(buf, x25519Pub[:])
					kse.KeyShares[i].Data = buf
					foundX25519 = true
				}
			}
			if !foundX25519 {
				buf := make([]byte, 32)
				copy(buf, x25519Pub[:])
				kse.KeyShares = append(kse.KeyShares, utls.KeyShare{
					Group: utls.X25519,
					Data:  buf,
				})
				foundX25519 = true
			}
		}
	}
	if !foundX25519 {
		return nil, errors.New("utls Chrome template missing KeyShareExtension")
	}

	suites := make([]uint16, len(hello.CipherSuites))
	copy(suites, hello.CipherSuites)
	return &ChromeHelloTemplate{
		uconn:        uconn,
		CipherSuites: suites,
	}, nil
}

// MarshalRecord injects random and sessionID into the Chrome ClientHello template,
// serializes it via uTLS, and wraps it in a standard TLS record header.
func (t *ChromeHelloTemplate) MarshalRecord(random [32]byte, sessionID [32]byte) ([]byte, error) {
	if t == nil || t.uconn == nil || t.uconn.HandshakeState.Hello == nil {
		return nil, errors.New("invalid ChromeHelloTemplate")
	}
	hello := t.uconn.HandshakeState.Hello
	hello.Random = make([]byte, 32)
	copy(hello.Random, random[:])
	hello.SessionId = make([]byte, 32)
	copy(hello.SessionId, sessionID[:])

	if err := t.uconn.MarshalClientHelloNoECH(); err != nil {
		return nil, fmt.Errorf("utls marshal client hello: %w", err)
	}
	rawHS := hello.Raw
	if len(rawHS) == 0 || len(rawHS) > MaxTLSRecordPayload {
		return nil, fmt.Errorf("unexpected ClientHello handshake length: %d", len(rawHS))
	}

	rec := make([]byte, 5+len(rawHS))
	rec[0] = RecordTypeHandshake
	rec[1] = 0x03
	rec[2] = 0x01 // TLS 1.0 legacy record version per RFC 8446
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(rawHS)))
	copy(rec[5:], rawHS)
	return rec, nil
}

// BuildChromeClientHello constructs a Chrome ClientHello TLS record with SNI, random, sessionID, and X25519 key.
func BuildChromeClientHello(sni string, random [32]byte, sessionID [32]byte, x25519Pub [32]byte) ([]byte, []uint16, error) {
	tmpl, err := PrepareChromeHelloTemplate(sni, x25519Pub)
	if err != nil {
		return nil, nil, err
	}
	rec, err := tmpl.MarshalRecord(random, sessionID)
	if err != nil {
		return nil, nil, err
	}
	return rec, tmpl.CipherSuites, nil
}

// BuildPlainChromeClientHello constructs an un-steganographied Chrome ClientHello for dest sampling.
func BuildPlainChromeClientHello(sni string) ([]byte, error) {
	uconn := utls.UClient(&nopConn{}, &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}, utls.HelloChrome_120)
	if err := uconn.BuildHandshakeStateWithoutSession(); err != nil {
		return nil, err
	}
	rawHS := uconn.HandshakeState.Hello.Raw
	rec := make([]byte, 5+len(rawHS))
	rec[0] = RecordTypeHandshake
	rec[1] = 0x03
	rec[2] = 0x01
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(rawHS)))
	copy(rec[5:], rawHS)
	return rec, nil
}

type nopConn struct{}

func (n *nopConn) Read(b []byte) (int, error)         { return 0, io.EOF }
func (n *nopConn) Write(b []byte) (int, error)        { return len(b), nil }
func (n *nopConn) Close() error                       { return nil }
func (n *nopConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (n *nopConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (n *nopConn) SetDeadline(t time.Time) error      { return nil }
func (n *nopConn) SetReadDeadline(t time.Time) error  { return nil }
func (n *nopConn) SetWriteDeadline(t time.Time) error { return nil }
