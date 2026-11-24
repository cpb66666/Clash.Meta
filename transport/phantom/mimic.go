package phantom

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrInvalidServerFlight = errors.New("invalid simulated server flight")
	ErrServerAuthFailed    = errors.New("server authentication tag mismatch")
	ErrClientFinishFailed  = errors.New("client finished verification failed")
)

// DestTarget defines an upstream camouflage destination site.
type DestTarget struct {
	SNI  string `json:"sni"`
	Addr string `json:"addr"`
}

// DestProfile captures the sampled TLS 1.3 ServerHello cipher, extension order, and encrypted handshake record lengths of a dest.
type DestProfile struct {
	SNI                 string
	DestAddr            string
	CipherSuite         uint16
	ServerHelloExtOrder []uint16
	CertRecordLengths   []int
	SampleOK            bool
	SampledAt           time.Time
}

// DefaultProfile returns a realistic TLS 1.3 profile matching typical CDN/enterprise sites.
func DefaultProfile(sni string, addr string) *DestProfile {
	return &DestProfile{
		SNI:                 sni,
		DestAddr:            addr,
		CipherSuite:         0x1301,
		ServerHelloExtOrder: []uint16{ExtSupportedVersions, ExtKeyShare},
		CertRecordLengths:   []int{138, 2840, 274, 58},
		SampleOK:            false,
		SampledAt:           time.Now(),
	}
}

// Sampler maintains TLS 1.3 response profiles for all configured dest targets.
type Sampler struct {
	mu         sync.RWMutex
	profiles   map[string]*DestProfile
	defaultSNI string
}

// NewSampler initializes a Sampler with default profiles for every target.
func NewSampler(targets []DestTarget) *Sampler {
	s := &Sampler{
		profiles: make(map[string]*DestProfile, len(targets)),
	}
	for i, t := range targets {
		if i == 0 {
			s.defaultSNI = t.SNI
		}
		s.profiles[t.SNI] = DefaultProfile(t.SNI, t.Addr)
	}
	return s
}

// GetProfile returns the DestProfile for sni, or the default profile if sni is unknown.
func (s *Sampler) GetProfile(sni string) *DestProfile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if p, ok := s.profiles[sni]; ok {
		return p
	}
	if p, ok := s.profiles[s.defaultSNI]; ok {
		return p
	}
	return DefaultProfile(sni, "")
}

func SampleDest(sni string, addr string, timeout time.Duration) *DestProfile {
	fallback := DefaultProfile(sni, addr)
	if addr == "" {
		return fallback
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fallback
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	helloRec, err := BuildPlainChromeClientHello(sni)
	if err != nil {
		return fallback
	}
	if _, err := conn.Write(helloRec); err != nil {
		return fallback
	}

	var cipherSuite uint16
	var extOrder []uint16
	var appLengths []int
	gotServerHello := false

	for len(appLengths) < 8 {
		if len(appLengths) > 0 {
			_ = conn.SetReadDeadline(time.Now().Add(180 * time.Millisecond))
		}
		recType, payload, err := readTLSRecord(conn)
		if err != nil {
			break
		}
		switch recType {
		case RecordTypeHandshake:
			if !gotServerHello && len(payload) >= 39 && payload[0] == HandshakeTypeServerHello {
				gotServerHello = true
				sidLen := int(payload[38])
				csOff := 39 + sidLen
				if csOff+2 <= len(payload) {
					cipherSuite = binary.BigEndian.Uint16(payload[csOff : csOff+2])
				}
				extOrder = parseServerHelloExtOrder(payload)
			}
		case RecordTypeChangeCipherSpec:
			continue
		case RecordTypeApplicationData:
			if len(payload) >= 18 {
				appLengths = append(appLengths, len(payload))
			}
		}
	}

	if !gotServerHello || len(appLengths) == 0 {
		return fallback
	}

	hasTagCarrier := false
	for _, l := range appLengths {
		if l >= 64 {
			hasTagCarrier = true
			break
		}
	}
	if !hasTagCarrier {
		return fallback
	}

	if cipherSuite == 0 {
		cipherSuite = 0x1301
	}
	if len(extOrder) == 0 {
		extOrder = []uint16{ExtSupportedVersions, ExtKeyShare}
	}

	return &DestProfile{
		SNI:                 sni,
		DestAddr:            addr,
		CipherSuite:         cipherSuite,
		ServerHelloExtOrder: extOrder,
		CertRecordLengths:   appLengths,
		SampleOK:            true,
		SampledAt:           time.Now(),
	}
}

func parseServerHelloExtOrder(payload []byte) []uint16 {
	if len(payload) < 44 || payload[0] != HandshakeTypeServerHello {
		return nil
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if 4+hsLen > len(payload) {
		return nil
	}
	p := payload[4 : 4+hsLen]
	off := 2 + 32
	if off+1 > len(p) {
		return nil
	}
	sidLen := int(p[off])
	off += 1 + sidLen + 2 + 1
	if off+2 > len(p) {
		return nil
	}
	extsLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+extsLen > len(p) {
		return nil
	}
	extEnd := off + extsLen
	var order []uint16
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(p[off : off+2])
		extLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			break
		}
		if extType == ExtSupportedVersions || extType == ExtKeyShare {
			order = append(order, extType)
		}
		off += extLen
	}
	return order
}

func readTLSRecord(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
	if recLen > MaxTLSRecordPayload+256 {
		return 0, nil, fmt.Errorf("tls record too large: %d", recLen)
	}
	payload := make([]byte, recLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

func makeHandshakeFlightNonce(seq uint64) [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], "phhs")
	binary.BigEndian.PutUint64(nonce[4:12], seq)
	return nonce
}

func makeClientFinishedNonce() [12]byte {
	var nonce [12]byte
	copy(nonce[0:4], "phfn")
	return nonce
}

// BuildSimulatedServerFlight builds a TLS 1.3 ServerHello + ChangeCipherSpec + encrypted handshake records
// whose encrypted record lengths match profile.CertRecordLengths 1:1.
func BuildSimulatedServerFlight(
	profile *DestProfile,
	clientSessionID []byte,
	serverEphPub [32]byte,
	s2cKey [32]byte,
	serverHandshakeTag [32]byte,
) ([]byte, error) {
	if profile == nil || len(profile.CertRecordLengths) == 0 {
		profile = DefaultProfile("example.com", "")
	}

	suite := profile.CipherSuite
	if suite == 0 {
		suite = 0x1301
	}

	var sid [32]byte
	if len(clientSessionID) >= 32 {
		copy(sid[:], clientSessionID[:32])
	} else {
		copy(sid[:], clientSessionID)
	}

	shRecord, err := buildServerHelloRecord(sid[:], suite, serverEphPub, profile.ServerHelloExtOrder)
	if err != nil {
		return nil, err
	}

	ccsRecord := []byte{RecordTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}

	aead, err := chacha20poly1305.New(s2cKey[:])
	if err != nil {
		return nil, err
	}

	lengths := make([]int, len(profile.CertRecordLengths))
	copy(lengths, profile.CertRecordLengths)
	tagIdx := -1
	for i, l := range lengths {
		if l >= 64 {
			tagIdx = i
			break
		}
	}
	if tagIdx == -1 {
		tagIdx = 0
		if lengths[0] < 64 {
			lengths[0] = 64
		}
	}

	totalSize := len(shRecord) + len(ccsRecord)
	for _, l := range lengths {
		totalSize += 5 + l
	}
	flight := make([]byte, 0, totalSize)
	flight = append(flight, shRecord...)
	flight = append(flight, ccsRecord...)

	for i, targetLen := range lengths {
		if targetLen < 18 {
			targetLen = 18
		}
		ptLen := targetLen - aead.Overhead()
		pt := make([]byte, ptLen)
		if _, err := io.ReadFull(rand.Reader, pt); err != nil {
			return nil, err
		}
		if i == len(lengths)-1 {
			pt[0] = 0x01
		} else {
			pt[0] = 0x00
		}
		if i == tagIdx {
			pt[1] = 0x01
			copy(pt[2:34], serverHandshakeTag[:])
		} else {
			pt[1] = 0x00
		}

		nonce := makeHandshakeFlightNonce(uint64(i))
		var hdr [5]byte
		hdr[0] = RecordTypeApplicationData
		hdr[1] = 0x03
		hdr[2] = 0x03
		binary.BigEndian.PutUint16(hdr[3:5], uint16(targetLen))

		ct := aead.Seal(nil, nonce[:], pt, hdr[:])
		flight = append(flight, hdr[:]...)
		flight = append(flight, ct...)
	}

	return flight, nil
}

func buildServerHelloRecord(sessionID []byte, cipherSuite uint16, serverEphPub [32]byte, extOrder []uint16) ([]byte, error) {
	var srvRandom [32]byte
	if _, err := io.ReadFull(rand.Reader, srvRandom[:]); err != nil {
		return nil, err
	}

	svExt := []byte{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04}
	ksExt := make([]byte, 0, 40)
	ksExt = append(ksExt, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20)
	ksExt = append(ksExt, serverEphPub[:]...)

	exts := make([]byte, 0, 46)
	emittedSV := false
	emittedKS := false
	for _, et := range extOrder {
		switch et {
		case ExtSupportedVersions:
			if !emittedSV {
				exts = append(exts, svExt...)
				emittedSV = true
			}
		case ExtKeyShare:
			if !emittedKS {
				exts = append(exts, ksExt...)
				emittedKS = true
			}
		}
	}
	if !emittedSV {
		exts = append(exts, svExt...)
	}
	if !emittedKS {
		exts = append(exts, ksExt...)
	}

	bodyLen := 2 + 32 + 1 + len(sessionID) + 2 + 1 + 2 + len(exts)
	hsLen := bodyLen
	recLen := 4 + hsLen

	out := make([]byte, 0, 5+recLen)
	out = append(out, RecordTypeHandshake, 0x03, 0x03, byte(recLen>>8), byte(recLen))
	out = append(out, HandshakeTypeServerHello, byte(hsLen>>16), byte(hsLen>>8), byte(hsLen))
	out = append(out, 0x03, 0x03)
	out = append(out, srvRandom[:]...)
	out = append(out, byte(len(sessionID)))
	out = append(out, sessionID...)
	out = append(out, byte(cipherSuite>>8), byte(cipherSuite))
	out = append(out, 0x00)
	out = append(out, byte(len(exts)>>8), byte(len(exts)))
	out = append(out, exts...)
	return out, nil
}

func parseServerHelloFields(payload []byte) (pub [32]byte, cipherSuite uint16, ok bool) {
	if len(payload) < 44 || payload[0] != HandshakeTypeServerHello {
		return pub, 0, false
	}
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	if 4+hsLen > len(payload) {
		return pub, 0, false
	}
	p := payload[4 : 4+hsLen]
	off := 2 + 32
	if off+1 > len(p) {
		return pub, 0, false
	}
	sidLen := int(p[off])
	off += 1 + sidLen
	if off+3 > len(p) {
		return pub, 0, false
	}
	cipherSuite = binary.BigEndian.Uint16(p[off : off+2])
	off += 3
	if off+2 > len(p) {
		return pub, 0, false
	}
	extsLen := int(binary.BigEndian.Uint16(p[off : off+2]))
	off += 2
	if off+extsLen > len(p) {
		return pub, 0, false
	}
	extEnd := off + extsLen
	for off+4 <= extEnd {
		extType := binary.BigEndian.Uint16(p[off : off+2])
		extLen := int(binary.BigEndian.Uint16(p[off+2 : off+4]))
		off += 4
		if off+extLen > extEnd {
			return pub, 0, false
		}
		extData := p[off : off+extLen]
		off += extLen
		if extType == ExtKeyShare && len(extData) == 36 {
			group := binary.BigEndian.Uint16(extData[0:2])
			klen := int(binary.BigEndian.Uint16(extData[2:4]))
			if group == CurveX25519 && klen == 32 {
				copy(pub[:], extData[4:36])
				return pub, cipherSuite, true
			}
		}
	}
	return pub, cipherSuite, false
}

// VerifySimulatedServerFlight reads the server's simulated TLS 1.3 flight, derives forward-secure
// session keys using the server's ephemeral KeyShare, and verifies the server's encrypted handshake tag.
func VerifySimulatedServerFlight(
	r io.Reader,
	clientPriv [32]byte,
	sharedSecret [32]byte,
	clientPub [32]byte,
	salt []byte,
) (c2sKey [32]byte, s2cKey [32]byte, clientFinishedTag [32]byte, cipherSuite uint16, observedRecordLens []int, err error) {
	recType, shPayload, err := readTLSRecord(r)
	if err != nil || recType != RecordTypeHandshake {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
	}
	serverEphPub, cipherSuite, ok := parseServerHelloFields(shPayload)
	if !ok {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
	}

	ecdheSecret, err := ComputeSharedSecret(clientPriv, serverEphPub)
	if err != nil {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
	}

	var serverHandshakeTag [32]byte
	c2sKey, s2cKey, serverHandshakeTag, clientFinishedTag, err = DeriveSessionKeys(
		sharedSecret, ecdheSecret, clientPub, serverEphPub, salt,
	)
	if err != nil {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, err
	}

	aead, err := chacha20poly1305.New(s2cKey[:])
	if err != nil {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, err
	}

	var seq uint64
	verifiedTag := false
	for {
		if seq > 16 {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
		}
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen > MaxTLSRecordPayload+256 {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
		}

		if hdr[0] == RecordTypeChangeCipherSpec {
			continue
		}
		if hdr[0] != RecordTypeApplicationData {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrInvalidServerFlight
		}

		observedRecordLens = append(observedRecordLens, recLen)
		nonce := makeHandshakeFlightNonce(seq)
		seq++
		pt, err := aead.Open(nil, nonce[:], payload, hdr[:])
		if err != nil || len(pt) < 2 {
			return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrServerAuthFailed
		}
		isLast := pt[0] == 0x01
		hasTag := pt[1] == 0x01
		if hasTag {
			if len(pt) < 34 || subtle.ConstantTimeCompare(pt[2:34], serverHandshakeTag[:]) != 1 {
				return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrServerAuthFailed
			}
			verifiedTag = true
		}
		if isLast {
			break
		}
	}

	if !verifiedTag {
		return c2sKey, s2cKey, clientFinishedTag, 0, nil, ErrServerAuthFailed
	}

	return c2sKey, s2cKey, clientFinishedTag, cipherSuite, observedRecordLens, nil
}

// BuildClientFinishedRecord builds the Chrome-like ChangeCipherSpec + encrypted Finished TLS record.
func BuildClientFinishedRecord(c2sKey [32]byte, clientFinishedTag [32]byte, cipherSuite uint16) ([]byte, error) {
	aead, err := chacha20poly1305.New(c2sKey[:])
	if err != nil {
		return nil, err
	}
	ccs := []byte{RecordTypeChangeCipherSpec, 0x03, 0x03, 0x00, 0x01, 0x01}

	ptLen := 37 // 37B + 16B tag = 53B (SHA-256 Finished)
	if cipherSuite == 0x1302 {
		ptLen = 53 // 53B + 16B tag = 69B (SHA-384 Finished)
	}
	pt := make([]byte, ptLen)
	copy(pt[0:32], clientFinishedTag[:])
	_, _ = io.ReadFull(rand.Reader, pt[32:])

	var hdr [5]byte
	hdr[0] = RecordTypeApplicationData
	hdr[1] = 0x03
	hdr[2] = 0x03
	binary.BigEndian.PutUint16(hdr[3:5], uint16(len(pt)+aead.Overhead()))

	nonce := makeClientFinishedNonce()
	ct := aead.Seal(nil, nonce[:], pt, hdr[:])

	out := make([]byte, 0, len(ccs)+len(hdr)+len(ct))
	out = append(out, ccs...)
	out = append(out, hdr[:]...)
	out = append(out, ct...)
	return out, nil
}

// ReadAndVerifyClientFinished reads the optional ChangeCipherSpec and verifies the client's encrypted Finished record.
func ReadAndVerifyClientFinished(r io.Reader, c2sKey [32]byte, expectedTag [32]byte) error {
	aead, err := chacha20poly1305.New(c2sKey[:])
	if err != nil {
		return err
	}
	for i := 0; i < 3; i++ {
		var hdr [5]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return ErrClientFinishFailed
		}
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))
		if recLen > 1024 {
			return ErrClientFinishFailed
		}
		payload := make([]byte, recLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return ErrClientFinishFailed
		}
		if hdr[0] == RecordTypeChangeCipherSpec {
			continue
		}
		if hdr[0] != RecordTypeApplicationData {
			return ErrClientFinishFailed
		}
		nonce := makeClientFinishedNonce()
		pt, err := aead.Open(nil, nonce[:], payload, hdr[:])
		if err != nil || len(pt) < 32 {
			return ErrClientFinishFailed
		}
		if subtle.ConstantTimeCompare(pt[0:32], expectedTag[:]) != 1 {
			return ErrClientFinishFailed
		}
		return nil
	}
	return ErrClientFinishFailed
}
