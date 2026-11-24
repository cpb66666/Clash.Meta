package phantom

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	// HandshakeInfoLabel is the HKDF context string for handshake steganography.
	HandshakeInfoLabel = "phantom-hs-v1"
	// SessionInfoLabel is the HKDF context string for session key derivation.
	SessionInfoLabel = "phantom-sess-v1"
	// StegoPlaintextLen is the exact plaintext size of StegoPayload (4+4+4+12 = 24 bytes).
	StegoPlaintextLen = 24
	// StegoCiphertextLen is StegoPlaintextLen + 16-byte Poly1305 tag = 40 bytes.
	StegoCiphertextLen = 40

	// CipherChaCha20Poly1305 selects ChaCha20-Poly1305 for tunnel records (fallback/legacy).
	CipherChaCha20Poly1305 uint8 = 0
	// CipherAES128GCM selects hardware-accelerated AES-128-GCM for tunnel records (default).
	CipherAES128GCM uint8 = 1
)

// PackShapeSeed encodes a 4-bit cipher/version flag in the top 4 bits of ShapeSeed
// while preserving 28 bits of shaping randomness with zero wire-size overhead.
func PackShapeSeed(seed28 uint32, cipherID uint8) uint32 {
	return (uint32(cipherID&0x0f) << 28) | (seed28 & 0x0fffffff)
}

// UnpackShapeSeed extracts the 28-bit shaping seed and 4-bit cipher ID from ShapeSeed.
func UnpackShapeSeed(packed uint32) (seed28 uint32, cipherID uint8) {
	return packed & 0x0fffffff, uint8((packed >> 28) & 0x0f)
}

var (
	ErrInvalidKey       = errors.New("invalid x25519 key")
	ErrStegoDecryptFail = errors.New("stego decryption failed")
	ErrLowOrderPoint    = errors.New("x25519 low order point")
)

// StegoPayload holds the authenticated user identity and shaping parameters embedded in ClientHello.
type StegoPayload struct {
	UserID    uint32
	Timestamp uint32
	ShapeSeed uint32
	UserProof [12]byte
}

// GenerateX25519KeyPair creates a fresh clamped X25519 private/public key pair.
func GenerateX25519KeyPair() (priv [32]byte, pub [32]byte, err error) {
	if _, err = io.ReadFull(rand.Reader, priv[:]); err != nil {
		return priv, pub, fmt.Errorf("read random private key: %w", err)
	}
	priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64

	pubSlice, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return priv, pub, fmt.Errorf("derive public key: %w", err)
	}
	copy(pub[:], pubSlice)
	return priv, pub, nil
}

// ComputeSharedSecret calculates an X25519 ECDH shared secret and rejects all-zero outputs.
func ComputeSharedSecret(priv [32]byte, peerPub [32]byte) ([32]byte, error) {
	var out [32]byte
	res, err := curve25519.X25519(priv[:], peerPub[:])
	if err != nil {
		return out, fmt.Errorf("%w: %v", ErrLowOrderPoint, err)
	}
	copy(out[:], res)
	var zero [32]byte
	if subtle.ConstantTimeCompare(out[:], zero[:]) == 1 {
		return out, ErrLowOrderPoint
	}
	return out, nil
}

// EncodeKey encodes a 32-byte key as raw URL-safe base64.
func EncodeKey(k [32]byte) string {
	return base64.RawURLEncoding.EncodeToString(k[:])
}

// DecodeKey decodes a 32-byte X25519 key from hex (64 chars), raw/padded URL-safe base64,
// or raw/padded standard base64.
func DecodeKey(s string) ([32]byte, error) {
	var out [32]byte
	s = strings.TrimSpace(s)
	if s == "" {
		return out, fmt.Errorf("%w: empty key", ErrInvalidKey)
	}

	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
			copy(out[:], b)
			return out, nil
		}
	}

	encodings := []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	}
	var decoded []byte
	var lastErr error
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err == nil {
			decoded = b
			lastErr = nil
			break
		}
		lastErr = err
	}
	if lastErr != nil {
		// Fall back to hex decode error check if caller passed odd/invalid hex
		if b, hexErr := hex.DecodeString(s); hexErr == nil {
			decoded = b
		} else {
			return out, fmt.Errorf("%w: %v", ErrInvalidKey, lastErr)
		}
	}
	if len(decoded) != 32 {
		return out, fmt.Errorf("%w: got %d bytes, want 32", ErrInvalidKey, len(decoded))
	}
	copy(out[:], decoded)
	return out, nil
}

// BuildAAD builds deterministic AEAD additional authenticated data binding SNI and CipherSuites.
func BuildAAD(sni string, cipherSuites []uint16) []byte {
	buf := make([]byte, 2+len(sni)+2+2*len(cipherSuites))
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(sni)))
	copy(buf[2:2+len(sni)], sni)
	off := 2 + len(sni)
	binary.BigEndian.PutUint16(buf[off:off+2], uint16(len(cipherSuites)))
	off += 2
	for _, cs := range cipherSuites {
		binary.BigEndian.PutUint16(buf[off:off+2], cs)
		off += 2
	}
	return buf
}

// ComputeUserProof calculates the 12-byte user-specific proof tag.
func ComputeUserProof(userSecret []byte, salt []byte, userID uint32, timestamp uint32) [12]byte {
	var out [12]byte
	mac := hmac.New(sha256.New, userSecret)
	mac.Write(salt)
	var tmp [8]byte
	binary.BigEndian.PutUint32(tmp[0:4], userID)
	binary.BigEndian.PutUint32(tmp[4:8], timestamp)
	mac.Write(tmp[:])
	sum := mac.Sum(nil)
	copy(out[:], sum[:12])
	return out
}

// VerifyUserProof checks the embedded user proof in constant time.
func VerifyUserProof(userSecret []byte, salt []byte, payload *StegoPayload) bool {
	if payload == nil || len(userSecret) == 0 || len(salt) != 16 {
		return false
	}
	expected := ComputeUserProof(userSecret, salt, payload.UserID, payload.Timestamp)
	return hmac.Equal(expected[:], payload.UserProof[:])
}

func deriveHandshakeMaterial(sharedSecret [32]byte, salt []byte) (authKey [32]byte, authNonce [12]byte, maskStream [32]byte, err error) {
	r := hkdf.New(sha256.New, sharedSecret[:], salt, []byte(HandshakeInfoLabel))
	var mat [76]byte
	if _, err = io.ReadFull(r, mat[:]); err != nil {
		return authKey, authNonce, maskStream, err
	}
	copy(authKey[:], mat[0:32])
	copy(authNonce[:], mat[32:44])
	copy(maskStream[:], mat[44:76])
	return authKey, authNonce, maskStream, nil
}

// EmbedStego generates a random Salt and encrypts the StegoPayload across Random[16:32] and SessionID[0:24],
// filling SessionID[24:32] with MaskStream[0:8] for natural high-entropy distribution.
func EmbedStego(
	clientPriv [32]byte,
	serverPub [32]byte,
	userID uint32,
	userSecret []byte,
	timestamp uint32,
	shapeSeed uint32,
	aad []byte,
) (random [32]byte, sessionID [32]byte, sharedSecret [32]byte, err error) {
	if len(userSecret) == 0 {
		return random, sessionID, sharedSecret, errors.New("empty user secret")
	}
	if _, err = io.ReadFull(rand.Reader, random[0:16]); err != nil {
		return random, sessionID, sharedSecret, fmt.Errorf("read random salt: %w", err)
	}
	salt := random[0:16]

	sharedSecret, err = ComputeSharedSecret(clientPriv, serverPub)
	if err != nil {
		return random, sessionID, sharedSecret, err
	}

	authKey, authNonce, maskStream, err := deriveHandshakeMaterial(sharedSecret, salt)
	if err != nil {
		return random, sessionID, sharedSecret, err
	}

	proof := ComputeUserProof(userSecret, salt, userID, timestamp)
	var pt [StegoPlaintextLen]byte
	binary.BigEndian.PutUint32(pt[0:4], userID)
	binary.BigEndian.PutUint32(pt[4:8], timestamp)
	binary.BigEndian.PutUint32(pt[8:12], shapeSeed)
	copy(pt[12:24], proof[:])

	aead, err := chacha20poly1305.New(authKey[:])
	if err != nil {
		return random, sessionID, sharedSecret, err
	}
	ct := aead.Seal(nil, authNonce[:], pt[:], aad)
	if len(ct) != StegoCiphertextLen {
		return random, sessionID, sharedSecret, fmt.Errorf("unexpected ciphertext length %d", len(ct))
	}

	copy(random[16:32], ct[0:16])
	copy(sessionID[0:24], ct[16:40])
	copy(sessionID[24:32], maskStream[0:8])
	return random, sessionID, sharedSecret, nil
}

// ExtractStego performs O(1) X25519 decryption of cross-field steganography and returns the replayKey.
func ExtractStego(
	serverPriv [32]byte,
	clientPub [32]byte,
	random [32]byte,
	sessionID [32]byte,
	aad []byte,
) (payload *StegoPayload, sharedSecret [32]byte, replayKey [32]byte, err error) {
	salt := random[0:16]
	sharedSecret, err = ComputeSharedSecret(serverPriv, clientPub)
	if err != nil {
		return nil, sharedSecret, replayKey, ErrStegoDecryptFail
	}

	authKey, authNonce, maskStream, err := deriveHandshakeMaterial(sharedSecret, salt)
	if err != nil {
		return nil, sharedSecret, replayKey, ErrStegoDecryptFail
	}

	if subtle.ConstantTimeCompare(sessionID[24:32], maskStream[0:8]) != 1 {
		return nil, sharedSecret, replayKey, ErrStegoDecryptFail
	}

	var ct [StegoCiphertextLen]byte
	copy(ct[0:16], random[16:32])
	copy(ct[16:40], sessionID[0:24])

	aead, err := chacha20poly1305.New(authKey[:])
	if err != nil {
		return nil, sharedSecret, replayKey, ErrStegoDecryptFail
	}
	pt, err := aead.Open(nil, authNonce[:], ct[:], aad)
	if err != nil || len(pt) != StegoPlaintextLen {
		return nil, sharedSecret, replayKey, ErrStegoDecryptFail
	}

	p := &StegoPayload{
		UserID:    binary.BigEndian.Uint32(pt[0:4]),
		Timestamp: binary.BigEndian.Uint32(pt[4:8]),
		ShapeSeed: binary.BigEndian.Uint32(pt[8:12]),
	}
	copy(p.UserProof[:], pt[12:24])

	h := sha256.New()
	h.Write(random[:])
	h.Write(sessionID[:])
	copy(replayKey[:], h.Sum(nil))

	return p, sharedSecret, replayKey, nil
}

// DeriveSessionKeys derives forward-secure session keys and handshake authentication tags
// from the static sharedSecret, ephemeral ecdheSecret, both ephemeral public keys, and ClientHello salt.
func DeriveSessionKeys(
	sharedSecret [32]byte,
	ecdheSecret [32]byte,
	clientPublic [32]byte,
	serverEphPublic [32]byte,
	salt []byte,
) (c2sKey [32]byte, s2cKey [32]byte, serverHandshakeTag [32]byte, clientFinishedTag [32]byte, err error) {
	ikm := make([]byte, 0, 128)
	ikm = append(ikm, sharedSecret[:]...)
	ikm = append(ikm, ecdheSecret[:]...)
	ikm = append(ikm, clientPublic[:]...)
	ikm = append(ikm, serverEphPublic[:]...)

	r := hkdf.New(sha256.New, ikm, salt, []byte(SessionInfoLabel))
	var mat [128]byte
	if _, err = io.ReadFull(r, mat[:]); err != nil {
		return c2sKey, s2cKey, serverHandshakeTag, clientFinishedTag, err
	}
	copy(c2sKey[:], mat[0:32])
	copy(s2cKey[:], mat[32:64])
	copy(serverHandshakeTag[:], mat[64:96])
	copy(clientFinishedTag[:], mat[96:128])
	return c2sKey, s2cKey, serverHandshakeTag, clientFinishedTag, nil
}
