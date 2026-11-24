package phantom

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// DialConfig specifies parameters for establishing a PhantomTLS client connection.
type DialConfig struct {
	ServerAddr  string
	ServerPub   [32]byte
	UserID      uint32
	UserSecret  string
	SNIList     []string
	DialTimeout time.Duration
	// DialContext optionally overrides the underlying TCP dialer (e.g. Mihomo TUN-safe dialer).
	DialContext func(ctx context.Context, network, addr string) (net.Conn, error)
}

// HandshakeInfo records diagnostic metadata from a client handshake.
type HandshakeInfo struct {
	SNI                string
	ShapeSeed          uint32
	ObservedRecordLens []int
	ClientHelloBytes   []byte
}

// DialPhantom establishes a fresh PhantomTLS connection using Chrome uTLS ClientHello steganography.
func DialPhantom(ctx context.Context, cfg DialConfig, explicitSNI string) (*TunnelConn, *HandshakeInfo, error) {
	sni := explicitSNI
	if sni == "" {
		sni = pickRandomSNI(cfg.SNIList)
	}
	if sni == "" {
		sni = "www.microsoft.com"
	}

	timeout := cfg.DialTimeout
	if timeout <= 0 {
		timeout = 8 * time.Second
	}

	clientPriv, clientPub, err := GenerateX25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	tmpl, err := PrepareChromeHelloTemplate(sni, clientPub)
	if err != nil {
		return nil, nil, err
	}

	aad := BuildAAD(sni, tmpl.CipherSuites)

	var seedBuf [4]byte
	if _, err := rand.Read(seedBuf[:]); err != nil {
		return nil, nil, err
	}
	rawSeed := binary.BigEndian.Uint32(seedBuf[:])
	// Negotiate hardware-accelerated AES-128-GCM in top 4 bits of ShapeSeed.
	shapeSeed := PackShapeSeed(rawSeed, CipherAES128GCM)
	ts := uint32(time.Now().Unix())

	random, sessionID, sharedSecret, err := EmbedStego(
		clientPriv,
		cfg.ServerPub,
		cfg.UserID,
		[]byte(cfg.UserSecret),
		ts,
		shapeSeed,
		aad,
	)
	if err != nil {
		return nil, nil, err
	}

	chRecord, err := tmpl.MarshalRecord(random, sessionID)
	if err != nil {
		return nil, nil, err
	}

	var rawConn net.Conn
	if cfg.DialContext != nil {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		rawConn, err = cfg.DialContext(dialCtx, "tcp", cfg.ServerAddr)
		cancel()
	} else {
		dialer := net.Dialer{Timeout: timeout}
		rawConn, err = dialer.DialContext(ctx, "tcp", cfg.ServerAddr)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("dial server: %w", err)
	}
	_ = rawConn.SetDeadline(time.Now().Add(timeout))

	if _, err := rawConn.Write(chRecord); err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("send ClientHello: %w", err)
	}

	c2sKey, s2cKey, clientFinishedTag, cipherSuite, observedLens, err := VerifySimulatedServerFlight(
		rawConn,
		clientPriv,
		sharedSecret,
		clientPub,
		random[0:16],
	)
	if err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("verify server flight: %w", err)
	}

	finRecord, err := BuildClientFinishedRecord(c2sKey, clientFinishedTag, cipherSuite)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}
	if _, err := rawConn.Write(finRecord); err != nil {
		rawConn.Close()
		return nil, nil, fmt.Errorf("send ClientFinished: %w", err)
	}

	_ = rawConn.SetDeadline(time.Time{})

	// Client reads with s2cKey and writes with c2sKey.
	tconn, err := NewTunnelConn(rawConn, s2cKey, c2sKey, shapeSeed)
	if err != nil {
		rawConn.Close()
		return nil, nil, err
	}

	info := &HandshakeInfo{
		SNI:                sni,
		ShapeSeed:          shapeSeed,
		ObservedRecordLens: observedLens,
		ClientHelloBytes:   chRecord,
	}
	return tconn, info, nil
}

func pickRandomSNI(list []string) string {
	if len(list) == 0 {
		return ""
	}
	if len(list) == 1 {
		return list[0]
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	idx := int(binary.BigEndian.Uint16(b[:])) % len(list)
	return list[idx]
}

type idleConn struct {
	conn      *TunnelConn
	expiresAt time.Time
}

const defaultIdleSleep = 60 * time.Second

// WarmPool maintains a lazy, heartbeat-free pool of pre-handshaked connections
// with randomized 15s-45s lifetimes, automatic 60s idle sleep, and multi-SNI rotation.
type WarmPool struct {
	cfg          DialConfig
	minIdle      int
	maxIdle      int
	idleSleepDur time.Duration

	lastActive atomic.Int64

	mu       sync.Mutex
	idle     []idleConn
	filling  int
	closed   bool
	stopCh   chan struct{}
	stopOnce sync.Once
}

// NewWarmPool creates a lazy, heartbeat-free WarmPool. It stays dormant until first Acquire().
func NewWarmPool(cfg DialConfig, minIdle int, maxIdle int) *WarmPool {
	if minIdle < 0 {
		minIdle = 0
	}
	if maxIdle < minIdle {
		maxIdle = minIdle
	}
	if maxIdle == 0 {
		maxIdle = 4
	}
	p := &WarmPool{
		cfg:          cfg,
		minIdle:      minIdle,
		maxIdle:      maxIdle,
		idleSleepDur: defaultIdleSleep,
		stopCh:       make(chan struct{}),
	}
	if minIdle > 0 {
		go p.maintainLoop()
	}
	return p
}

// Reset immediately closes and discards all idle connections (call on network switch e.g. Wi-Fi <-> 5G).
func (p *WarmPool) Reset() {
	p.mu.Lock()
	old := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, ic := range old {
		go ic.conn.Close()
	}
}

// Config returns the DialConfig used by this pool.
func (p *WarmPool) Config() DialConfig {
	return p.cfg
}

// Close closes all idle connections and stops the maintenance loop.
func (p *WarmPool) Close() {
	p.stopOnce.Do(func() {
		close(p.stopCh)
		p.mu.Lock()
		p.closed = true
		for _, ic := range p.idle {
			_ = ic.conn.Close()
		}
		p.idle = nil
		p.mu.Unlock()
	})
}

// Acquire returns a TunnelConn and reports whether it came from the idle pool (fromPool=true)
// or was freshly dialed (fromPool=false).
func (p *WarmPool) Acquire(ctx context.Context) (*TunnelConn, bool, error) {
	now := time.Now()
	p.lastActive.Store(now.UnixNano())

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, false, errors.New("warm pool closed")
	}
	var picked *TunnelConn
	for len(p.idle) > 0 {
		ic := p.idle[0]
		p.idle = p.idle[1:]
		if now.Before(ic.expiresAt) {
			picked = ic.conn
			break
		}
		go ic.conn.Close()
	}
	needFill := p.minIdle > 0 && len(p.idle)+p.filling < p.minIdle
	p.mu.Unlock()

	if needFill {
		p.triggerFill()
	}

	if picked != nil {
		return picked, true, nil
	}

	tconn, _, err := DialPhantom(ctx, p.cfg, "")
	return tconn, false, err
}

// IdleCount returns the current number of non-expired idle connections.
func (p *WarmPool) IdleCount() int {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	count := 0
	for _, ic := range p.idle {
		if now.Before(ic.expiresAt) {
			count++
		}
	}
	return count
}

func (p *WarmPool) isAwake(now time.Time) bool {
	last := p.lastActive.Load()
	if last == 0 {
		return false
	}
	return now.Sub(time.Unix(0, last)) < p.idleSleepDur
}

func (p *WarmPool) maintainLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.stopCh:
			return
		case now := <-ticker.C:
			p.pruneExpired()
			if p.isAwake(now) {
				p.triggerFill()
			}
		}
	}
}

func (p *WarmPool) pruneExpired() {
	now := time.Now()
	var expired []*TunnelConn

	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	kept := p.idle[:0]
	for _, ic := range p.idle {
		if now.Before(ic.expiresAt) {
			kept = append(kept, ic)
		} else {
			expired = append(expired, ic.conn)
		}
	}
	p.idle = kept
	p.mu.Unlock()

	for _, c := range expired {
		_ = c.Close()
	}
}

func (p *WarmPool) triggerFill() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	needed := p.minIdle - (len(p.idle) + p.filling)
	if needed <= 0 {
		p.mu.Unlock()
		return
	}
	p.filling += needed
	p.mu.Unlock()

	for i := 0; i < needed; i++ {
		go func(idx int) {
			if idx > 0 {
				time.Sleep(randomDuration(40, 220) * time.Millisecond)
			}
			p.fillOne()
		}(i)
	}
}

func (p *WarmPool) fillOne() {
	defer func() {
		p.mu.Lock()
		if p.filling > 0 {
			p.filling--
		}
		p.mu.Unlock()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	tconn, _, err := DialPhantom(ctx, p.cfg, "")
	if err != nil {
		return
	}

	ttl := time.Duration(randomDuration(15, 45)) * time.Second
	ic := idleConn{
		conn:      tconn,
		expiresAt: time.Now().Add(ttl),
	}

	p.mu.Lock()
	if p.closed || len(p.idle) >= p.maxIdle {
		p.mu.Unlock()
		_ = tconn.Close()
		return
	}
	p.idle = append(p.idle, ic)
	p.mu.Unlock()
}

func randomDuration(minVal int64, maxVal int64) time.Duration {
	if maxVal <= minVal {
		return time.Duration(minVal)
	}
	var b [2]byte
	_, _ = rand.Read(b[:])
	span := uint64(maxVal - minVal + 1)
	return time.Duration(minVal + int64(binary.BigEndian.Uint16(b[:]))%int64(span))
}
