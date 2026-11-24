package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	CN "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/component/proxydialer"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/phantom"
)

type Phantom struct {
	*Base
	option  *PhantomOption
	dialCfg phantom.DialConfig
	pool    *phantom.WarmPool
}

type PhantomOption struct {
	BasicOption
	Name      string `proxy:"name"`
	Server    string `proxy:"server"`
	Port      int    `proxy:"port"`
	UserID    uint32 `proxy:"user-id"`
	Secret    string `proxy:"secret"`
	PublicKey string `proxy:"public-key"`
	SNI       any    `proxy:"sni,omitempty"`
	MinIdle   int    `proxy:"min-idle,omitempty"`
	MaxIdle   int    `proxy:"max-idle,omitempty"`
	UDP       bool   `proxy:"udp,omitempty"`
}

func parsePhantomSNI(raw any) ([]string, error) {
	if raw == nil {
		return []string{"www.microsoft.com"}, nil
	}
	var out []string
	switch v := raw.(type) {
	case string:
		for _, part := range strings.Split(v, ",") {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	case []string:
		for _, part := range v {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
	case []any:
		for _, item := range v {
			str, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("phantom sni item must be string, got %T", item)
			}
			if s := strings.TrimSpace(str); s != "" {
				out = append(out, s)
			}
		}
	default:
		return nil, fmt.Errorf("phantom sni must be string or list, got %T", raw)
	}
	if len(out) == 0 {
		return nil, errors.New("phantom sni list cannot be empty when specified")
	}
	return out, nil
}

func NewPhantom(option PhantomOption) (*Phantom, error) {
	if strings.TrimSpace(option.Server) == "" {
		return nil, errors.New("phantom server is required")
	}
	if option.Port <= 0 || option.Port > 65535 {
		return nil, fmt.Errorf("phantom invalid port: %d", option.Port)
	}
	if option.UserID == 0 {
		return nil, errors.New("phantom user-id must be > 0")
	}
	if option.Secret == "" {
		return nil, errors.New("phantom secret is required")
	}
	pubKey, err := phantom.DecodeKey(option.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("phantom invalid public-key: %w", err)
	}
	sniList, err := parsePhantomSNI(option.SNI)
	if err != nil {
		return nil, err
	}

	minIdle := option.MinIdle
	if minIdle < 0 {
		minIdle = 0
	}
	maxIdle := option.MaxIdle
	if maxIdle <= 0 {
		maxIdle = 4
	}
	if maxIdle < minIdle {
		maxIdle = minIdle
	}

	addr := net.JoinHostPort(option.Server, strconv.Itoa(option.Port))
	outbound := &Phantom{
		Base: &Base{
			name:   option.Name,
			addr:   addr,
			tp:     C.Phantom,
			udp:    option.UDP,
			tfo:    option.TFO,
			mpTcp:  option.MPTCP,
			iface:  option.Interface,
			rmark:  option.RoutingMark,
			prefer: C.NewDNSPrefer(option.IPVersion),
		},
		option: &option,
	}

	baseDialer := dialer.NewDialer(outbound.DialOptions()...)
	dialCtxFn := func(ctx context.Context, network, address string) (net.Conn, error) {
		var d C.Dialer = baseDialer
		if len(option.DialerProxy) > 0 {
			proxied, err := proxydialer.NewByName(option.DialerProxy, baseDialer)
			if err != nil {
				return nil, err
			}
			d = proxied
		}
		return d.DialContext(ctx, network, address)
	}

	dialCfg := phantom.DialConfig{
		ServerAddr:  addr,
		ServerPub:   pubKey,
		UserID:      option.UserID,
		UserSecret:  option.Secret,
		SNIList:     sniList,
		DialTimeout: 8 * time.Second,
		DialContext: dialCtxFn,
	}

	outbound.dialCfg = dialCfg
	outbound.pool = phantom.NewWarmPool(dialCfg, minIdle, maxIdle)

	return outbound, nil
}

// PhantomRealityShortID is the magic Reality short-id used to auto-translate Xboard VLESS+Reality
// subscriptions into PhantomTLS outbounds without modifying the Xboard panel.
const PhantomRealityShortID = "7068616e"

// IsPhantomRealityVless reports whether a parsed VLESS option carries PhantomTLS's magic short-id.
func IsPhantomRealityVless(option *VlessOption) bool {
	if option == nil {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(option.RealityOpts.ShortID), PhantomRealityShortID) &&
		strings.TrimSpace(option.RealityOpts.PublicKey) != ""
}

// NewPhantomFromVless translates a zero-modification Xboard VLESS+Reality option into a Phantom outbound.
func NewPhantomFromVless(option VlessOption) (*Phantom, error) {
	if strings.TrimSpace(option.UUID) == "" {
		return nil, errors.New("phantom vless-reality requires uuid")
	}
	var sniVal any
	if sni := strings.TrimSpace(option.ServerName); sni != "" {
		sniVal = sni
	}
	return NewPhantom(PhantomOption{
		BasicOption: option.BasicOption,
		Name:        option.Name,
		Server:      option.Server,
		Port:        option.Port,
		UserID:      phantom.DeriveUserID(option.UUID),
		Secret:      option.UUID,
		PublicKey:   option.RealityOpts.PublicKey,
		SNI:         sniVal,
		UDP:         option.UDP,
	})
}

func buildPhantomTargetHeader(cmd byte, metadata *C.Metadata) (phantom.RequestHeader, error) {
	if metadata == nil || !metadata.Valid() || metadata.DstPort == 0 {
		return phantom.RequestHeader{}, errors.New("phantom invalid target metadata")
	}
	addrType, addr := phantom.ParseTargetAddr(metadata.String())
	return phantom.RequestHeader{
		Cmd:      cmd,
		AddrType: addrType,
		Addr:     addr,
		Port:     metadata.DstPort,
	}, nil
}

// DialContext implements C.ProxyAdapter.
func (p *Phantom) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	reqHdr, err := buildPhantomTargetHeader(phantom.CmdTCP, metadata)
	if err != nil {
		return nil, err
	}

	tconn, fromPool, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	sc := newPhantomStreamConn(tconn, fromPool, reqHdr, func() (*phantom.TunnelConn, error) {
		redialCtx, cancel := context.WithTimeout(context.Background(), p.dialCfg.DialTimeout)
		defer cancel()
		fresh, _, rErr := phantom.DialPhantom(redialCtx, p.dialCfg, "")
		return fresh, rErr
	})
	return NewConn(sc, p), nil
}

// SupportWithDialer implements C.ProxyAdapter.
func (p *Phantom) SupportWithDialer() C.NetWork {
	return C.ALLNet
}

// SupportUOT implements C.ProxyAdapter.
func (p *Phantom) SupportUOT() bool {
	return true
}

func encodePhantomUDPHeader(metadata *C.Metadata) ([]byte, error) {
	reqHdr := phantom.RequestHeader{
		Cmd:      phantom.CmdUDP,
		AddrType: phantom.AddrTypeIPv4,
		Addr:     "0.0.0.0",
		Port:     0,
	}
	if metadata != nil && metadata.Valid() && metadata.DstPort > 0 {
		if h, err := buildPhantomTargetHeader(phantom.CmdUDP, metadata); err == nil {
			reqHdr = h
		}
	}
	return phantom.EncodeRequestHeader(reqHdr, nil)
}

// ListenPacketContext implements C.ProxyAdapter.
func (p *Phantom) ListenPacketContext(ctx context.Context, metadata *C.Metadata) (C.PacketConn, error) {
	if !p.SupportUDP() {
		return nil, C.ErrNotSupport
	}

	hdrBytes, err := encodePhantomUDPHeader(metadata)
	if err != nil {
		return nil, err
	}

	tconn, fromPool, err := p.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := tconn.Write(hdrBytes); err != nil {
		_ = tconn.Close()
		if !fromPool {
			return nil, err
		}
		tconn, _, err = phantom.DialPhantom(ctx, p.dialCfg, "")
		if err != nil {
			return nil, err
		}
		if _, err := tconn.Write(hdrBytes); err != nil {
			_ = tconn.Close()
			return nil, err
		}
	}

	return newPacketConn(CN.NewThreadSafePacketConn(phantom.NewPacketConn(tconn)), p), nil
}

// ListenPacketWithDialer implements C.ProxyAdapter.
func (p *Phantom) ListenPacketWithDialer(ctx context.Context, d C.Dialer, metadata *C.Metadata) (C.PacketConn, error) {
	if !p.SupportUDP() {
		return nil, C.ErrNotSupport
	}
	if len(p.option.DialerProxy) > 0 {
		var err error
		d, err = proxydialer.NewByName(p.option.DialerProxy, d)
		if err != nil {
			return nil, err
		}
	}

	hdrBytes, err := encodePhantomUDPHeader(metadata)
	if err != nil {
		return nil, err
	}

	cfg := p.dialCfg
	cfg.DialContext = d.DialContext
	tconn, _, err := phantom.DialPhantom(ctx, cfg, "")
	if err != nil {
		return nil, err
	}
	if _, err := tconn.Write(hdrBytes); err != nil {
		_ = tconn.Close()
		return nil, err
	}

	return newPacketConn(CN.NewThreadSafePacketConn(phantom.NewPacketConn(tconn)), p), nil
}

// PoolIdleCount returns the current non-expired idle connections in the warm pool.
func (p *Phantom) PoolIdleCount() int {
	if p.pool == nil {
		return 0
	}
	return p.pool.IdleCount()
}

// DialContextWithDialer implements C.ProxyAdapter.
func (p *Phantom) DialContextWithDialer(ctx context.Context, d C.Dialer, metadata *C.Metadata) (C.Conn, error) {
	reqHdr, err := buildPhantomTargetHeader(phantom.CmdTCP, metadata)
	if err != nil {
		return nil, err
	}
	if len(p.option.DialerProxy) > 0 {
		d, err = proxydialer.NewByName(p.option.DialerProxy, d)
		if err != nil {
			return nil, err
		}
	}
	cfg := p.dialCfg
	cfg.DialContext = d.DialContext
	tconn, _, err := phantom.DialPhantom(ctx, cfg, "")
	if err != nil {
		return nil, err
	}
	sc := newPhantomStreamConn(tconn, false, reqHdr, nil)
	return NewConn(sc, p), nil
}

// ProxyInfo implements C.ProxyAdapter.
func (p *Phantom) ProxyInfo() C.ProxyInfo {
	info := p.Base.ProxyInfo()
	info.DialerProxy = p.option.DialerProxy
	return info
}

// Reset discards all pooled idle connections (e.g., on network switches).
func (p *Phantom) Reset() {
	if p.pool != nil {
		p.pool.Reset()
	}
}

// Close implements C.ProxyAdapter.
func (p *Phantom) Close() error {
	if p.pool != nil {
		p.pool.Close()
	}
	return nil
}

type phantomRedialFn func() (*phantom.TunnelConn, error)

// phantomStreamConn merges the PhantomTLS RequestHeader with the first application payload write
// and transparently redials once if a pooled connection fails either on initial Write or before
// the first downstream Read byte (covering OS-buffered half-closed TCP FIN/RST sockets).
type phantomStreamConn struct {
	tconnPtr atomic.Pointer[phantom.TunnelConn]
	reqHdr   phantom.RequestHeader
	redial   phantomRedialFn

	headerMu   sync.Mutex
	headerSent bool
	headerDone atomic.Bool

	stateMu      sync.Mutex
	fromPool     bool
	firstEncoded []byte
	hasFirstRead atomic.Bool

	closed atomic.Bool
}

func newPhantomStreamConn(tconn *phantom.TunnelConn, fromPool bool, reqHdr phantom.RequestHeader, redial phantomRedialFn) *phantomStreamConn {
	sc := &phantomStreamConn{
		fromPool: fromPool,
		reqHdr:   reqHdr,
		redial:   redial,
	}
	sc.tconnPtr.Store(tconn)
	return sc
}

func (c *phantomStreamConn) sendInitialEncodedLocked(encoded []byte) error {
	tc := c.tconnPtr.Load()

	c.stateMu.Lock()
	canRetry := c.fromPool && c.redial != nil && !c.closed.Load()
	if canRetry {
		c.firstEncoded = append([]byte(nil), encoded...)
	}
	c.stateMu.Unlock()

	_, wErr := tc.Write(encoded)
	if wErr != nil && canRetry {
		c.stateMu.Lock()
		_ = tc.Close()
		c.fromPool = false
		c.firstEncoded = nil
		fresh, rErr := c.redial()
		if rErr != nil {
			c.stateMu.Unlock()
			return rErr
		}
		c.tconnPtr.Store(fresh)
		c.stateMu.Unlock()
		_, wErr = fresh.Write(encoded)
	}
	return wErr
}

func (c *phantomStreamConn) Write(p []byte) (int, error) {
	if c.headerDone.Load() {
		if !c.hasFirstRead.Load() {
			c.stateMu.Lock()
			c.fromPool = false
			c.firstEncoded = nil
			c.stateMu.Unlock()
		}
		return c.tconnPtr.Load().Write(p)
	}

	c.headerMu.Lock()
	if c.headerSent {
		c.headerMu.Unlock()
		if !c.hasFirstRead.Load() {
			c.stateMu.Lock()
			c.fromPool = false
			c.firstEncoded = nil
			c.stateMu.Unlock()
		}
		return c.tconnPtr.Load().Write(p)
	}

	encoded, err := phantom.EncodeRequestHeader(c.reqHdr, p)
	if err != nil {
		c.headerMu.Unlock()
		return 0, err
	}

	wErr := c.sendInitialEncodedLocked(encoded)
	c.headerSent = true
	c.headerDone.Store(true)
	c.headerMu.Unlock()

	if wErr != nil {
		return 0, wErr
	}
	return len(p), nil
}

func (c *phantomStreamConn) Read(b []byte) (int, error) {
	if !c.headerDone.Load() {
		c.headerMu.Lock()
		if !c.headerSent {
			encoded, err := phantom.EncodeRequestHeader(c.reqHdr, nil)
			if err != nil {
				c.headerMu.Unlock()
				return 0, err
			}
			wErr := c.sendInitialEncodedLocked(encoded)
			c.headerSent = true
			c.headerDone.Store(true)
			if wErr != nil {
				c.headerMu.Unlock()
				return 0, wErr
			}
		}
		c.headerMu.Unlock()
	}

	tc := c.tconnPtr.Load()
	n, err := tc.Read(b)
	if n > 0 {
		if !c.hasFirstRead.Load() {
			c.stateMu.Lock()
			c.fromPool = false
			c.firstEncoded = nil
			c.hasFirstRead.Store(true)
			c.stateMu.Unlock()
		}
		return n, err
	}

	if err != nil && !c.hasFirstRead.Load() && !c.closed.Load() {
		c.stateMu.Lock()
		if c.fromPool && len(c.firstEncoded) > 0 && c.redial != nil {
			saved := c.firstEncoded
			c.firstEncoded = nil
			c.fromPool = false
			_ = tc.Close()
			fresh, rErr := c.redial()
			if rErr != nil {
				c.stateMu.Unlock()
				return 0, rErr
			}
			if _, wErr := fresh.Write(saved); wErr != nil {
				_ = fresh.Close()
				c.stateMu.Unlock()
				return 0, wErr
			}
			c.tconnPtr.Store(fresh)
			c.stateMu.Unlock()

			n, err = fresh.Read(b)
			if n > 0 {
				c.hasFirstRead.Store(true)
			}
			return n, err
		}
		c.stateMu.Unlock()
	}

	return n, err
}

func (c *phantomStreamConn) Close() error {
	c.closed.Store(true)
	return c.tconnPtr.Load().Close()
}

func (c *phantomStreamConn) CloseWrite() error {
	return c.tconnPtr.Load().CloseWrite()
}

func (c *phantomStreamConn) LocalAddr() net.Addr                { return c.tconnPtr.Load().LocalAddr() }
func (c *phantomStreamConn) RemoteAddr() net.Addr               { return c.tconnPtr.Load().RemoteAddr() }
func (c *phantomStreamConn) SetDeadline(t time.Time) error      { return c.tconnPtr.Load().SetDeadline(t) }
func (c *phantomStreamConn) SetReadDeadline(t time.Time) error  { return c.tconnPtr.Load().SetReadDeadline(t) }
func (c *phantomStreamConn) SetWriteDeadline(t time.Time) error { return c.tconnPtr.Load().SetWriteDeadline(t) }
