package adapter

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/convert"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/phantom"
)

func TestPhantomParseProxyConfig(t *testing.T) {
	_, pub, err := phantom.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	validCases := []struct {
		name      string
		publicKey string
		sni       any
	}{
		{
			name:      "raw_url_base64_and_slice_any",
			publicKey: base64.RawURLEncoding.EncodeToString(pub[:]),
			sni:       []any{"www.microsoft.com", "learn.microsoft.com"},
		},
		{
			name:      "std_base64_and_csv_sni",
			publicKey: base64.StdEncoding.EncodeToString(pub[:]),
			sni:       "www.microsoft.com, ajax.aspnetcdn.com",
		},
		{
			name:      "hex_key_and_string_slice",
			publicKey: hex.EncodeToString(pub[:]),
			sni:       []string{"www.microsoft.com"},
		},
		{
			name:      "omitted_sni_default",
			publicKey: base64.RawURLEncoding.EncodeToString(pub[:]),
			sni:       nil,
		},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]any{
				"name":       "phantom-" + tc.name,
				"type":       "phantom",
				"server":     "23.144.20.116",
				"port":       443,
				"user-id":    1001,
				"secret":     "test-secret-uuid",
				"public-key": tc.publicKey,
			}
			if tc.sni != nil {
				m["sni"] = tc.sni
			}
			p, err := ParseProxy(m)
			if err != nil {
				t.Fatalf("ParseProxy(%s) failed: %v", tc.name, err)
			}
			defer p.Close()
			if p.Type() != C.Phantom {
				t.Fatalf("expected C.Phantom, got %v", p.Type())
			}
		})
	}

	invalidCases := []struct {
		name    string
		mapping map[string]any
	}{
		{
			name: "missing_server",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "", "port": 443,
				"user-id": 1, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
			},
		},
		{
			name: "invalid_port_zero",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 0,
				"user-id": 1, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
			},
		},
		{
			name: "invalid_port_overflow",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 70000,
				"user-id": 1, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
			},
		},
		{
			name: "zero_user_id",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 443,
				"user-id": 0, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
			},
		},
		{
			name: "empty_secret",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 443,
				"user-id": 1, "secret": "", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
			},
		},
		{
			name: "short_public_key",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 443,
				"user-id": 1, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:31]),
			},
		},
		{
			name: "non_base64_public_key",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 443,
				"user-id": 1, "secret": "sec", "public-key": "not!a!valid!key",
			},
		},
		{
			name: "empty_sni_string",
			mapping: map[string]any{
				"name": "bad", "type": "phantom", "server": "1.2.3.4", "port": 443,
				"user-id": 1, "secret": "sec", "public-key": base64.RawURLEncoding.EncodeToString(pub[:]),
				"sni": "  ,  ",
			},
		},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseProxy(tc.mapping); err == nil {
				t.Fatalf("expected ParseProxy(%s) to fail, got nil", tc.name)
			}
		})
	}
}

func TestPhantomWireFingerprintParity(t *testing.T) {
	priv, pub, err := phantom.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	_, srvPub, err := phantom.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}

	tmpl, err := phantom.PrepareChromeHelloTemplate("www.microsoft.com", pub)
	if err != nil {
		t.Fatalf("PrepareChromeHelloTemplate: %v", err)
	}
	aad := phantom.BuildAAD("www.microsoft.com", tmpl.CipherSuites)
	seed := phantom.PackShapeSeed(0x123456, phantom.CipherAES128GCM)
	random, sid, _, err := phantom.EmbedStego(priv, srvPub, 1001, []byte("secret"), uint32(time.Now().Unix()), seed, aad)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := tmpl.MarshalRecord(random, sid)
	if err != nil {
		t.Fatalf("MarshalRecord: %v", err)
	}
	parsed, err := phantom.ParseClientHelloRecord(rec)
	if err != nil {
		t.Fatalf("ParseClientHelloRecord: %v", err)
	}
	if !parsed.SupportsTLS13 || !parsed.HasX25519 {
		t.Fatalf("expected TLS 1.3 X25519 ClientHello, got TLS13=%v X25519=%v", parsed.SupportsTLS13, parsed.HasX25519)
	}
	if parsed.X25519KeyShare != pub {
		t.Fatal("ClientHello X25519 KeyShare mismatch")
	}

	var key, tag [32]byte
	fin256, err := phantom.BuildClientFinishedRecord(key, tag, 0x1301)
	if err != nil {
		t.Fatal(err)
	}
	// 6B CCS + 5B AppData header + 53B payload
	if len(fin256) != 6+5+53 {
		t.Fatalf("expected 53B ClientFinished payload for 0x1301, total len=%d", len(fin256))
	}
	fin384, err := phantom.BuildClientFinishedRecord(key, tag, 0x1302)
	if err != nil {
		t.Fatal(err)
	}
	if len(fin384) != 6+5+69 {
		t.Fatalf("expected 69B ClientFinished payload for 0x1302, total len=%d", len(fin384))
	}

	// Verify CloseWrite emits exact 19B record payload (0x17 0x03 0x03 0x00 0x13 + 19B)
	c1, c2 := net.Pipe()
	defer c2.Close()
	tc, err := phantom.NewTunnelConn(c1, key, key, seed)
	if err != nil {
		t.Fatal(err)
	}
	var gotClose []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		gotClose, _ = io.ReadAll(c2)
	}()
	_ = tc.Close()
	<-done
	if len(gotClose) != 5+19 || gotClose[0] != 0x17 || gotClose[3] != 0x00 || gotClose[4] != 0x13 {
		t.Fatalf("expected 19B compact CloseAlert record (24B wire), got %d bytes: %x", len(gotClose), gotClose)
	}
}

type localPhantomServer struct {
	ln            net.Listener
	priv          [32]byte
	pub           [32]byte
	userID        uint32
	userSecret    string
	fallbackAddr  string
	activeConns   atomic.Int64
	fallbackConns atomic.Int64
	authOKConns   atomic.Int64
	mu            sync.Mutex
	activeRaw     map[net.Conn]struct{}
	wg            sync.WaitGroup
}

func (s *localPhantomServer) closeActiveServerConns() {
	s.mu.Lock()
	conns := make([]net.Conn, 0, len(s.activeRaw))
	for c := range s.activeRaw {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func startLocalPhantomServer(t *testing.T, userID uint32, userSecret string) *localPhantomServer {
	t.Helper()

	// Start a mock HTTPS-like fallback dest that returns non-Phantom TLS ServerHello + alert or closes cleanly.
	fbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fbLn.Close() })
	go func() {
		for {
			c, err := fbLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 2048)
				_, _ = conn.Read(buf)
				// Respond with non-matching TLS ServerHello + small ApplicationData (no valid serverHandshakeTag)
				var srvPub [32]byte
				_, _ = rand.Read(srvPub[:])
				var randKey, randTag [32]byte
				_, _ = rand.Read(randKey[:])
				_, _ = rand.Read(randTag[:])
				flight, _ := phantom.BuildSimulatedServerFlight(
					phantom.DefaultProfile("www.microsoft.com", ""),
					make([]byte, 32),
					srvPub,
					randKey,
					randTag,
				)
				_, _ = conn.Write(flight)
			}(c)
		}
	}()

	priv, pub, err := phantom.GenerateX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := &localPhantomServer{
		ln:           ln,
		priv:         priv,
		pub:          pub,
		userID:       userID,
		userSecret:   userSecret,
		fallbackAddr: fbLn.Addr().String(),
		activeRaw:    make(map[net.Conn]struct{}),
	}
	t.Cleanup(func() {
		_ = ln.Close()
		s.wg.Wait()
	})

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			s.wg.Add(1)
			go func(c net.Conn) {
				defer s.wg.Done()
				s.handleConn(c)
			}(conn)
		}
	}()

	return s
}

func (s *localPhantomServer) handleConn(clientConn net.Conn) {
	defer clientConn.Close()
	_ = clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))

	rawFirst, isTLS, err := phantom.ReadFirstTLSRecordOrRaw(clientConn)
	if err != nil && len(rawFirst) == 0 {
		return
	}
	_ = clientConn.SetReadDeadline(time.Time{})

	fallback := func() {
		s.fallbackConns.Add(1)
		destConn, dErr := net.DialTimeout("tcp", s.fallbackAddr, 2*time.Second)
		if dErr != nil {
			return
		}
		defer destConn.Close()
		_, _ = destConn.Write(rawFirst)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(destConn, clientConn)
		}()
		go func() {
			defer wg.Done()
			_, _ = io.Copy(clientConn, destConn)
		}()
		wg.Wait()
	}

	if !isTLS {
		fallback()
		return
	}

	parsed, err := phantom.ParseClientHelloRecord(rawFirst)
	if err != nil || !parsed.SupportsTLS13 || !parsed.HasX25519 || len(parsed.SessionID) < 32 {
		fallback()
		return
	}
	var sid [32]byte
	copy(sid[:], parsed.SessionID[:32])
	aad := phantom.BuildAAD(parsed.SNI, parsed.CipherSuites)
	payload, sharedSecret, _, err := phantom.ExtractStego(s.priv, parsed.X25519KeyShare, parsed.Random, sid, aad)
	if err != nil || payload.UserID != s.userID {
		fallback()
		return
	}
	if !phantom.VerifyUserProof([]byte(s.userSecret), parsed.Random[0:16], payload) {
		fallback()
		return
	}

	s.authOKConns.Add(1)
	s.activeConns.Add(1)
	s.mu.Lock()
	s.activeRaw[clientConn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.activeRaw, clientConn)
		s.mu.Unlock()
		s.activeConns.Add(-1)
	}()

	srvEphPriv, srvEphPub, err := phantom.GenerateX25519KeyPair()
	if err != nil {
		return
	}
	ecdheSecret, err := phantom.ComputeSharedSecret(srvEphPriv, parsed.X25519KeyShare)
	if err != nil {
		return
	}
	c2sKey, s2cKey, srvTag, cliFinTag, err := phantom.DeriveSessionKeys(
		sharedSecret, ecdheSecret, parsed.X25519KeyShare, srvEphPub, parsed.Random[0:16],
	)
	if err != nil {
		return
	}
	profile := &phantom.DestProfile{
		SNI:               parsed.SNI,
		CipherSuite:       0x1302,
		CertRecordLengths: []int{36, 4096, 281, 69},
	}
	flight, err := phantom.BuildSimulatedServerFlight(profile, sid[:], srvEphPub, s2cKey, srvTag)
	if err != nil {
		return
	}
	if _, err := clientConn.Write(flight); err != nil {
		return
	}
	if err := phantom.ReadAndVerifyClientFinished(clientConn, c2sKey, cliFinTag); err != nil {
		return
	}

	tconn, err := phantom.NewTunnelConn(clientConn, c2sKey, s2cKey, payload.ShapeSeed)
	if err != nil {
		return
	}
	if err := tconn.SendDummySessionTicket(); err != nil {
		return
	}

	reqHdr, err := phantom.ReadRequestHeader(tconn)
	if err != nil {
		return
	}

	if reqHdr.Cmd == phantom.CmdUDP {
		udpSock, err := net.ListenPacket("udp", ":0")
		if err != nil {
			return
		}
		defer udpSock.Close()

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer udpSock.Close()
			defer tconn.Close()
			for {
				d, err := phantom.ReadUDPDatagram(tconn)
				if err != nil {
					return
				}
				raddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(d.Addr, strconv.Itoa(int(d.Port))))
				if err != nil {
					continue
				}
				_, _ = udpSock.WriteTo(d.Data, raddr)
			}
		}()
		go func() {
			defer wg.Done()
			defer udpSock.Close()
			defer tconn.Close()
			buf := make([]byte, 65535)
			for {
				n, raddr, err := udpSock.ReadFrom(buf)
				if err != nil {
					return
				}
				ua, ok := raddr.(*net.UDPAddr)
				if !ok {
					continue
				}
				at, addrStr := phantom.ParseTargetAddr(ua.IP.String())
				if err := phantom.WriteUDPDatagram(tconn, phantom.UDPDatagram{
					AddrType: at,
					Addr:     addrStr,
					Port:     uint16(ua.Port),
					Data:     buf[:n],
				}); err != nil {
					return
				}
			}
		}()
		wg.Wait()
		return
	}

	if reqHdr.Cmd != phantom.CmdTCP {
		return
	}
	targetConn, err := net.DialTimeout("tcp", reqHdr.TargetAddress(), 3*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(targetConn, tconn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(tconn, targetConn)
		_ = tconn.CloseWrite()
	}()
	wg.Wait()
}

type recordingDialer struct {
	called atomic.Bool
}

func (r *recordingDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	r.called.Store(true)
	return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, address)
}

func (r *recordingDialer) ListenPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort) (net.PacketConn, error) {
	return nil, errors.New("not implemented")
}

func TestPhantomTCPEndToEndAndFallback(t *testing.T) {
	// Start local upstream echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	srv := startLocalPhantomServer(t, 1001, "super-secret-token")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pubStr := base64.RawURLEncoding.EncodeToString(srv.pub[:])

	proxy, err := ParseProxy(map[string]any{
		"name":       "local-phantom",
		"type":       "phantom",
		"server":     host,
		"port":       port,
		"user-id":    1001,
		"secret":     "super-secret-token",
		"public-key": pubStr,
		"sni":        []any{"www.microsoft.com", "learn.microsoft.com"},
	})
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	defer proxy.Close()

	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	echoPort, _ := strconv.Atoi(echoPortStr)
	meta := &C.Metadata{
		NetWork: C.TCP,
		DstIP:   netip.MustParseAddr(echoHost),
		DstPort: uint16(echoPort),
	}

	t.Run("large_bidirectional_tcp_shaping_and_fastpath", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		conn, err := proxy.DialContext(ctx, meta)
		if err != nil {
			t.Fatalf("DialContext: %v", err)
		}

		// > 256 KB crosses both first-6 dynamic shaping and packet 7+ AES-128-GCM fast path
		payload := make([]byte, 280*1024)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}

		errCh := make(chan error, 1)
		go func() {
			// Write in realistic chunks to produce > 7 frames
			for off := 0; off < len(payload); {
				n := 1200
				if off > 12*1200 {
					n = 32 * 1024
				}
				if off+n > len(payload) {
					n = len(payload) - off
				}
				if _, wErr := conn.Write(payload[off : off+n]); wErr != nil {
					errCh <- wErr
					return
				}
				off += n
			}
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite()
			}
			errCh <- nil
		}()

		got := make([]byte, len(payload))
		if _, err := io.ReadFull(conn, got); err != nil {
			t.Fatalf("ReadFull echo: %v", err)
		}
		if wErr := <-errCh; wErr != nil {
			t.Fatalf("Write echo: %v", wErr)
		}
		if !bytes.Equal(got, payload) {
			t.Fatal("echoed TCP payload mismatch")
		}
		_ = conn.Close()

		// Wait briefly for server goroutine teardown to reclaim activeConns
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			if srv.activeConns.Load() == 0 {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if gotActive := srv.activeConns.Load(); gotActive != 0 {
			t.Fatalf("expected 0 active server conns after Close, got %d", gotActive)
		}
	})

	t.Run("dial_context_with_custom_dialer", func(t *testing.T) {
		if proxy.SupportWithDialer() != C.ALLNet {
			t.Fatalf("expected SupportWithDialer C.ALLNet, got %v", proxy.SupportWithDialer())
		}
		recDialer := &recordingDialer{}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := proxy.DialContextWithDialer(ctx, recDialer, meta)
		if err != nil {
			t.Fatalf("DialContextWithDialer: %v", err)
		}
		defer conn.Close()
		if !recDialer.called.Load() {
			t.Fatal("expected custom C.Dialer to be invoked")
		}

		msg := []byte("hello-custom-dialer")
		if _, err := conn.Write(msg); err != nil {
			t.Fatalf("Write: %v", err)
		}
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("got %q, want %q", buf, msg)
		}
	})

	t.Run("wrong_credentials_trigger_clean_error_and_server_fallback", func(t *testing.T) {
		beforeFB := srv.fallbackConns.Load()

		badSecretProxy, err := ParseProxy(map[string]any{
			"name":       "bad-secret",
			"type":       "phantom",
			"server":     host,
			"port":       port,
			"user-id":    1001,
			"secret":     "wrong-secret",
			"public-key": pubStr,
		})
		if err != nil {
			t.Fatalf("ParseProxy bad-secret: %v", err)
		}
		defer badSecretProxy.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if conn, err := badSecretProxy.DialContext(ctx, meta); err == nil {
			_ = conn.Close()
			t.Fatal("expected DialContext with wrong secret to fail")
		}

		_, wrongPub, _ := phantom.GenerateX25519KeyPair()
		badPubProxy, err := ParseProxy(map[string]any{
			"name":       "bad-pub",
			"type":       "phantom",
			"server":     host,
			"port":       port,
			"user-id":    1001,
			"secret":     "super-secret-token",
			"public-key": base64.RawURLEncoding.EncodeToString(wrongPub[:]),
		})
		if err != nil {
			t.Fatalf("ParseProxy bad-pub: %v", err)
		}
		defer badPubProxy.Close()

		if conn, err := badPubProxy.DialContext(ctx, meta); err == nil {
			_ = conn.Close()
			t.Fatal("expected DialContext with wrong public-key to fail")
		}

		if srv.fallbackConns.Load() < beforeFB+2 {
			t.Fatalf("expected server transparent fallback count >= %d, got %d", beforeFB+2, srv.fallbackConns.Load())
		}
		if srv.activeConns.Load() != 0 {
			t.Fatalf("expected 0 active conns after failed auth, got %d", srv.activeConns.Load())
		}
	})
}

func TestPhantomLiveNode23_144_20_116(t *testing.T) {
	// Ensure outbound.Phantom compiles cleanly as an exported adapter
	var _ outbound.ProxyAdapter = (*outbound.Phantom)(nil)

	cfgBytes, err := os.ReadFile("/Volumes/untitled/ai/客户端/configs/client.json")
	if err != nil {
		t.Skipf("live client.json not found, skipping remote node test: %v", err)
	}
	var cfg struct {
		ServerAddr      string   `json:"server_addr"`
		ServerPublicKey string   `json:"server_public_key"`
		UserID          uint32   `json:"user_id"`
		UserSecret      string   `json:"user_secret"`
		SNIList         []string `json:"sni_list"`
	}
	if err := json.Unmarshal(cfgBytes, &cfg); err != nil {
		t.Fatalf("unmarshal client.json: %v", err)
	}
	host, portStr, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		t.Fatalf("split server_addr: %v", err)
	}
	port, _ := strconv.Atoi(portStr)

	proxy, err := ParseProxy(map[string]any{
		"name":       "live-phantom",
		"type":       "phantom",
		"server":     host,
		"port":       port,
		"user-id":    cfg.UserID,
		"secret":     cfg.UserSecret,
		"public-key": cfg.ServerPublicKey,
		"sni":        cfg.SNIList,
		"udp":        true,
	})
	if err != nil {
		t.Fatalf("ParseProxy live: %v", err)
	}
	defer proxy.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := proxy.DialContext(ctx, &C.Metadata{
		NetWork: C.TCP,
		Host:    "api.ipify.org",
		DstPort: 80,
	})
	if err != nil {
		t.Fatalf("DialContext to live node %s: %v", cfg.ServerAddr, err)
	}
	defer conn.Close()

	req := "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nUser-Agent: phantom-mihomo-test\r\nConnection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("Write HTTP request: %v", err)
	}
	resp, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("ReadAll HTTP response: %v", err)
	}
	if !strings.Contains(string(resp), host) {
		t.Fatalf("expected live exit IP %q in response, got:\n%s", host, string(resp))
	}

	// Verify live UDP DNS query (example.com A record to 8.8.8.8:53)
	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("8.8.8.8"),
		DstPort: 53,
	})
	if err != nil {
		t.Fatalf("ListenPacketContext live UDP: %v", err)
	}
	defer pc.Close()
	_ = pc.SetReadDeadline(time.Now().Add(8 * time.Second))

	dnsQuery := []byte{
		0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		0x00, 0x01, 0x00, 0x01,
	}
	if _, err := pc.WriteTo(dnsQuery, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53}); err != nil {
		t.Fatalf("live UDP WriteTo DNS: %v", err)
	}
	dnsBuf := make([]byte, 1500)
	n, _, err := pc.ReadFrom(dnsBuf)
	if err != nil {
		t.Fatalf("live UDP ReadFrom DNS: %v", err)
	}
	if n < 12 || dnsBuf[0] != 0x12 || dnsBuf[1] != 0x34 || (dnsBuf[2]&0x80) == 0 {
		t.Fatalf("unexpected live DNS response (%d bytes): %x", n, dnsBuf[:n])
	}
}

func startUDPEchoServer(t *testing.T, network string, addr string) (*net.UDPConn, int) {
	t.Helper()
	pc, err := net.ListenPacket(network, addr)
	if err != nil {
		return nil, 0
	}
	uc := pc.(*net.UDPConn)
	t.Cleanup(func() { _ = uc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, raddr, err := uc.ReadFromUDP(buf)
			if err != nil {
				return
			}
			_, _ = uc.WriteToUDP(buf[:n], raddr)
		}
	}()
	return uc, uc.LocalAddr().(*net.UDPAddr).Port
}

type domainNetAddr struct {
	addr string
}

func (d domainNetAddr) Network() string { return "udp" }
func (d domainNetAddr) String() string  { return d.addr }

func TestPhantomUDPEndToEnd(t *testing.T) {
	_, udp4Port := startUDPEchoServer(t, "udp4", "127.0.0.1:0")
	if udp4Port == 0 {
		t.Fatal("failed to start ipv4 udp echo server")
	}

	srv := startLocalPhantomServer(t, 1001, "udp-secret")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pubStr := base64.RawURLEncoding.EncodeToString(srv.pub[:])

	// 1. udp: false rejects ListenPacketContext cleanly
	noUDPProxy, err := ParseProxy(map[string]any{
		"name":       "no-udp",
		"type":       "phantom",
		"server":     host,
		"port":       port,
		"user-id":    1001,
		"secret":     "udp-secret",
		"public-key": pubStr,
		"udp":        false,
	})
	if err != nil {
		t.Fatalf("ParseProxy no-udp: %v", err)
	}
	defer noUDPProxy.Close()
	if noUDPProxy.SupportUDP() {
		t.Fatal("expected SupportUDP=false")
	}
	if _, err := noUDPProxy.ListenPacketContext(context.Background(), &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udp4Port)}); !errors.Is(err, C.ErrNotSupport) {
		t.Fatalf("expected C.ErrNotSupport when udp=false, got %v", err)
	}

	// 2. udp: true supports IPv4, Domain, and IPv6 datagrams + custom dialer
	proxy, err := ParseProxy(map[string]any{
		"name":       "udp-phantom",
		"type":       "phantom",
		"server":     host,
		"port":       port,
		"user-id":    1001,
		"secret":     "udp-secret",
		"public-key": pubStr,
		"udp":        true,
	})
	if err != nil {
		t.Fatalf("ParseProxy udp: %v", err)
	}
	defer proxy.Close()
	if !proxy.SupportUDP() || !proxy.SupportUOT() {
		t.Fatal("expected SupportUDP and SupportUOT true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{
		NetWork: C.UDP,
		DstIP:   netip.MustParseAddr("127.0.0.1"),
		DstPort: uint16(udp4Port),
	})
	if err != nil {
		t.Fatalf("ListenPacketContext: %v", err)
	}

	buf := make([]byte, 2048)
	// IPv4 target packets
	for i := 0; i < 4; i++ {
		msg := []byte(fmt.Sprintf("ipv4-udp-dgram-%d-boundary-check", i))
		if _, err := pc.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp4Port}); err != nil {
			t.Fatalf("WriteTo IPv4: %v", err)
		}
		n, raddr, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom IPv4: %v", err)
		}
		if string(buf[:n]) != string(msg) || raddr == nil {
			t.Fatalf("IPv4 datagram mismatch: got %q (%v), want %q", buf[:n], raddr, msg)
		}
	}

	// Domain target packet (resolved on server side)
	domMsg := []byte("domain-udp-dgram-localhost")
	if _, err := pc.WriteTo(domMsg, domainNetAddr{addr: fmt.Sprintf("localhost:%d", udp4Port)}); err != nil {
		t.Fatalf("WriteTo domain: %v", err)
	}
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom domain: %v", err)
	}
	if string(buf[:n]) != string(domMsg) {
		t.Fatalf("domain datagram mismatch: got %q, want %q", buf[:n], domMsg)
	}

	// IPv6 loopback target if supported on host
	if _, udp6Port := startUDPEchoServer(t, "udp6", "[::1]:0"); udp6Port > 0 {
		v6Msg := []byte("ipv6-udp-dgram-loopback")
		if _, err := pc.WriteTo(v6Msg, &net.UDPAddr{IP: net.ParseIP("::1"), Port: udp6Port}); err != nil {
			t.Fatalf("WriteTo IPv6: %v", err)
		}
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom IPv6: %v", err)
		}
		if string(buf[:n]) != string(v6Msg) {
			t.Fatalf("IPv6 datagram mismatch: got %q, want %q", buf[:n], v6Msg)
		}
	}

	_ = pc.Close()

	// ListenPacketWithDialer verification
	recDialer := &recordingDialer{}
	pc2, err := proxy.ListenPacketWithDialer(ctx, recDialer, &C.Metadata{
		NetWork: C.UDP,
		Host:    "localhost",
		DstPort: uint16(udp4Port),
	})
	if err != nil {
		t.Fatalf("ListenPacketWithDialer: %v", err)
	}
	if !recDialer.called.Load() {
		t.Fatal("expected custom dialer to be invoked for UDP")
	}
	if _, err := pc2.WriteTo([]byte("udp-custom-dialer"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udp4Port}); err != nil {
		t.Fatalf("pc2 WriteTo: %v", err)
	}
	n, _, err = pc2.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "udp-custom-dialer" {
		t.Fatalf("pc2 ReadFrom mismatch: n=%d err=%v", n, err)
	}
	_ = pc2.Close()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.activeConns.Load() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if gotActive := srv.activeConns.Load(); gotActive != 0 {
		t.Fatalf("expected 0 active server conns after UDP close, got %d", gotActive)
	}
}

func TestPhantomWarmPoolLifecycleAndStaleRedial(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	echoHost, echoPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	echoPort, _ := strconv.Atoi(echoPortStr)
	meta := &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr(echoHost), DstPort: uint16(echoPort)}

	srv := startLocalPhantomServer(t, 1001, "pool-secret")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pubStr := base64.RawURLEncoding.EncodeToString(srv.pub[:])

	// Test lazy WarmPool with min-idle=2, max-idle=4
	ph, err := outbound.NewPhantom(outbound.PhantomOption{
		Name:      "pool-phantom",
		Server:    host,
		Port:      port,
		UserID:    1001,
		Secret:    "pool-secret",
		PublicKey: pubStr,
		MinIdle:   2,
		MaxIdle:   4,
		UDP:       true,
	})
	if err != nil {
		t.Fatalf("NewPhantom: %v", err)
	}
	defer ph.Close()

	// Lazy pool must stay dormant before first Acquire (zero background connections)
	time.Sleep(150 * time.Millisecond)
	if ph.PoolIdleCount() != 0 || srv.authOKConns.Load() != 0 {
		t.Fatalf("expected dormant pool before first use, idle=%d authOK=%d", ph.PoolIdleCount(), srv.authOKConns.Load())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// First Dial wakes WarmPool and triggers background fill of minIdle=2 connections
	c1, err := ph.DialContext(ctx, meta)
	if err != nil {
		t.Fatalf("DialContext #1: %v", err)
	}
	if _, err := c1.Write([]byte("wake-pool")); err != nil {
		t.Fatalf("Write #1: %v", err)
	}
	r1 := make([]byte, 9)
	if _, err := io.ReadFull(c1, r1); err != nil {
		t.Fatalf("Read #1: %v", err)
	}
	_ = c1.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ph.PoolIdleCount() < 2 {
		time.Sleep(30 * time.Millisecond)
	}
	if ph.PoolIdleCount() < 2 {
		t.Fatalf("expected warm pool to fill at least 2 idle conns, got %d", ph.PoolIdleCount())
	}

	// Kill all active pooled connections on the server side to simulate stale half-closed conns
	srv.closeActiveServerConns()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.activeConns.Load() > 0 {
		time.Sleep(20 * time.Millisecond)
	}

	// Next DialContext picks a stale pooled conn and must transparently redial on Write failure
	beforeAuth := srv.authOKConns.Load()
	c2, err := ph.DialContext(ctx, meta)
	if err != nil {
		t.Fatalf("DialContext #2: %v", err)
	}
	if _, err := c2.Write([]byte("after-stale-redial")); err != nil {
		t.Fatalf("Write after stale pooled conn should transparently redial, got err: %v", err)
	}
	r2 := make([]byte, len("after-stale-redial"))
	if _, err := io.ReadFull(c2, r2); err != nil || string(r2) != "after-stale-redial" {
		t.Fatalf("Read #2 failed: %q err=%v", r2, err)
	}
	_ = c2.Close()
	if srv.authOKConns.Load() <= beforeAuth {
		t.Fatal("expected transparent redial to establish a new authenticated connection")
	}

	// Reset must immediately clear idle pool (network switch simulation)
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && ph.PoolIdleCount() == 0 {
		time.Sleep(30 * time.Millisecond)
	}
	ph.Reset()
	if ph.PoolIdleCount() != 0 {
		t.Fatalf("expected 0 idle conns immediately after Reset, got %d", ph.PoolIdleCount())
	}

	// Proxy still works after Reset
	c3, err := ph.DialContext(ctx, meta)
	if err != nil {
		t.Fatalf("DialContext after Reset: %v", err)
	}
	if _, err := c3.Write([]byte("post-reset")); err != nil {
		t.Fatalf("Write after Reset: %v", err)
	}
	r3 := make([]byte, len("post-reset"))
	if _, err := io.ReadFull(c3, r3); err != nil || string(r3) != "post-reset" {
		t.Fatalf("Read after Reset mismatch: %q err=%v", r3, err)
	}
	_ = c3.Close()

	// Closing outbound clears pool and drains server activeConns to 0
	_ = ph.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && srv.activeConns.Load() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if gotActive := srv.activeConns.Load(); gotActive != 0 {
		t.Fatalf("expected 0 active server conns after Close, got %d", gotActive)
	}
}

func TestPhantomConcurrentTCPAndUDPRace(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	tcpHost, tcpPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPort := startUDPEchoServer(t, "udp4", "127.0.0.1:0")

	srv := startLocalPhantomServer(t, 1001, "race-secret")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	pubStr := base64.RawURLEncoding.EncodeToString(srv.pub[:])

	proxy, err := ParseProxy(map[string]any{
		"name":       "race-phantom",
		"type":       "phantom",
		"server":     host,
		"port":       port,
		"user-id":    1001,
		"secret":     "race-secret",
		"public-key": pubStr,
		"min-idle":   2,
		"max-idle":   6,
		"udp":        true,
	})
	if err != nil {
		t.Fatalf("ParseProxy: %v", err)
	}
	defer proxy.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 24)

	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			c, err := proxy.DialContext(ctx, &C.Metadata{
				NetWork: C.TCP, DstIP: netip.MustParseAddr(tcpHost), DstPort: uint16(tcpPort),
			})
			if err != nil {
				errs <- err
				return
			}
			defer c.Close()
			msg := []byte(fmt.Sprintf("tcp-worker-%d-payload", id))
			if _, err := c.Write(msg); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("tcp mismatch worker %d", id)
			}
		}(i)

		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{
				NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpPort),
			})
			if err != nil {
				errs <- err
				return
			}
			defer pc.Close()
			msg := []byte(fmt.Sprintf("udp-worker-%d-payload", id))
			if _, err := pc.WriteTo(msg, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udpPort}); err != nil {
				errs <- err
				return
			}
			buf := make([]byte, 512)
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				errs <- err
				return
			}
			if string(buf[:n]) != string(msg) {
				errs <- fmt.Errorf("udp mismatch worker %d", id)
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent TCP/UDP error: %v", err)
		}
	}

	_ = proxy.Close()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.activeConns.Load() > 0 {
		time.Sleep(20 * time.Millisecond)
	}
	if gotActive := srv.activeConns.Load(); gotActive != 0 {
		t.Fatalf("expected 0 active server conns after concurrent stress test, got %d", gotActive)
	}
}

func TestPhantomURIToParseProxyE2E(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()
	tcpHost, tcpPortStr, _ := net.SplitHostPort(echoLn.Addr().String())
	tcpPort, _ := strconv.Atoi(tcpPortStr)
	_, udpPort := startUDPEchoServer(t, "udp4", "127.0.0.1:0")

	srv := startLocalPhantomServer(t, 2025, "uri-secret-xyz")
	host, portStr, _ := net.SplitHostPort(srv.ln.Addr().String())
	pubStr := base64.RawURLEncoding.EncodeToString(srv.pub[:])

	shareURI := fmt.Sprintf("phantom://2025:uri-secret-xyz@%s:%s?pub=%s&sni=www.microsoft.com,learn.microsoft.com&fp=chrome#URI%%20Node", host, portStr, pubStr)
	sub := base64.StdEncoding.EncodeToString([]byte(shareURI))

	mappings, err := convert.ConvertsV2Ray([]byte(sub))
	if err != nil || len(mappings) != 1 {
		t.Fatalf("ConvertsV2Ray failed: mappings=%d err=%v", len(mappings), err)
	}

	proxy, err := ParseProxy(mappings[0])
	if err != nil {
		t.Fatalf("ParseProxy from ConvertsV2Ray: %v", err)
	}
	defer proxy.Close()
	if proxy.Name() != "URI Node" || proxy.Type() != C.Phantom {
		t.Fatalf("unexpected proxy name/type: %q / %v", proxy.Name(), proxy.Type())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()

	// Verify TCP via converted URI proxy
	c, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, DstIP: netip.MustParseAddr(tcpHost), DstPort: uint16(tcpPort)})
	if err != nil {
		t.Fatalf("TCP DialContext via URI proxy: %v", err)
	}
	if _, err := c.Write([]byte("uri-tcp-ok")); err != nil {
		t.Fatal(err)
	}
	gotTCP := make([]byte, 10)
	if _, err := io.ReadFull(c, gotTCP); err != nil || string(gotTCP) != "uri-tcp-ok" {
		t.Fatalf("URI TCP echo mismatch: %q err=%v", gotTCP, err)
	}
	_ = c.Close()

	// Verify UDP via converted URI proxy
	pc, err := proxy.ListenPacketContext(ctx, &C.Metadata{NetWork: C.UDP, DstIP: netip.MustParseAddr("127.0.0.1"), DstPort: uint16(udpPort)})
	if err != nil {
		t.Fatalf("UDP ListenPacketContext via URI proxy: %v", err)
	}
	if _, err := pc.WriteTo([]byte("uri-udp-ok"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udpPort}); err != nil {
		t.Fatal(err)
	}
	uBuf := make([]byte, 64)
	n, _, err := pc.ReadFrom(uBuf)
	if err != nil || string(uBuf[:n]) != "uri-udp-ok" {
		t.Fatalf("URI UDP echo mismatch: %q err=%v", uBuf[:n], err)
	}
	_ = pc.Close()
}
