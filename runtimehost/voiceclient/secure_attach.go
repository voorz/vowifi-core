package voiceclient

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// AttachSecureMessaging binds the messaging client to an already-authenticated
// IMS ESP channel. It creates a unified sipgo UA + Client + Server, injects
// the pre-established TCP connection via InjectTCPConnection, and registers
// OnMessage handler for inbound SIP MESSAGE (SMS delivery reports, incoming SMS).
//
// This is the unified SIP stack architecture: all SIP transactions (SUBSCRIBE,
// NOTIFY, MESSAGE, RP-ACK) flow through this single UA, sharing one IMS tunnel
// with VoWiFi. See VOWIFI_SMS_IMPLEMENTATION_SPEC.md 改动点 1 for design rationale.
func AttachSecureMessaging(ctx context.Context, cfg Config, conn net.Conn) (*Client, error) {
	if conn == nil {
		return nil, errors.New("voiceclient: secure messaging connection is required")
	}
	if cfg.LocalIP == nil || cfg.LocalPort <= 0 {
		return nil, errors.New("voiceclient: secure messaging local endpoint is required")
	}
	if strings.TrimSpace(cfg.PCSCFAddr) == "" {
		return nil, errors.New("voiceclient: secure messaging P-CSCF is required")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" || strings.TrimSpace(cfg.PublicURI) == "" || strings.TrimSpace(cfg.HomeDomain) == "" {
		return nil, errors.New("voiceclient: secure messaging IMS identity is required")
	}
	if cfg.Transport == "" {
		cfg.Transport = "tcp"
	}
	cfg.SkipRegister = true
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("voiceclient: clear inherited secure messaging deadline: %w", err)
	}

	registerProfile := registerProfileForConfig(cfg).Normalized()
	if strings.TrimSpace(cfg.RegisterProfile.ContactFeatures) != "" {
		registerProfile = cfg.RegisterProfile.Normalized()
	}
	sipInstanceURN := strings.TrimSpace(cfg.SIPInstanceURN)
	if sipInstanceURN == "" {
		sipInstanceURN = NewSIPInstanceURN()
	}
	contactUser := ""
	if registerProfile.ContactUserRandom {
		contactUser = newContactUserUUID()
	}

	// Create unified sipgo UA + Client + Server.
	// The UA's transport layer will own the injected TCP connection.

	// 改动点 5: connDone channel for TCP EOF detection.
	// Closed when the P-CSCF closes the TCP connection, signaling imscore
	// to trigger pipeline recovery.
	connDone := make(chan struct{})
	connDoneOnce := &sync.Once{}
	signalConnDone := func() {
		connDoneOnce.Do(func() { close(connDone) })
	}

	uaOptions := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(registerProfile.UserAgent),
		// 改动点 5: Register OnConnClose callback to detect TCP EOF.
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerOnConnClose(func(_ sip.Connection) {
				logger.Info(fmt.Sprintf("[%s] IMS TCP OnConnClose 回调触发", strings.TrimSpace(cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
					logger.String("device_id", strings.TrimSpace(cfg.DeviceID)))
				signalConnDone()
			}),
			sip.WithTransactionLayerTerminateOnConnClose(),
		),
	}
	// Attach device_id/trace_id context to sipgo's transport and transaction
	// layer logs, matching the pattern used in Dial() and startInboundSIPServer().
	deviceLogger := slog.New(logger.NewSlogHandler(logger.Get())).With(
		"device_id", strings.TrimSpace(cfg.DeviceID),
		"trace_id", strings.TrimSpace(cfg.TraceID),
	)
	uaOptions = append(uaOptions,
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerLogger(deviceLogger),
		),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerLogger(deviceLogger),
		),
	)
	ua, err := sipgo.NewUA(uaOptions...)
	if err != nil {
		return nil, fmt.Errorf("voiceclient: secure messaging UA: %w", err)
	}

	clientOptions := []sipgo.ClientOption{
		sipgo.WithClientHostname(cfg.LocalIP.String()),
		sipgo.WithClientPort(cfg.localPort()),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(cfg.LocalIP.String(), fmt.Sprintf("%d", cfg.localPort()))),
	}
	sipClient, err := sipgo.NewClient(ua, clientOptions...)
	if err != nil {
		_ = ua.Close()
		return nil, fmt.Errorf("voiceclient: secure messaging client: %w", err)
	}

	sipServer, err := sipgo.NewServer(ua)
	if err != nil {
		_ = sipClient.Close()
		_ = ua.Close()
		return nil, fmt.Errorf("voiceclient: secure messaging server: %w", err)
	}

	c := &Client{
		cfg:             cfg,
		ua:              ua,
		client:          sipClient,
		server:          sipServer,
		registerProfile: registerProfile,
		sipInstanceURN:  sipInstanceURN,
		contactUser:     contactUser,
		basePrivateID:   cfg.PrivateID,
		basePublicURI:   cfg.PublicURI,
		securityClient:  newSecurityClientState(),
		stopCh:          make(chan struct{}),
		stopDone:        make(chan struct{}),
		connDone:        connDone,
		connDoneOnce:    *connDoneOnce,
	}

	// Register OnMessage handler for inbound SIP MESSAGE (SMS + delivery reports).
	sipServer.OnMessage(c.handleIncomingMessage)

	// Inject the pre-established TCP connection into sipgo transport layer.
	// After injection, inbound SIP messages are parsed and dispatched by sipgo's
	// Server TransactionLayer — no manual readLoop needed.
	ua.TransportLayer().InjectTCPConnection(conn)

	logger.Debug(fmt.Sprintf("[%s] sipgo 安全连接注入成功", strings.TrimSpace(cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(cfg.TraceID)),
		logger.String("local", conn.LocalAddr().String()),
		logger.String("remote", conn.RemoteAddr().String()))

	// 改动点 6: stopDone goroutine — ensures Client.Close() doesn't block for 10s.
	// 06d896c forgot this goroutine; must always be present when creating a Client.
	// Also signals connDone as a fallback when the client is shutting down.
	go func() {
		select {
		case <-ctx.Done():
		case <-c.stopCh:
		}
		close(c.stopDone)
		c.signalConnDone() // fallback: ensure connDone is closed on shutdown
	}()

	// 改动点 3: Start REGISTER refresh loop to keep the TCP connection alive.
	// The refresh interval = expires * 80%. SkipRegister is true because the
	// initial registration was done by imscore, but we still need periodic
	// refresh to prevent the P-CSCF from tearing down the session.
if cfg.RegisterExpiry > 0 {
	c.startRefreshLoop(cfg.RegisterExpiry)
} else {
	// Default to 3600s if not specified.
	c.startRefreshLoop(3600 * time.Second)
}

// Start SIP OPTIONS keepalive loop to prevent P-CSCF from closing idle
// TCP connections between REGISTER refreshes. The keepalive interval
// is controlled by TCPKeepaliveSeconds (default 15s) and OptionsPingIntervalSeconds
// (default 30s) from the carrier profile.
c.startKeepaliveLoop(cfg.TCPKeepaliveSeconds, cfg.OptionsPingIntervalSeconds)

return c, nil
}

// appendHeaderToken appends a token to a SIP header if not already present.
// Used by Require/Proxy-Require sec-agree handling.
func appendHeaderToken(req *sip.Request, headerName, token string) {
	if req == nil {
		return
	}
	for _, header := range req.GetHeaders(headerName) {
		if header == nil {
			continue
		}
		for _, existing := range strings.Split(header.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(existing), token) {
				return
			}
		}
	}
	req.AppendHeader(sip.NewHeader(headerName, token))
}
