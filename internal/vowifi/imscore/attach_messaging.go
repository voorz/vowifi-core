package imscore

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// attachSIPStack creates a unified sipgo UA + Client + Server directly owned
// by imscore.Service, and injects the pre-established TCP connection.
//
// This replaces voiceclient.AttachSecureMessaging — instead of creating a
// voiceclient.Client wrapper, imscore.Service directly holds the SIP stack
// (sipUA, sipClient, sipServer) and all IMS identity state.
//
// After this call:
//   - s.sipUA / s.sipClient / s.sipServer are populated
//   - s.tcpConn is injected into the sipgo transport layer
//   - s.registerProfile / s.sipInstanceURN / s.contactUser etc. are set
//   - s.stopCh / s.stopDone / s.connDone are initialized
//   - Inbound SIP MESSAGE handler is registered on s.sipServer
//   - REGISTER refresh loop and keepalive loop are started
func (s *Service) attachSIPStack(ctx context.Context, conn net.Conn, reg *registerResult) error {
	if conn == nil {
		return fmt.Errorf("imscore: secure messaging connection is required")
	}
	if s.cfg.LocalIP == nil {
		return fmt.Errorf("imscore: local IP is required")
	}
	if strings.TrimSpace(s.cfg.PCSCFAddr) == "" {
		return fmt.Errorf("imscore: P-CSCF is required")
	}
	if strings.TrimSpace(s.cfg.PrivateID) == "" || strings.TrimSpace(s.cfg.PublicURI) == "" || strings.TrimSpace(s.cfg.HomeDomain) == "" {
		return fmt.Errorf("imscore: IMS identity is required")
	}

	// Clear any inherited deadline on the connection.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return fmt.Errorf("imscore: clear connection deadline: %w", err)
	}

	// Resolve register profile.
	registerProfile := voiceclient.SimAdminGBEERegisterProfile()
	if ua := strings.TrimSpace(s.imsCfg.UserAgent); ua != "" {
		rp := registerProfile
		rp.UserAgent = ua
		registerProfile = rp.Normalized()
	}

	// Resolve SIP instance URN.
	sipInstanceURN := strings.TrimSpace(s.cfg.SIPInstanceURN)
	if sipInstanceURN == "" {
		sipInstanceURN = voiceclient.NewSIPInstanceURN()
	}

	// Resolve contact user.
	contactUser := ""
	if registerProfile.ContactUserRandom {
		contactUser = newContactUserUUID()
	}

	// Initialize lifecycle channels.
	s.stopCh = make(chan struct{})
	s.stopDone = make(chan struct{})
	s.connDone = make(chan struct{})

	// Create sipgo UA with OnConnClose callback for TCP EOF detection.
	deviceID := strings.TrimSpace(s.cfg.DeviceID)
	traceID := strings.TrimSpace(s.cfg.TraceID)

	signalConnDone := func() {
		s.connDoneOnce.Do(func() { close(s.connDone) })
	}

	uaOptions := []sipgo.UserAgentOption{
		sipgo.WithUserAgent(registerProfile.UserAgent),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerOnConnClose(func(_ sip.Connection) {
				logger.Info(fmt.Sprintf("[%s] IMS TCP OnConnClose 回调触发", deviceID),
					logger.String("trace_id", traceID),
					logger.String("device_id", deviceID))
				signalConnDone()
			}),
			sip.WithTransactionLayerTerminateOnConnClose(),
		),
	}
	deviceLogger := slog.New(logger.NewSlogHandler(logger.Get())).With(
		"device_id", deviceID,
		"trace_id", traceID,
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
		return fmt.Errorf("imscore: create UA: %w", err)
	}

	localPort := s.imsCfg.LocalPort
	if localPort <= 0 {
		localPort = 5060
	}

	clientOptions := []sipgo.ClientOption{
		sipgo.WithClientHostname(s.cfg.LocalIP.String()),
		sipgo.WithClientPort(localPort),
		sipgo.WithClientConnectionAddr(net.JoinHostPort(s.cfg.LocalIP.String(), fmt.Sprintf("%d", localPort))),
	}
	sipClient, err := sipgo.NewClient(ua, clientOptions...)
	if err != nil {
		_ = ua.Close()
		return fmt.Errorf("imscore: create SIP client: %w", err)
	}

	sipServer, err := sipgo.NewServer(ua)
	if err != nil {
		_ = sipClient.Close()
		_ = ua.Close()
		return fmt.Errorf("imscore: create SIP server: %w", err)
	}

	// Populate imscore.Service fields directly.
	s.sipUA = ua
	s.sipClient = sipClient
	s.sipServer = sipServer
	s.tcpConn = conn
	s.registerProfile = registerProfile
	s.sipInstanceURN = sipInstanceURN
	s.contactUser = contactUser
	s.basePrivateID = s.cfg.PrivateID
	s.basePublicURI = s.cfg.PublicURI
	s.securityClient = newSecurityClientState()

	// Inherit Security-Verify and Service-Route from the registration result.
	s.verifyHeader = reg.verifyHeader
	s.serviceRoutes = append([]string(nil), reg.serviceRoutes...)

	// Register OnMessage handler for inbound SIP MESSAGE.
	sipServer.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		s.handleInboundSIPMessage(s.lifecycleCtx, req, tx)
	})

	// Inject the pre-established TCP connection into sipgo transport layer.
	ua.TransportLayer().InjectTCPConnection(conn)

	logger.Debug(fmt.Sprintf("[%s] sipgo 安全连接注入成功 (imscore 直持)", deviceID),
		logger.String("trace_id", traceID),
		logger.String("local", conn.LocalAddr().String()),
		logger.String("remote", conn.RemoteAddr().String()))

	// stopDone goroutine — ensures Close() doesn't block.
	// Also signals connDone as a fallback when shutting down.
	go func() {
		select {
		case <-ctx.Done():
		case <-s.stopCh:
		}
		close(s.stopDone)
		signalConnDone()
	}()

	// Start REGISTER refresh loop.
	expires := time.Duration(reg.expiresSeconds) * time.Second
	if expires <= 0 {
		expires = 3600 * time.Second
	}
	s.startRefreshLoop(expires)

	// Start SIP OPTIONS keepalive loop.
	s.startKeepaliveLoop(s.cfg.TCPKeepaliveSeconds, s.cfg.OptionsPingIntervalSeconds)

	return nil
}

// signalConnDone safely closes the connDone channel exactly once.
func (s *Service) signalConnDone() {
	s.connDoneOnce.Do(func() {
		close(s.connDone)
	})
}

// ConnDone returns a channel that is closed when the injected TCP connection
// is closed by the remote side (EOF, reset, or read error).
func (s *Service) ConnDone() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.connDone
}

// shutdownSIPStack closes the imscore-owned SIP stack (server, client, UA).
func (s *Service) shutdownSIPStack() {
	if s.sipServer != nil {
		_ = s.sipServer.Close()
		s.sipServer = nil
	}
	if s.sipClient != nil {
		_ = s.sipClient.Close()
		s.sipClient = nil
	}
	if s.sipUA != nil {
		_ = s.sipUA.Close()
		s.sipUA = nil
	}
}

// newContactUserUUID generates a random RFC 4122 UUID for the SIP Contact
// header user part. This is the imscore-owned version of
// voiceclient.newContactUserUUID.
func newContactUserUUID() string {
	return voiceclient.NewSIPInstanceURN()
}
