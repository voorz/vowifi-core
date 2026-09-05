package imscore

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/voorz/swu-go/pkg/logger"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/vowifi-core/internal/vowifi/ipsec3gpp"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// Start runs the full IMS Core lifecycle: REGISTER FSM, ipsec transport runtime,
// TCP write scheduler, and post-register messaging attach.
func (s *Service) Start(ctx context.Context) error {
	if s == nil {
		return fmt.Errorf("imscore: service is nil")
	}
	if s.cfg.AKA == nil {
		return fmt.Errorf("imscore: Config.AKA is required")
	}
	if s.cfg.LocalIP == nil {
		return fmt.Errorf("imscore: Config.LocalIP is required")
	}

	addr := strings.TrimSpace(s.imsCfg.Registrar)
	if addr == "" {
		addr = strings.TrimSpace(s.cfg.PCSCFAddr)
	}
	logger.Info(fmt.Sprintf("[%s] IMS Core 正在启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("addr", addr),
		logger.String("transport", strings.TrimSpace(s.imsCfg.Transport)),
		logger.String("preset_id", strings.TrimSpace(s.imsCfg.CarrierPresetID)),
		logger.String("register_template", strings.TrimSpace(s.imsCfg.IMSRegisterTemplate.ID)),
		logger.String("register_policy", registerPolicyID(s.imsCfg.IMSRegisterTemplate)),
		logger.String("register_policy_source", strings.TrimSpace(s.imsCfg.IMSRegisterPolicySource)))

	swu, err := s.resolveSWUDialer()
	if err != nil {
		return err
	}
	s.swu = swu

	lifecycleCtx, cancel := context.WithCancel(ctx)
	s.lifecycleCtx = lifecycleCtx
	s.lifecycleCancel = cancel

	registerCtx, registerCancel := context.WithTimeout(lifecycleCtx, registerDialTimeout)
	defer registerCancel()

	reg, err := s.runRegisterFlow(registerCtx)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] IMS 注册失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("pcscf", s.cfg.PCSCFAddr),
			logger.Int("registrar_candidates", len(s.cfg.RegistrarCandidates)),
			logger.String("error", err.Error()))
		return fmt.Errorf("register: %w", err)
	}

	winningPCSCF := strings.TrimSpace(reg.pcscfAddr)
	if winningPCSCF == "" {
		winningPCSCF = s.cfg.PCSCFAddr
	}
	s.cfg.PCSCFAddr = winningPCSCF
	s.imsCfg.Registrar = winningPCSCF
	s.imsCfg.PCSCF = winningPCSCF

	s.registered = true
	s.expiresSeconds = reg.expiresSeconds
	s.verifyHeader = reg.verifyHeader
	s.sipSecurityMode = "ipsec3gpp"
	s.ipsecInstalled = reg.secureConn != nil || reg.tcpConn != nil
	s.pcscf = winningPCSCF
	s.localAddr = s.cfg.LocalIP.String()

	// Create messaging.Service for inbound SMS handling.
	s.msgSvc = messaging.NewService(s.cfg.DeviceID, s.cfg.IMSI, s.cfg.DeliveryStore, s.cfg.Dispatcher)

	if reg.secureConn != nil && reg.transport != nil && !reg.secureConn.PacketMode() {
		rt, err := startTransportRuntime(lifecycleCtx, s.cfg, swu, reg.ipsecPolicy, reg.transport, reg.secureConn)
		if err != nil {
			logger.Warn(fmt.Sprintf("[%s] IMS 传输运行时启动失败", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("error", err.Error()))
		} else {
			s.transportRuntime = rt
			s.logTCPWriterLoop(lifecycleCtx, reg.secureConn)
			s.startInboundSIPServer(lifecycleCtx, rt.portSListener, nil)
			s.notifySMSCapability()
		}
	} else if reg.tcpConn != nil {
		// TCP+ESP mode: ESP handled by netstack transparently.
		// Start TCP writer log, port_s inbound listeners, and SMS notification.
		s.logTCPWriterLoop(lifecycleCtx, reg.tcpConn)
		if reg.ipsecPolicy.LocalPortS > 0 {
			if err := s.startPortSListeners(lifecycleCtx, swu, reg.ipsecPolicy); err != nil {
				logger.Warn(fmt.Sprintf("[%s] IMS port_s 入站监听启动失败", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("error", err.Error()))
			}
		}
		s.startInboundSIPServer(lifecycleCtx, s.portSListener, s.portSUDP)
		s.notifySMSCapability()
	}

	if err := s.attachMessaging(lifecycleCtx, winningPCSCF, reg); err != nil {
		return err
	}
	s.started = true
	return nil
}

func (s *Service) resolveSWUDialer() (voiceclient.SWUTCPDialer, error) {
	if s == nil {
		return nil, fmt.Errorf("imscore: service is nil")
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok && us != nil {
		if dialer := us.SWUDialer(); dialer != nil {
			return dialer, nil
		}
	}
	return newSWUNetstack(s.cfg.LocalIP, s.cfg.Dataplane, s.cfg.TraceID, s.cfg.DeviceID)
}

func (s *Service) logTCPWriterLoop(ctx context.Context, conn net.Conn) {
	if s == nil || conn == nil {
		return
	}
	local := ""
	if conn.LocalAddr() != nil {
		local = conn.LocalAddr().String()
	}
	logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("local", local))

	go func() {
		<-ctx.Done()
		logger.Info(fmt.Sprintf("[%s] TCP 专用写通道调度器已退出", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("local", local))
	}()
}

// startPortSListeners starts TCP and UDP listeners on port_s for inbound SIP
// messages. In TCP+ESP mode, the netstack's ESP transformer decrypts inbound
// ESP packets transparently, so these listeners receive plain SIP messages.
func (s *Service) startPortSListeners(ctx context.Context, swu voiceclient.SWUTCPDialer, policy ipsec3gpp.Policy) error {
	if swu == nil || policy.LocalPortS <= 0 {
		return fmt.Errorf("imscore: port_s listener requires SWu dialer and valid port_s")
	}

	// TCP listener on port_s
	tcpLn, err := swu.ListenContextTCP(ctx, s.cfg.LocalIP, policy.LocalPortS)
	if err != nil {
		return fmt.Errorf("port_s TCP listen: %w", err)
	}
	s.portSListener = tcpLn
	logger.Info(fmt.Sprintf("[%s] 准备启动 IMS TCP 入站监听", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.Int("port", policy.LocalPortS))
	go s.drainPortSTCP(ctx, tcpLn)

	// UDP listener on port_s
	udpConn, err := swu.ListenContextUDP(ctx, s.cfg.LocalIP, policy.LocalPortS)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] IMS port_s UDP 监听失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.Int("port_s", policy.LocalPortS),
			logger.String("error", err.Error()))
	} else {
		s.portSUDP = udpConn
		logger.Info(fmt.Sprintf("[%s] IMS Core IPSec3GPP 模式启用 UDP 接收器", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("transport", "udp"),
			logger.Int("port", policy.LocalPortS))
		go s.drainPortSUDP(ctx, udpConn)
	}

	return nil
}

func (s *Service) drainPortSTCP(ctx context.Context, ln net.Listener) {
	// Replaced by startInboundSIPServer — sipgo Server handles inbound SIP.
	_ = ctx
	_ = ln
}

func (s *Service) drainPortSUDP(ctx context.Context, conn net.PacketConn) {
	// Replaced by startInboundSIPServer — sipgo Server handles inbound SIP.
	_ = ctx
	_ = conn
}

// startInboundSIPServer creates a sipgo Server that listens on port_s for
// inbound SIP MESSAGE requests (SMS delivery reports, incoming SMS).
// The server uses the SWu TCP/UDP listener directly — connections accepted
// by the SWu listener are processed by sipgo's transport layer, which parses
// SIP messages and dispatches them to the OnMessage handler.
func (s *Service) startInboundSIPServer(ctx context.Context, tcpLn net.Listener, udpConn net.PacketConn) {
	if s.msgSvc == nil {
		return
	}
	deviceLogger := slog.New(logger.NewSlogHandler(logger.Get())).With(
		"device_id", strings.TrimSpace(s.cfg.DeviceID),
		"trace_id", strings.TrimSpace(s.cfg.TraceID),
	)
	ua, err := sipgo.NewUA(
		sipgo.WithUserAgent(s.cfg.UserAgent),
		sipgo.WithUserAgentTransportLayerOptions(
			sip.WithTransportLayerLogger(deviceLogger),
		),
		sipgo.WithUserAgentTransactionLayerOptions(
			sip.WithTransactionLayerLogger(deviceLogger),
		),
	)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] 入站 SIP Server UA 创建失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("error", err.Error()))
		return
	}
	srv, err := sipgo.NewServer(ua)
	if err != nil {
		_ = ua.Close()
		logger.Warn(fmt.Sprintf("[%s] 入站 SIP Server 创建失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("error", err.Error()))
		return
	}
	srv.OnMessage(func(req *sip.Request, tx sip.ServerTransaction) {
		s.handleInboundSIPMessage(ctx, req, tx)
	})
	// VoWiFi inbound voice call handling (V2b/V2c).
	// Phase 1: acknowledge inbound INVITE/BYE/CANCEL so IMS doesn't
	// retransmit indefinitely. Full call forwarding to Linphone will
	// be implemented in a later phase via OnInboundCall callback.
	srv.OnInvite(func(req *sip.Request, tx sip.ServerTransaction) {
		callID := ""
		if c := req.CallID(); c != nil {
			callID = strings.TrimSpace(c.Value())
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 100, "Trying", nil))

		handler := s.cfg.OnInboundCall
		if handler == nil {
			logger.Info(fmt.Sprintf("[%s] IMS 入站 INVITE（无回调，回复 486）", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("call_id", callID))
			_ = tx.Respond(sip.NewResponseFromRequest(req, 486, "Busy Here", nil))
			return
		}

		callerURI := ""
		if from := req.From(); from != nil {
			callerURI = strings.TrimSpace(from.Address.String())
		}
		calleeURI := ""
		if to := req.To(); to != nil {
			calleeURI = strings.TrimSpace(to.Address.String())
		}

		logger.Info(fmt.Sprintf("[%s] IMS 入站 INVITE，转发到回调", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("call_id", callID),
			logger.String("caller", callerURI),
			logger.String("callee", calleeURI))

		// respondFunc allows the handler to send provisional responses
		// (e.g. 180 Ringing) before returning the final response.
		respondFunc := func(statusCode int, reason string, sdp []byte) error {
			return tx.Respond(sip.NewResponseFromRequest(req, statusCode, reason, sdp))
		}

		statusCode, reason, sdp, err := handler(ctx, s.cfg.DeviceID, callID, callerURI, calleeURI, append([]byte(nil), req.Body()...), respondFunc)
		if err != nil {
			logger.Warn(fmt.Sprintf("[%s] IMS 入站 INVITE 回调失败", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("call_id", callID),
				logger.String("error", err.Error()))
			_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Internal Server Error", nil))
			return
		}
		if statusCode < 100 {
			statusCode = 486
		}
		if strings.TrimSpace(reason) == "" {
			reason = "OK"
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, statusCode, reason, sdp))
	})
	srv.OnBye(func(req *sip.Request, tx sip.ServerTransaction) {
		callID := ""
		if c := req.CallID(); c != nil {
			callID = strings.TrimSpace(c.Value())
		}
		if byeHandler := s.cfg.OnInboundBye; byeHandler != nil {
			logger.Info(fmt.Sprintf("[%s] IMS 入站 BYE，转发到回调", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("call_id", callID))
			if err := byeHandler(ctx, s.cfg.DeviceID, callID); err != nil {
				logger.Warn(fmt.Sprintf("[%s] IMS 入站 BYE 回调失败", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.String("call_id", callID),
					logger.String("error", err.Error()))
			}
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	srv.OnCancel(func(req *sip.Request, tx sip.ServerTransaction) {
		callID := ""
		if c := req.CallID(); c != nil {
			callID = strings.TrimSpace(c.Value())
		}
		if cancelHandler := s.cfg.OnInboundCancel; cancelHandler != nil {
			logger.Info(fmt.Sprintf("[%s] IMS 入站 CANCEL，转发到回调", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("call_id", callID))
			if err := cancelHandler(ctx, s.cfg.DeviceID, callID); err != nil {
				logger.Warn(fmt.Sprintf("[%s] IMS 入站 CANCEL 回调失败", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.String("call_id", callID),
					logger.String("error", err.Error()))
			}
		}
		_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
	})
	srv.OnRequest("ACK", func(req *sip.Request, tx sip.ServerTransaction) {
		// ACK has no response in a transactionless model; just absorb it.
	})
	s.sipServer = srv

	if tcpLn != nil {
		go func() {
		if err := srv.ServeTCP(tcpLn); err != nil {
				logger.Warn(fmt.Sprintf("[%s] 入站 SIP Server TCP 退出", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("error", err.Error()))
			}
		}()
	}
	if udpConn != nil {
		go func() {
		if err := srv.ServeUDP(udpConn); err != nil {
				logger.Warn(fmt.Sprintf("[%s] 入站 SIP Server UDP 退出", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
					logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
					logger.String("error", err.Error()))
			}
		}()
	}

	logger.Info(fmt.Sprintf("[%s] 入站 SIP Server 已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.Bool("tcp", tcpLn != nil),
		logger.Bool("udp", udpConn != nil))
}

// handleInboundSIPMessage processes an inbound SIP MESSAGE request: extracts
// the RP-DATA body, calls messaging.Service.HandleIMSMessage for TPdu decode
// and event dispatch, and responds with 200 OK + RP-ACK (or error).
func (s *Service) handleInboundSIPMessage(ctx context.Context, req *sip.Request, tx sip.ServerTransaction) {
	if s.msgSvc == nil {
		_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Messaging service unavailable", nil))
		return
	}

	msgReq := messaging.IMSMessageRequest{
		Body: req.Body(),
	}
	if ct := req.GetHeader("Content-Type"); ct != nil {
		msgReq.ContentType = strings.TrimSpace(ct.Value())
	}
	if from := req.From(); from != nil {
		msgReq.FromURI = from.Address.String()
	}
	if to := req.To(); to != nil {
		msgReq.ToURI = to.Address.String()
	}
	if callID := req.CallID(); callID != nil {
		msgReq.CallID = callID.Value()
	}
	if cseq := req.CSeq(); cseq != nil {
		msgReq.CSeq = int(cseq.SeqNo)
	}
	msgReq.Headers = make(map[string][]string)
	for _, hdr := range req.GetHeaders("") {
		msgReq.Headers[string(hdr.Name())] = append(msgReq.Headers[string(hdr.Name())], hdr.Value())
	}

	result, err := s.msgSvc.HandleIMSMessage(ctx, msgReq)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] 入站 IMS MESSAGE 处理失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("error", err.Error()),
			logger.String("content_type", msgReq.ContentType),
			logger.Int("body_len", len(msgReq.Body)),
			logger.String("body_hex", fmt.Sprintf("%x", msgReq.Body)))
		_ = tx.Respond(sip.NewResponseFromRequest(req, 500, "Internal Error", nil))
		return
	}

	statusCode := result.StatusCode
	if statusCode == 0 {
		statusCode = 200
	}
	reason := result.Reason
	if reason == "" {
		reason = "OK"
	}
	resp := sip.NewResponseFromRequest(req, statusCode, reason, result.ReplyBody)
	if result.ReplyContentType != "" && len(result.ReplyBody) > 0 {
		resp.AppendHeader(sip.NewHeader("Content-Type", result.ReplyContentType))
	}
	if result.Incoming != nil {
		logger.Info(fmt.Sprintf("[%s] 收到 IMS 短信", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("sender", result.Incoming.Sender),
			logger.Int("len", len(result.Incoming.Content)),
			logger.String("transport", "tcp"))
	}
	_ = tx.Respond(resp)
}

func (s *Service) notifySMSCapability() {
	logger.Info(fmt.Sprintf("[%s] IMS SMS 能力已就绪", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("reason", "inbound_transport_ready"),
		logger.Bool("receiver_ready", true),
		logger.Bool("smsc_present", s.cfg.SMSC != ""))
}

// attachMessaging hooks voiceclient for SMS/USSD after imscore registration.
func (s *Service) attachMessaging(ctx context.Context, winningPCSCF string, reg *registerResult) error {
	if reg == nil {
		return fmt.Errorf("voiceclient attach: register result is required")
	}
	// Determine the connection to use for messaging.
	var msgConn net.Conn
	if reg.tcpConn != nil {
		// TCP+ESP mode: use the TCP connection directly.
		msgConn = reg.tcpConn
	} else if reg.secureConn != nil && reg.secureConn.PacketMode() {
		// UDP+ESP mode: use the SecureChannelConn.
		msgConn = reg.secureConn
	} else {
		return fmt.Errorf("voiceclient attach: secure channel unavailable")
	}
	protectedPCSCF := winningPCSCF
	if remoteIP := net.IP(reg.ipsecPolicy.RemoteIP); remoteIP != nil && reg.ipsecPolicy.FlowC.RemotePort > 0 {
		protectedPCSCF = net.JoinHostPort(remoteIP.String(), strconv.Itoa(reg.ipsecPolicy.FlowC.RemotePort))
	}
	localPort := reg.ipsecPolicy.FlowC.LocalPort
	if localPort <= 0 && reg.tcpConn != nil {
		if tcpAddr, ok := reg.tcpConn.LocalAddr().(*net.TCPAddr); ok && tcpAddr != nil {
			localPort = tcpAddr.Port
		}
	}
	voiceCfg := voiceclient.Config{
		DeviceID:        s.cfg.DeviceID,
		TraceID:         s.cfg.TraceID,
		LocalIP:         s.cfg.LocalIP,
		LocalPort:       localPort,
		PCSCFAddr:       protectedPCSCF,
		SecurityVerify:  reg.verifyHeader,
		SMSC:            s.cfg.SMSC,
		ServiceRoutes:   append([]string(nil), reg.serviceRoutes...),
		Realm:           s.cfg.Realm,
		PrivateID:       s.cfg.PrivateID,
		PublicURI:       s.cfg.PublicURI,
		HomeDomain:      s.cfg.HomeDomain,
		IMSI:            s.cfg.IMSI,
		Transport:       "tcp",
		MCC:             s.cfg.MCC,
		MNC:             s.cfg.MNC,
		CellID:          s.cfg.CellID,
		AKA:             s.cfg.AKA,
		DeliveryStore:   s.cfg.DeliveryStore,
		SIPInstanceURN:  s.cfg.SIPInstanceURN,
		RegisterProfile: voiceclient.SimAdminGBEERegisterProfile(),
		SkipRegister:    true,
	}
	if s.cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(s.cfg.RegisterExpirySeconds) * time.Second
	}
	logger.Info(fmt.Sprintf("[%s] IMS attachMessaging 开始", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("transport", voiceCfg.Transport),
		logger.String("pcscf", protectedPCSCF),
		logger.Bool("tcp_conn", msgConn != nil))
	inner, err := voiceclient.AttachSecureMessaging(ctx, voiceCfg, msgConn)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] IMS attachMessaging 失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("error", err.Error()))
		return fmt.Errorf("voiceclient attach: %w", err)
	}
	s.inner = inner
	s.msgSvc.SetSMSTransport(inner)
	s.msgSvc.SetUSSDTransport(voiceclient.NewUSSDTransport(inner))
	logger.Info(fmt.Sprintf("[%s] IMS attachMessaging 成功", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)))
	return nil
}

// Stop tears down the IMS Core lifecycle.
func (s *Service) Stop(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
	}
	return s.Close(ctx)
}
