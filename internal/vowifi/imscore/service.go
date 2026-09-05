package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/voorz/vowifi-core/internal/vowifi/policy"
	"github.com/voorz/sipgo"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// Service is the RE-recovered imscore IMS messaging surface.
type Service struct {
	imsCfg IMSConfig
	cfg    Config
	mu     sync.Mutex

	registered      bool
	expiresSeconds  int
	verifyHeader    string
	sipSecurityMode string
	ipsecInstalled  bool
	pcscf           string
	localAddr       string
	started         bool

	network          IMSNetwork
	transportRuntime *transportRuntime
	swu              voiceclient.SWUTCPDialer
	portSListener    net.Listener
	portSUDP         net.PacketConn

	lifecycleCtx    context.Context
	lifecycleCancel context.CancelFunc

	inner *voiceclient.Client

	msgSvc    *messaging.Service
	sipServer *sipgo.Server

	progressCb func(RegisterProgress)
}

// Dial is a compatibility wrapper around StartSessionIMSCore for legacy callers.
func Dial(ctx context.Context, cfg Config) (*Service, error) {
	if cfg.AKA == nil {
		return nil, fmt.Errorf("imscore: Config.AKA is required")
	}
	if cfg.LocalIP == nil {
		return nil, fmt.Errorf("imscore: Config.LocalIP is required")
	}
	if strings.TrimSpace(cfg.PCSCFAddr) == "" {
		return nil, fmt.Errorf("imscore: Config.PCSCFAddr is required")
	}
	if strings.TrimSpace(cfg.PrivateID) == "" || strings.TrimSpace(cfg.PublicURI) == "" {
		return nil, fmt.Errorf("imscore: IMS identity is required")
	}

	voiceCfg := voiceclient.Config{
		DeviceID:            cfg.DeviceID,
		TraceID:             cfg.TraceID,
		LocalIP:             cfg.LocalIP,
		Dataplane:           cfg.Dataplane,
		PCSCFAddr:           cfg.PCSCFAddr,
		RegistrarCandidates: cfg.RegistrarCandidates,
		Realm:               cfg.Realm,
		PrivateID:           cfg.PrivateID,
		PublicURI:           cfg.PublicURI,
		HomeDomain:          cfg.HomeDomain,
		IMSI:                cfg.IMSI,
		MCC:                 cfg.MCC,
		MNC:                 cfg.MNC,
		CellID:              cfg.CellID,
		AKA:                 cfg.AKA,
		DeliveryStore:       cfg.DeliveryStore,
		SIPInstanceURN:      cfg.SIPInstanceURN,
		RegisterProfile:     voiceclient.RegisterProfile{UserAgent: cfg.UserAgent},
	}
	if cfg.RegisterExpirySeconds > 0 {
		voiceCfg.RegisterExpiry = time.Duration(cfg.RegisterExpirySeconds) * time.Second
	}

	network, err := NewUserspaceIMSNetwork(cfg.LocalIP, cfg.Dataplane, cfg.TraceID, cfg.DeviceID)
	if err != nil {
		return nil, err
	}
	imsCfg := IMSConfigFromVoice(voiceCfg, cfg.Template, "")
	return StartSessionIMSCore(ctx, imsCfg, network, StartSessionInput{
		TraceID:               cfg.TraceID,
		LocalIP:               cfg.LocalIP,
		Dataplane:             cfg.Dataplane,
		RegistrarCandidates:   cfg.RegistrarCandidates,
		AKA:                   cfg.AKA,
		EAPRand:               cfg.EAPRand,
		EAPAutn:               cfg.EAPAutn,
		EAPRES:                cfg.EAPRES,
		EAPCK:                 cfg.EAPCK,
		EAPIK:                 cfg.EAPIK,
		DeliveryStore:         cfg.DeliveryStore,
		IMSI:                  cfg.IMSI,
		MCC:                   cfg.MCC,
		MNC:                   cfg.MNC,
		CellID:                cfg.CellID,
		RegisterExpirySeconds: cfg.RegisterExpirySeconds,
	})
}

func (s *Service) SendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if s == nil || s.inner == nil {
		return messaging.SendOutcome{}, fmt.Errorf("IMS service not ready")
	}
	return s.inner.SendSMS(ctx, peer, content, parts)
}

// VoiceClient returns the underlying voiceclient.Client created during
// attachMessaging. Returns nil if IMS has not been registered yet.
// Used by runtimehost.runStagedPipeline to wire OnIMSReady callback
// for VoWiFi voice agent setup.
func (s *Service) VoiceClient() *voiceclient.Client {
	if s == nil {
		return nil
	}
	return s.inner
}

// SetInboundCallHandler sets the callback invoked when an inbound IMS
// INVITE arrives (an incoming VoWiFi call). The handler returns the
// final status code, reason phrase, and SDP body to send as the SIP
// response. The respond function lets the handler send provisional
// responses (e.g. 180 Ringing) before returning the final response.
// Uses primitive types to avoid a circular dependency on
// runtimehost.InboundCallRequest.
func (s *Service) SetInboundCallHandler(f func(ctx context.Context, deviceID, callID, callerURI, calleeURI string, remoteSDP []byte, respond func(int, string, []byte) error) (int, string, []byte, error)) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.OnInboundCall = f
	s.mu.Unlock()
}

// SetInboundByeHandler sets the callback invoked when an inbound IMS BYE
// arrives (the remote party hangs up an established call). The caller
// should forward the BYE to Linphone and clean up any call resources.
func (s *Service) SetInboundByeHandler(f func(ctx context.Context, deviceID, callID string) error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.OnInboundBye = f
	s.mu.Unlock()
}

// SetInboundCancelHandler sets the callback invoked when an inbound IMS
// CANCEL arrives (the remote party cancels a ringing call). The caller
// should forward the CANCEL to Linphone and clean up any call resources.
func (s *Service) SetInboundCancelHandler(f func(ctx context.Context, deviceID, callID string) error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.cfg.OnInboundCancel = f
	s.mu.Unlock()
}

// SendSMSWithOptions delegates to msgSvc, which handles TPDU encoding and event dispatch.
// This replaces the pre-encode bridge in vohive-next with a standard messaging path.
func (s *Service) SendSMSWithOptions(ctx context.Context, to, text string, opts messaging.SendOptions) (messaging.SendOutcome, error) {
	if s == nil || s.msgSvc == nil {
		return messaging.SendOutcome{}, fmt.Errorf("IMS service not ready")
	}
	return s.msgSvc.SendSMSWithOptions(ctx, to, text, opts)
}

func (s *Service) SendUSSD(ctx context.Context, command string) (*messaging.USSDResult, error) {
	if s == nil || s.msgSvc == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	return s.msgSvc.SendUSSD(ctx, command)
}

func (s *Service) ContinueUSSD(ctx context.Context, sessionID, input string) (*messaging.USSDResult, error) {
	if s == nil || s.msgSvc == nil {
		return nil, fmt.Errorf("IMS service not ready")
	}
	return s.msgSvc.ContinueUSSD(ctx, sessionID, input)
}

func (s *Service) CancelUSSD(ctx context.Context, sessionID string) error {
	if s == nil || s.msgSvc == nil {
		return fmt.Errorf("IMS service not ready")
	}
	return s.msgSvc.CancelUSSD(ctx, sessionID)
}

func (s *Service) Close(ctx context.Context) error {
	if s == nil {
		return nil
	}
	if s.lifecycleCancel != nil {
		s.lifecycleCancel()
		s.lifecycleCancel = nil
	}
	if s.transportRuntime != nil {
		s.transportRuntime.Close()
		s.transportRuntime = nil
	}
	if s.sipServer != nil {
		_ = s.sipServer.Close()
		s.sipServer = nil
	}
	if s.portSListener != nil {
		_ = s.portSListener.Close()
		s.portSListener = nil
	}
	if s.portSUDP != nil {
		_ = s.portSUDP.Close()
		s.portSUDP = nil
	}
	var innerErr error
	if s.inner != nil {
		innerErr = s.inner.Close(ctx)
		s.inner = nil
	}
	if us, ok := s.network.(*UserspaceIMSNetwork); ok {
		_ = us.Close()
	} else if s.swu != nil {
		_ = s.swu.Close()
	}
	s.swu = nil
	return innerErr
}

func (s *Service) Status() map[string]interface{} {
	if s == nil {
		return map[string]interface{}{"enabled": false}
	}
	return map[string]interface{}{
		"enabled":            true,
		"device_id":          s.cfg.DeviceID,
		"registered":         s.registered,
		"reg_status":         "registered",
		"registrar":          s.pcscf,
		"local_addr":         s.localAddr,
		"sip_security_mode":  s.sipSecurityMode,
		"trace_id":           s.cfg.TraceID,
		"signaling_ready":    s.registered,
		"ipsec_installed":    s.ipsecInstalled,
		"effective_security": securityModeLabel(s.ipsecInstalled),
		"register_template":  s.imsCfg.IMSRegisterTemplate.ID,
		"preset_id":          s.imsCfg.CarrierPresetID,
		"verify":             s.verifyHeader,
		"expires_seconds":    s.expiresSeconds,
	}
}

func securityModeLabel(ipsec bool) string {
	if ipsec {
		return "ipsec3gpp"
	}
	return "plain"
}

// ConfigFromVoice builds imscore.Config from an established runtimehost voiceclient.Config.
func ConfigFromVoice(v voiceclient.Config, template policy.IMSRegisterTemplate) Config {
	return Config{
		DeviceID:              v.DeviceID,
		TraceID:               v.TraceID,
		LocalIP:               v.LocalIP,
		Dataplane:             v.Dataplane,
		PCSCFAddr:             v.PCSCFAddr,
		RegistrarCandidates:   v.RegistrarCandidates,
		Realm:                 v.Realm,
		PrivateID:             v.PrivateID,
		PublicURI:             v.PublicURI,
		HomeDomain:            v.HomeDomain,
		IMSI:                  v.IMSI,
		SMSC:                  v.SMSC,
		AKA:                   v.AKA,
		Template:              template,
		MCC:                   v.MCC,
		MNC:                   v.MNC,
		CellID:                v.CellID,
		SIPInstanceURN:        v.SIPInstanceURN,
		UserAgent:             v.RegisterProfile.UserAgent,
		RegisterExpirySeconds: int(v.RegisterExpiry / time.Second),
		DeliveryStore:         v.DeliveryStore,
	}
}

// ParsePCSCFHostPort splits a P-CSCF address for logging and policy setup.
func ParsePCSCFHostPort(addr string) (net.IP, int, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, 0, err
	}
	port, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return nil, 0, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("invalid P-CSCF host %q", host)
	}
	return ip, port, nil
}
