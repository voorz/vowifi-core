package imscore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// refreshInterval returns the REGISTER refresh interval = expires * 80%.
func refreshInterval(expires time.Duration) time.Duration {
	if expires <= 0 {
		expires = 3600 * time.Second
	}
	interval := expires * 4 / 5
	if interval < 30*time.Second {
		interval = 30 * time.Second
	}
	return interval
}

// startRefreshLoop starts a background REGISTER refresh loop.
// The loop sends a protected REGISTER at intervals of expires * 80%,
// keeping the TCP connection alive and the P-CSCF session active.
// The loop exits when stopCh is closed.
//
// This is the imscore-owned version of voiceclient.Client.startRefreshLoop.
func (s *Service) startRefreshLoop(expires time.Duration) {
	interval := refreshInterval(expires)

	logger.Info(fmt.Sprintf("[%s] IMS REGISTER refresh 循环已启动", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("next_refresh_in", interval.String()),
		logger.Int("expires_seconds", int(expires.Seconds())))

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), registerTransactionTimeout)
				if err := s.SendRegisterRefresh(ctx); err != nil {
					logger.Warn(fmt.Sprintf("[%s] IMS REGISTER refresh 失败", strings.TrimSpace(s.cfg.DeviceID)),
						logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
						logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
						logger.String("error", err.Error()))
				} else {
					logger.Debug(fmt.Sprintf("[%s] IMS REGISTER refresh 成功", strings.TrimSpace(s.cfg.DeviceID)),
						logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
						logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
						logger.String("next_refresh_in", interval.String()))
				}
				cancel()
			}
		}
	}()
}

// SendRegisterRefresh sends a protected REGISTER refresh to keep the IMS
// registration and TCP connection alive.
//
// The refresh REGISTER:
//   - No Authorization header (UE does not set integrity-protected; the
//     P-CSCF adds it per 3GPP TS 33.203)
//   - Security-Verify: inherited from the initial registration
//   - Expires: same as the initial registration
//   - Routed through the P-CSCF over the established TCP+IPSec channel
func (s *Service) SendRegisterRefresh(ctx context.Context) error {
	if s.sipClient == nil {
		return fmt.Errorf("imscore: SIP client unavailable")
	}

	req, err := s.buildRefreshRegister()
	if err != nil {
		return fmt.Errorf("build refresh REGISTER: %w", err)
	}

	res, err := s.doRegisterTransaction(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		return fmt.Errorf("send refresh REGISTER: %w", err)
	}

	if res.StatusCode == 401 || res.StatusCode == 407 {
		logger.Warn(fmt.Sprintf("[%s] IMS REGISTER refresh 收到挑战，需要重新注册", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.Int("status", res.StatusCode))
		return fmt.Errorf("refresh REGISTER challenged: %d (re-registration needed)", res.StatusCode)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("refresh REGISTER rejected: %d %s", res.StatusCode, res.Reason)
	}

	// Update Service-Route headers if the server provides new ones.
	s.updateServiceRoutesFromResponse(res)

	logger.Info(fmt.Sprintf("[%s] IMS REGISTER refresh 成功", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.Int("status", res.StatusCode))
	return nil
}

// buildRefreshRegister constructs a protected REGISTER request for refresh.
// Uses buildRegisterRequest (the same path as initial registration) to ensure
// a single REGISTER construction pipeline. The refresh REGISTER carries
// Security-Verify (inherited from initial registration) but no Authorization
// and no Security-Client (IPsec SA already established).
func (s *Service) buildRefreshRegister() (*sip.Request, error) {
	state := registerState{
		spiC:          s.securityClient.spiC,
		spiS:          s.securityClient.spiS,
		portC:         int(s.securityClient.portC),
		portS:         int(s.securityClient.portS),
		transportMode: s.transportNetwork(),
		sipInstance:   strings.TrimSpace(s.sipInstanceURN),
		verifyHeader:  strings.TrimSpace(s.verifyHeader),
	}
	req, err := buildRegisterRequest(s.cfg, state, false, initialRegisterVariant{})
	if err != nil {
		return nil, err
	}
	// decorateRegisterRequest handles Via, Call-ID, CSeq, Max-Forwards, Contact.
	// Use Service-owned values for these fields.
	req.RemoveHeader("Via")
	req.RemoveHeader("Call-ID")
	req.RemoveHeader("CSeq")
	req.RemoveHeader("Max-Forwards")
	transport := s.transportNetwork()
	localPort := s.imsCfg.LocalPort
	if localPort <= 0 {
		localPort = 5060
	}
	viaHost := formatRegisterViaHost(s.cfg.LocalIP, localPort)
	via := fmt.Sprintf("SIP/2.0/%s %s;branch=%s;rport", strings.ToUpper(transport), viaHost, sip.GenerateBranchN(16))
	req.PrependHeader(sip.NewHeader("Via", via))
	req.AppendHeader(sip.NewHeader("Call-ID", uuid.NewString()))
	cseq := nextRegisterTransportAttemptCSeq(0)
	req.AppendHeader(sip.NewHeader("CSeq", fmt.Sprintf("%d REGISTER", cseq)))
	req.AppendHeader(sip.NewHeader("Max-Forwards", "70"))
	req.SetTransport(strings.ToUpper(transport))
	return req, nil
}

// updateServiceRoutesFromResponse updates Service-Route headers from a
// refresh REGISTER 200 OK response.
func (s *Service) updateServiceRoutesFromResponse(res *sip.Response) {
	routes := res.GetHeaders("Service-Route")
	if len(routes) == 0 {
		return
	}
	newRoutes := make([]string, 0, len(routes))
	for _, h := range routes {
		if v := strings.TrimSpace(h.Value()); v != "" {
			newRoutes = append(newRoutes, v)
		}
	}
	if len(newRoutes) > 0 {
		s.serviceRoutes = newRoutes
	}
}
