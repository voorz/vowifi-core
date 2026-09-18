package voiceclient

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// refreshInterval returns the REGISTER refresh interval = expires * 80%.
// Per 改动点 3 spec: this takes priority over TCPKeepaliveSeconds.
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
// Called by AttachSecureMessaging when the client is attached to an
// already-registered IMS session (imscore path).
//
// The loop sends a protected REGISTER at intervals of expires * 80%,
// keeping the TCP connection alive and the P-CSCF session active.
// The loop exits when stopCh is closed.
//
// Per 3GPP TS 33.203, the protected REGISTER is sent over the already-
// established IPSec security association. The S-CSCF identifies the UE
// via the SPI/port mapping — no Authorization header or integrity-protected
// directive is needed (that is inserted by the P-CSCF, not the UE).
func (c *Client) startRefreshLoop(expires time.Duration) {
	interval := refreshInterval(expires)

	nextRefresh := interval
	logger.Info(fmt.Sprintf("[%s] IMS REGISTER refresh 循环已启动", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("next_refresh_in", nextRefresh.String()),
		logger.Int("expires_seconds", int(expires.Seconds())))

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), registerTransactionTimeout)
				if err := c.SendRegisterRefresh(ctx); err != nil {
					logger.Warn(fmt.Sprintf("[%s] IMS REGISTER refresh 失败", strings.TrimSpace(c.cfg.DeviceID)),
						logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
						logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
						logger.String("error", err.Error()))
				} else {
					logger.Debug(fmt.Sprintf("[%s] IMS REGISTER refresh 成功", strings.TrimSpace(c.cfg.DeviceID)),
						logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
						logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
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
//
// Per 改动点 3 spec, this is a best-effort refresh: failure is logged but
// does not tear down the session. The next tick will retry.
// If the S-CSCF returns 401/407 (challenge), the refresh is skipped — a
// full re-registration via the imscore pipeline is needed for that.
func (c *Client) SendRegisterRefresh(ctx context.Context) error {
	if c.client == nil {
		return fmt.Errorf("voiceclient: SIP client unavailable")
	}

	req, err := c.buildRefreshRegister()
	if err != nil {
		return fmt.Errorf("build refresh REGISTER: %w", err)
	}

	res, err := c.doRegisterTransaction(ctx, req, sipgo.ClientRequestRegisterBuild)
	if err != nil {
		return fmt.Errorf("send refresh REGISTER: %w", err)
	}

	if res.StatusCode == 401 || res.StatusCode == 407 {
		// S-CSCF issued a challenge — the security association may have expired.
		// A full re-registration via the imscore pipeline is needed; log and skip.
		logger.Warn(fmt.Sprintf("[%s] IMS REGISTER refresh 收到挑战，需要重新注册", strings.TrimSpace(c.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
			logger.Int("status", res.StatusCode))
		return fmt.Errorf("refresh REGISTER challenged: %d (re-registration needed)", res.StatusCode)
	}
	if res.StatusCode != 200 {
		return fmt.Errorf("refresh REGISTER rejected: %d %s", res.StatusCode, res.Reason)
	}

	// Update Service-Route headers if the server provides new ones.
	c.updateServiceRoutesFromResponse(res)

	logger.Info(fmt.Sprintf("[%s] IMS REGISTER refresh 成功", strings.TrimSpace(c.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(c.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(c.cfg.DeviceID)),
		logger.Int("status", res.StatusCode))
	return nil
}

// buildRefreshRegister constructs a protected REGISTER request for refresh.
// Per 3GPP TS 33.203 and the register_session_test.go assertion, the UE
// must NOT include integrity-protected= in the Authorization header —
// the P-CSCF inserts that. The UE sends a clean REGISTER over the
// already-secured IPSec channel; the S-CSCF identifies the UE via the
// security association (SPI/port mapping).
func (c *Client) buildRefreshRegister() (*sip.Request, error) {
	// Build a REGISTER with initialRegister=false (no initial Authorization).
	req, err := c.newRequest(sip.REGISTER, c.cfg.PCSCFAddr, false)
	if err != nil {
		return nil, err
	}
	return req, nil
}

// updateServiceRoutesFromResponse updates Service-Route headers from a
// refresh REGISTER 200 OK response, matching the behavior of the initial
// registration flow.
func (c *Client) updateServiceRoutesFromResponse(res *sip.Response) {
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
		c.cfg.ServiceRoutes = newRoutes
	}
}
