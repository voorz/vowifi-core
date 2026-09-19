package imscore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
)

// subscribeRegTimeout is the maximum time to wait for the SUBSCRIBE 200 OK.
const subscribeRegTimeout = 12 * time.Second

// subscribeRegExpires is the default Expires for reg event subscription.
const subscribeRegExpires = 3600

// sendSubscribeReg sends a SUBSCRIBE(reg) request to establish a reg event
// subscription with the P-CSCF. This keeps the P-CSCF session context alive,
// preventing premature TCP connection teardown.
//
// Per 改动点 2 spec:
//   - Request-URI: home domain (e.g. sip:ims.mnc033.mcc234.3gppnetwork.org)
//   - Event: reg
//   - Expires: 3600 (or from config)
//   - Security-Verify: inherited from IMS registration
//   - Call-ID: independent from REGISTER (separate dialog)
//
// After SUBSCRIBE succeeds, the P-CSCF sends an initial NOTIFY with the
// current registration state. The NOTIFY is handled by the sipgo Server's
// OnRequest handler, which auto-replies 200 OK.
func (s *Service) sendSubscribeReg(ctx context.Context) error {
	if s.sipClient == nil {
		return fmt.Errorf("imscore: SIP client unavailable for SUBSCRIBE")
	}

	sipClient := s.sipClient

	req, err := s.buildSubscribeRegRequest()
	if err != nil {
		return fmt.Errorf("build SUBSCRIBE(reg): %w", err)
	}

	// Log the full SUBSCRIBE request for debugging 500 errors.
	logger.Debug(fmt.Sprintf("[%s] IMS SUBSCRIBE(reg) 完整请求", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("sip_message", req.String()))

	txCtx, cancel := context.WithTimeout(ctx, subscribeRegTimeout)
	defer cancel()

	tx, err := sipClient.TransactionRequest(txCtx, req)
	if err != nil {
		return fmt.Errorf("send SUBSCRIBE(reg): %w", err)
	}
	defer tx.Terminate()

	callID := ""
	if c := req.CallID(); c != nil {
		callID = strings.TrimSpace(c.Value())
	}

	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return fmt.Errorf("SUBSCRIBE(reg) transaction ended: %w", err)
		}
		return fmt.Errorf("SUBSCRIBE(reg) transaction ended without response")
	case res := <-tx.Responses():
		// Log the full response for debugging.
		logger.Debug(fmt.Sprintf("[%s] IMS SUBSCRIBE(reg) 完整响应", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("status", res.StatusCode),
			logger.String("reason", res.Reason),
			logger.String("sip_message", res.String()))

		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("SUBSCRIBE(reg) rejected: %d %s", res.StatusCode, res.Reason)
		}

		// Extract dialog info from the 200 OK (To-Tag for dialog correlation).
		toTag := ""
		if to := res.To(); to != nil {
			if tag, ok := to.Params.Get("tag"); ok {
				toTag = strings.TrimSpace(tag)
			}
		}

		logger.Info(fmt.Sprintf("[%s] IMS SUBSCRIBE(reg) 成功", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("call_id", callID),
			logger.Int("code", res.StatusCode),
			logger.String("to_tag", toTag),
			logger.Int("expires", subscribeRegExpires))

		// Store dialog info for potential SUBSCRIBE refresh.
		s.subscribeDialog = subscribeDialogInfo{
			callID: callID,
			toTag:  toTag,
		}
		return nil
	case <-txCtx.Done():
		return txCtx.Err()
	}
}

// buildSubscribeRegRequest constructs the SUBSCRIBE(reg) SIP request.
func (s *Service) buildSubscribeRegRequest() (*sip.Request, error) {
	// Request-URI: use PublicURI (IMPU) as AOR, matching community version.
	// S-CSCF needs the user part to resolve the subscriber via Cx interface.
	// Using bare domain causes "500 Cx Unable To Comply".
	publicURI := strings.TrimSpace(s.cfg.PublicURI)
	if publicURI == "" {
		return nil, fmt.Errorf("public URI (IMPU) is empty")
	}

	// Log domain source for debugging (matches community closed-source log line 121).
	logger.Debug(fmt.Sprintf("[%s] IMS SUBSCRIBE 域名来源", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("cfg_realm", strings.TrimSpace(s.cfg.Realm)),
		logger.String("auth_realm", ""),
		logger.String("public_uri", publicURI))

	// Build the SUBSCRIBE request via imscore's newRequest.
	// This ensures Security-Verify, Supported, Allow, and other headers are set.
	req, err := s.newRequest(sip.SUBSCRIBE, publicURI, false)
	if err != nil {
		return nil, err
	}

	// Event: reg
	req.AppendHeader(sip.NewHeader("Event", "reg"))

	// Expires: 3600 (or from config)
	expires := subscribeRegExpires
	if s.cfg.RegisterExpirySeconds > 0 {
		expires = s.cfg.RegisterExpirySeconds
	}
	req.AppendHeader(sip.NewHeader("Expires", fmt.Sprintf("%d", expires)))

	// P-Preferred-Identity
	if identity := strings.TrimSpace(s.cfg.PublicURI); identity != "" {
		// newRequest may already add P-Preferred-Identity for non-REGISTER,
		// but SUBSCRIBE needs it to identify the subscriber.
		if req.GetHeader("P-Preferred-Identity") == nil {
			req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+identity+">"))
		}
	}

	// Accept: application/reginfo+xml (for NOTIFY bodies)
	req.AppendHeader(sip.NewHeader("Accept", "application/reginfo+xml"))

	return req, nil
}

// subscribeDialogInfo stores the dialog identifiers from the SUBSCRIBE 200 OK,
// used for potential SUBSCRIBE refresh within the same dialog.
type subscribeDialogInfo struct {
	callID string
	toTag  string
}

// handleInboundNOTIFY processes inbound NOTIFY requests for the reg event
// package. It logs the NOTIFY and replies 200 OK, keeping the subscription
// active. The NOTIFY body (reginfo XML) is not parsed — we only need to
// acknowledge it to prevent retransmission.
func (s *Service) handleInboundNOTIFY(ctx context.Context, req *sip.Request, tx sip.ServerTransaction) {
	event := ""
	if e := req.GetHeader("Event"); e != nil {
		event = strings.TrimSpace(e.Value())
	}
	contentType := ""
	if ct := req.GetHeader("Content-Type"); ct != nil {
		contentType = strings.TrimSpace(ct.Value())
	}
	callID := ""
	if c := req.CallID(); c != nil {
		callID = strings.TrimSpace(c.Value())
	}

	logger.Debug(fmt.Sprintf("[%s] IMS NOTIFY received", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("call_id", callID),
		logger.String("event", event),
		logger.String("ct", contentType),
		logger.Int("len", len(req.Body())))

	// Reply 200 OK to acknowledge the NOTIFY.
	_ = tx.Respond(sip.NewResponseFromRequest(req, 200, "OK", nil))
}
