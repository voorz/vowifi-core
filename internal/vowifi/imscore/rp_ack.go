package imscore

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"

	"github.com/voorz/vowifi-core/runtimehost/messaging"
)

// rpAckTimeout is the maximum time to wait for the RP-ACK MESSAGE 200 OK response.
const rpAckTimeout = 10 * time.Second

// rpAckMaxRetries is the maximum number of retry attempts for sending RP-ACK.
const rpAckMaxRetries = 2

// sendRPAckMessage constructs and sends an independent SIP MESSAGE carrying
// the RP-ACK PDU, as specified in 改动点 4. The RP-ACK MESSAGE:
//   - Request-URI: extracted from P-Asserted-Identity (or From) of the inbound MESSAGE
//   - In-Reply-To: the Call-ID of the inbound MESSAGE
//   - Content-Type: application/vnd.3gpp.sms (or CPIM wrapper)
//   - Body: RP-ACK PDU
//   - Security-Verify: inherited from the IMS registration
//
// This replaces the previous approach of carrying RP-ACK in the 200 OK body,
// which caused duplicate SMS delivery after restart (P-CSCF retransmits
// unacknowledged RP-DATA).
func (s *Service) sendRPAckMessage(ctx context.Context, inboundReq *sip.Request, rpAckBody []byte, contentType string) {
	if s.inner == nil {
		logger.Warn(fmt.Sprintf("[%s] RP-ACK 发送失败：voiceclient 不可用", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)))
		return
	}

	// Extract the target URI from P-Asserted-Identity or From header.
	targetURI := extractRPAckTargetURI(inboundReq)
	if targetURI == "" {
		logger.Warn(fmt.Sprintf("[%s] RP-ACK 发送失败：无法提取目标 URI", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)))
		return
	}

	// Extract the Call-ID for In-Reply-To.
	inboundCallID := ""
	if callID := inboundReq.CallID(); callID != nil {
		inboundCallID = strings.TrimSpace(callID.Value())
	}

	traceID := strings.TrimSpace(s.cfg.TraceID)

	// Build and send the RP-ACK MESSAGE with retry.
	var lastErr error
	for attempt := 0; attempt <= rpAckMaxRetries; attempt++ {
		if attempt > 0 {
			logger.Debug(fmt.Sprintf("[%s] RP-ACK 重试", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", traceID),
				logger.Int("attempt", attempt+1))
		}
		err := s.doSendRPAck(ctx, targetURI, inboundCallID, rpAckBody, contentType)
		if err == nil {
			logger.Debug(fmt.Sprintf("[%s] IMS RP report send", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", traceID),
				logger.String("target", targetURI),
				logger.String("in_reply_to", inboundCallID))
			return
		}
		lastErr = err
		// Check if context is cancelled before retrying.
		if ctx.Err() != nil {
			break
		}
	}
	logger.Warn(fmt.Sprintf("[%s] RP-ACK 发送失败", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", traceID),
		logger.String("error", lastErr.Error()),
		logger.Int("attempts", rpAckMaxRetries+1))
}

// doSendRPAck builds and sends a single RP-ACK SIP MESSAGE.
func (s *Service) doSendRPAck(ctx context.Context, targetURI, inboundCallID string, body []byte, contentType string) error {
	sipClient := s.inner.SIPClient()
	if sipClient == nil {
		return fmt.Errorf("sipgo client unavailable")
	}

	// Build the RP-ACK MESSAGE request.
	req, err := s.buildRPAckRequest(targetURI, inboundCallID, body, contentType)
	if err != nil {
		return fmt.Errorf("build RP-ACK request: %w", err)
	}

	// Send via sipgo Client transaction.
	txCtx, cancel := context.WithTimeout(ctx, rpAckTimeout)
	defer cancel()

	tx, err := sipClient.TransactionRequest(txCtx, req)
	if err != nil {
		return fmt.Errorf("transaction request: %w", err)
	}
	defer tx.Terminate()

	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return fmt.Errorf("transaction ended: %w", err)
		}
		return fmt.Errorf("transaction ended without response")
	case res := <-tx.Responses():
		logger.Debug(fmt.Sprintf("[%s] RP-ACK 响应", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.Int("sip_code", res.StatusCode),
			logger.String("reason", res.Reason))
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return fmt.Errorf("RP-ACK MESSAGE rejected: %d %s", res.StatusCode, res.Reason)
		}
		return nil
	case <-txCtx.Done():
		return txCtx.Err()
	}
}

// buildRPAckRequest constructs a SIP MESSAGE carrying the RP-ACK PDU.
func (s *Service) buildRPAckRequest(targetURI, inboundCallID string, body []byte, contentType string) (*sip.Request, error) {
	// Parse the target URI.
	recipient := sip.Uri{}
	rawURI := strings.TrimSpace(targetURI)
	if !strings.HasPrefix(strings.ToLower(rawURI), "sip:") && !strings.HasPrefix(strings.ToLower(rawURI), "sips:") {
		rawURI = "sip:" + rawURI
	}
	if err := sip.ParseUri(rawURI, &recipient); err != nil {
		return nil, fmt.Errorf("parse target URI %q: %w", rawURI, err)
	}

	req := sip.NewRequest(sip.MESSAGE, recipient)

	// From/To headers.
	fromURI := strings.TrimSpace(s.cfg.PublicURI)
	if fromURI == "" {
		return nil, fmt.Errorf("public URI is empty")
	}
	req.AppendHeader(sip.NewHeader("From", "<"+fromURI+">;tag="+sip.GenerateTagN(16)))
	req.AppendHeader(sip.NewHeader("To", "<"+targetURI+">"))

	// Contact header.
	// Use net.JoinHostPort to correctly bracket IPv6 addresses.
	contactHost := s.cfg.LocalIP.String()
	contactPort := s.inner.LocalPort()
	if contactPort <= 0 {
		contactPort = 5060
	}
	contactUser := s.inner.ContactUser()
	if contactUser == "" {
		contactUser = "anonymous"
	}
	contactHostPort := net.JoinHostPort(contactHost, fmt.Sprintf("%d", contactPort))
	req.AppendHeader(sip.NewHeader("Contact", fmt.Sprintf("<sip:%s@%s;transport=tcp>", contactUser, contactHostPort)))

	// In-Reply-To: the Call-ID of the inbound MESSAGE.
	if inboundCallID != "" {
		req.AppendHeader(sip.NewHeader("In-Reply-To", inboundCallID))
	}

	// Security-Verify: inherited from IMS registration.
	if verify := strings.TrimSpace(s.verifyHeader); verify != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", verify))
	}

	// Service-Route (if available).
	for _, route := range s.inner.ServiceRoutes() {
		if v := strings.TrimSpace(route); v != "" {
			req.AppendHeader(sip.NewHeader("Route", v))
		}
	}

	// P-Preferred-Identity.
	req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+fromURI+">"))

	// Content-Type and body.
	if contentType == "" {
		contentType = messaging.IMS3GPPSMSContentType
	}
	req.AppendHeader(sip.NewHeader("Content-Type", contentType))
	req.SetBody(body)

	// Transport and destination.
	req.SetTransport("TCP")
	req.SetDestination(s.pcscf)

	return req, nil
}

// extractRPAckTargetURI extracts the RP-ACK target URI from the inbound MESSAGE.
// Per spec, it checks P-Asserted-Identity first, then falls back to From header.
func extractRPAckTargetURI(req *sip.Request) string {
	// Try P-Asserted-Identity first.
	for _, header := range req.GetHeaders("P-Asserted-Identity") {
		if header == nil {
			continue
		}
		uri := extractAngleBracketURI(strings.TrimSpace(header.Value()))
		if uri != "" && !strings.ContainsAny(uri, "\r\n") {
			return uri
		}
	}
	// Fall back to From header.
	if from := req.From(); from != nil {
		uri := extractAngleBracketURI(strings.TrimSpace(from.Address.String()))
		if uri != "" && !strings.ContainsAny(uri, "\r\n") {
			return uri
		}
	}
	return ""
}
