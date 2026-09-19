package imscore

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// ussdTransport adapts *imscore.Service to implement messaging.USSDTransport.
// USSD over IMS uses SIP INVITE (dialog setup) → INFO (continuation) → BYE (cancel),
// per 3GPP TS 24.390.
//
// This is the imscore-owned version of voiceclient.ussdTransport, rewritten
// to depend on imscore.Service instead of voiceclient.Client.
type ussdTransport struct {
	svc *Service

	mu       sync.Mutex
	sessions map[string]*ussdDialog
}

type ussdDialog struct {
	callID     string
	cseq       int
	fromTag    string
	toTag      string
	contactURI string
	routeSet   []string
}

// newUSSDTransport creates a messaging.USSDTransport backed by the given imscore.Service.
func newUSSDTransport(s *Service) messaging.USSDTransport {
	return &ussdTransport{svc: s, sessions: make(map[string]*ussdDialog)}
}

func (t *ussdTransport) ExecuteUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	if t == nil || t.svc == nil {
		return messaging.USSDResult{SessionID: req.SessionID, Done: true}, messaging.ErrUSSDTransportUnavailable
	}
	command := strings.TrimSpace(req.Command)
	if command == "" {
		return messaging.USSDResult{SessionID: req.SessionID, Done: true}, fmt.Errorf("ussd command is empty")
	}
	s := t.svc
	sessionID := req.SessionID
	if sessionID == "" {
		sessionID = fmt.Sprintf("ussd-%d", len(command))
	}

	logger.Info(fmt.Sprintf("[%s] IMS USSD 发送", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("command", command),
		logger.String("session_id", sessionID))

	// Build USSD XML payload
	xmlBody, err := messaging.BuildIMSUSSDXML(messaging.IMSUSSDPayload{
		Language:  "en",
		Text:      command,
		Operation: messaging.IMSUSSDOperationRequest,
	})
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, err
	}

	// Build multipart/mixed body (SDP + USSD XML)
	boundary := "vowifi-ussd-" + sessionID
	body := buildUSSDMultipartBody(s.cfg.LocalIP.String(), boundary, xmlBody)

	// Build remote URI
	remoteURI := ussdRemoteURI(command, s.cfg.HomeDomain)
	if remoteURI == "" {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, fmt.Errorf("ussd remote URI is empty")
	}

	// Build INVITE request
	inviteReq, err := s.newRequest(sip.INVITE, remoteURI, false)
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, err
	}
	inviteReq.AppendHeader(sip.NewHeader("Content-Type", `multipart/mixed;boundary="`+boundary+`"`))
	inviteReq.AppendHeader(sip.NewHeader("Accept", messaging.IMSUSSDContentType+", application/sdp, multipart/mixed"))
	inviteReq.AppendHeader(sip.NewHeader("Recv-Info", messaging.IMSUSSDInfoPackage))
	inviteReq.AppendHeader(sip.NewHeader("P-Preferred-Service", "urn:urn-7:3gpp-service.ims.icsi.ussd"))
	inviteReq.AppendHeader(sip.NewHeader("Accept-Contact", "*;+g.3gpp.ussd"))
	inviteReq.SetBody(body)

	// Send INVITE (wait for final response, skip 100 Trying / 183 Session Progress)
	res, err := s.doTransactionFinal(ctx, inviteReq)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] IMS USSD INVITE 失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("session_id", sessionID),
			logger.String("error", err.Error()))
		return messaging.USSDResult{SessionID: sessionID, Done: true, Status: 0}, err
	}

	// Send ACK for 2xx response
	if res.StatusCode >= 200 && res.StatusCode < 300 {
		if err := t.sendACK(ctx, inviteReq, res); err != nil {
			logger.Warn(fmt.Sprintf("[%s] IMS USSD ACK 失败", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("session_id", sessionID),
				logger.String("error", err.Error()))
		}
	}

	// Parse USSD response
	result := parseUSSDResponse(sessionID, res)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		result.Done = true
		logger.Warn(fmt.Sprintf("[%s] IMS USSD INVITE 被拒绝", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("session_id", sessionID),
			logger.Int("sip_code", res.StatusCode),
			logger.String("reason", res.Reason))
		return result, fmt.Errorf("IMS USSD INVITE rejected: %d %s", res.StatusCode, res.Reason)
	}

	// Store dialog state if session continues
	if !result.Done {
		dialog := t.extractDialog(inviteReq, res)
		t.storeSession(sessionID, dialog)
	}

	logger.Info(fmt.Sprintf("[%s] IMS USSD 响应", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("session_id", sessionID),
		logger.Int("sip_code", res.StatusCode),
		logger.String("text", result.Text),
		logger.Bool("done", result.Done))

	return result, nil
}

func (t *ussdTransport) ContinueUSSD(ctx context.Context, req messaging.USSDRequest) (messaging.USSDResult, error) {
	if t == nil || t.svc == nil {
		return messaging.USSDResult{SessionID: req.SessionID, Done: true}, messaging.ErrUSSDTransportUnavailable
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return messaging.USSDResult{}, fmt.Errorf("ussd session_id is empty")
	}
	input := strings.TrimSpace(req.Input)
	if input == "" {
		return messaging.USSDResult{SessionID: sessionID}, fmt.Errorf("ussd input is empty")
	}
	dialog, ok := t.session(sessionID)
	if !ok {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, fmt.Errorf("ussd session %s is not active", sessionID)
	}
	s := t.svc
	dialog.cseq++

	logger.Info(fmt.Sprintf("[%s] IMS USSD 继续", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("session_id", sessionID),
		logger.String("input", input))

	// Build USSD XML
	xmlBody, err := messaging.BuildIMSUSSDXML(messaging.IMSUSSDPayload{
		Language:  "en",
		Text:      input,
		Operation: messaging.IMSUSSDOperationRequest,
	})
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, err
	}

	// Build INFO request within dialog
	infoReq, err := t.buildDialogRequest(sip.INFO, dialog, xmlBody)
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Done: true}, err
	}
	infoReq.AppendHeader(sip.NewHeader("Info-Package", messaging.IMSUSSDInfoPackage))
	infoReq.AppendHeader(sip.NewHeader("Content-Disposition", messaging.IMSUSSDContentDisposition))
	infoReq.AppendHeader(sip.NewHeader("Accept", messaging.IMSUSSDContentType))
	infoReq.AppendHeader(sip.NewHeader("Recv-Info", messaging.IMSUSSDInfoPackage))

	res, err := s.doTransaction(ctx, infoReq)
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Done: true, Status: 0}, err
	}

	result := parseUSSDResponse(sessionID, res)
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		result.Done = true
		t.clearSession(sessionID)
		return result, fmt.Errorf("IMS USSD INFO rejected: %d %s", res.StatusCode, res.Reason)
	}

	if result.Done {
		t.clearSession(sessionID)
	} else {
		t.storeSession(sessionID, dialog)
	}

	logger.Info(fmt.Sprintf("[%s] IMS USSD 继续响应", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("session_id", sessionID),
		logger.Int("sip_code", res.StatusCode),
		logger.String("text", result.Text),
		logger.Bool("done", result.Done))

	return result, nil
}

func (t *ussdTransport) CancelUSSD(ctx context.Context, req messaging.USSDRequest) error {
	if t == nil || t.svc == nil {
		return messaging.ErrUSSDTransportUnavailable
	}
	sessionID := strings.TrimSpace(req.SessionID)
	if sessionID == "" {
		return fmt.Errorf("ussd session_id is empty")
	}
	dialog, ok := t.session(sessionID)
	if !ok {
		return nil
	}
	s := t.svc
	dialog.cseq++

	logger.Info(fmt.Sprintf("[%s] IMS USSD 取消", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("session_id", sessionID))

	byeReq, err := t.buildDialogRequest(sip.BYE, dialog, nil)
	if err != nil {
		t.clearSession(sessionID)
		return err
	}

	_, err = s.doTransaction(ctx, byeReq)
	t.clearSession(sessionID)
	if err != nil {
		return err
	}
	return nil
}

// sendACK sends an ACK for a 2xx INVITE response.
func (t *ussdTransport) sendACK(ctx context.Context, invite *sip.Request, res *sip.Response) error {
	s := t.svc
	ackURI := invite.Recipient
	if contact := res.GetHeader("Contact"); contact != nil {
		parsed := sip.Uri{}
		if err := sip.ParseUri(parseContactURI(contact.Value()), &parsed); err == nil {
			ackURI = parsed
		}
	}
	ack := sip.NewRequest(sip.ACK, ackURI)
	// Copy Call-ID, From, To, CSeq from INVITE/response
	if callID := invite.CallID(); callID != nil {
		ack.AppendHeader(sip.NewHeader("Call-ID", callID.Value()))
	}
	if from := invite.GetHeader("From"); from != nil {
		ack.AppendHeader(from)
	}
	if to := res.GetHeader("To"); to != nil {
		ack.AppendHeader(to)
	} else if toHdr := invite.GetHeader("To"); toHdr != nil {
		ack.AppendHeader(toHdr)
	}
	cseqStr := "1 ACK"
	if cseq := invite.GetHeader("CSeq"); cseq != nil {
		cseqStr = replaceCSeqMethod(cseq.Value(), "ACK")
	}
	ack.AppendHeader(sip.NewHeader("CSeq", cseqStr))
	// Copy Via
	if via := invite.GetHeader("Via"); via != nil {
		ack.AppendHeader(via)
	}
	// Copy Route headers from response
	for _, route := range getRecordRoute(res) {
		ack.AppendHeader(sip.NewHeader("Route", route))
	}
	ack.SetTransport(invite.Transport())
	if s.transportNetwork() == "udp" {
		ack.SetTransport("UDP")
	} else {
		ack.SetTransport("TCP")
	}
	return s.sipClient.WriteRequest(ack)
}

// buildDialogRequest builds a SIP request within an established dialog.
func (t *ussdTransport) buildDialogRequest(method sip.RequestMethod, d *ussdDialog, body []byte) (*sip.Request, error) {
	s := t.svc
	remoteURI := d.contactURI
	if remoteURI == "" {
		remoteURI = s.basePublicURI
	}
	recipient := sip.Uri{}
	if err := sip.ParseUri(remoteURI, &recipient); err != nil {
		return nil, fmt.Errorf("parse dialog remote URI: %w", err)
	}
	req := sip.NewRequest(method, recipient)
	req.AppendHeader(sip.NewHeader("From", "<"+s.basePublicURI+">;tag="+d.fromTag))
	req.AppendHeader(sip.NewHeader("To", "<"+remoteURI+">;tag="+d.toTag))
	req.AppendHeader(sip.NewHeader("Call-ID", d.callID))
	req.AppendHeader(sip.NewHeader("CSeq", strconv.Itoa(d.cseq)+" "+string(method)))
	contact := s.buildContactHeader()
	req.AppendHeader(sip.NewHeader("Contact", contact))
	req.AppendHeader(sip.NewHeader("User-Agent", voiceclient.NormalizeUserAgent(s.registerProfile.UserAgent)))
	for _, route := range d.routeSet {
		req.AppendHeader(sip.NewHeader("Route", route))
	}
	if body != nil {
		req.AppendHeader(sip.NewHeader("Content-Type", messaging.IMSUSSDContentType))
		req.SetBody(body)
	}
	if s.transportNetwork() == "udp" {
		req.SetTransport("UDP")
	} else {
		req.SetTransport("TCP")
	}
	return req, nil
}

// extractDialog extracts dialog parameters from INVITE request and 2xx response.
func (t *ussdTransport) extractDialog(invite *sip.Request, res *sip.Response) *ussdDialog {
	d := &ussdDialog{}
	if callID := invite.CallID(); callID != nil {
		d.callID = callID.Value()
	}
	if from := invite.GetHeader("From"); from != nil {
		d.fromTag = extractTag(from.Value())
	}
	if to := res.GetHeader("To"); to != nil {
		d.toTag = extractTag(to.Value())
	}
	if contact := res.GetHeader("Contact"); contact != nil {
		d.contactURI = parseContactURI(contact.Value())
	}
	d.routeSet = getRecordRoute(res)
	d.cseq = 1
	return d
}

func (t *ussdTransport) session(sessionID string) (*ussdDialog, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	d, ok := t.sessions[sessionID]
	return d, ok
}

func (t *ussdTransport) storeSession(sessionID string, d *ussdDialog) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sessions[sessionID] = d
}

func (t *ussdTransport) clearSession(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.sessions, sessionID)
}

// parseUSSDResponse extracts USSD result from SIP response body.
func parseUSSDResponse(sessionID string, res *sip.Response) messaging.USSDResult {
	contentType := ""
	if ct := res.GetHeader("Content-Type"); ct != nil {
		contentType = ct.Value()
	}
	payload, ok, err := messaging.DecodeIMSUSSDDocument(contentType, res.Body())
	if err != nil {
		return messaging.USSDResult{SessionID: sessionID, Status: res.StatusCode, Done: true}
	}
	if ok {
		result := ussdResultFromPayload(sessionID, payload, res.StatusCode)
		return result
	}
	return messaging.USSDResult{SessionID: sessionID, Status: res.StatusCode, Done: true}
}

// ussdResultFromPayload converts a parsed USSD payload to a USSDResult.
func ussdResultFromPayload(sessionID string, payload messaging.IMSUSSDPayload, status int) messaging.USSDResult {
	done := payload.HasError || payload.Operation == messaging.IMSUSSDOperationNotify || payload.Operation == messaging.IMSUSSDOperationRelease
	res := messaging.USSDResult{
		SessionID: sessionID,
		Text:      payload.Text,
		RawText:   payload.Text,
		Status:    status,
		DCS:       15,
		Done:      done,
	}
	if payload.HasError {
		res.Status = payload.ErrorCode
	}
	return res
}

// buildUSSDMultipartBody builds a multipart/mixed body with SDP + USSD XML.
func buildUSSDMultipartBody(localIP, boundary string, ussdBody []byte) []byte {
	localIP = strings.TrimSpace(localIP)
	if localIP == "" {
		localIP = "0.0.0.0"
	}
	var out bytes.Buffer
	out.WriteString("--")
	out.WriteString(boundary)
	out.WriteString("\r\nContent-Type: application/sdp\r\n\r\n")
	out.WriteString("v=0\r\n")
	out.WriteString("o=- 0 0 IN IP4 ")
	out.WriteString(localIP)
	out.WriteString("\r\n")
	out.WriteString("s=-\r\n")
	out.WriteString("c=IN IP4 ")
	out.WriteString(localIP)
	out.WriteString("\r\n")
	out.WriteString("t=0 0\r\n")
	out.WriteString("m=message 0 TCP/MSRP *\r\n")
	out.WriteString("a=recvonly\r\n")
	out.WriteString("--")
	out.WriteString(boundary)
	out.WriteString("\r\nContent-Type: ")
	out.WriteString(messaging.IMSUSSDContentType)
	out.WriteString("\r\nContent-Disposition: ")
	out.WriteString(messaging.IMSUSSDContentDisposition)
	out.WriteString("\r\n\r\n")
	out.Write(ussdBody)
	out.WriteString("\r\n--")
	out.WriteString(boundary)
	out.WriteString("--\r\n")
	return out.Bytes()
}

// ussdRemoteURI builds the remote URI for USSD INVITE.
func ussdRemoteURI(command, domain string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	lower := strings.ToLower(command)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") || strings.HasPrefix(lower, "tel:") {
		return command
	}
	encoded := encodeUSSDDialString(command)
	if domain == "" {
		return "tel:" + encoded
	}
	return "sip:" + encoded + "@" + domain + ";user=dialstring"
}

// encodeUSSDDialString percent-encodes non-dial characters in USSD commands.
func encodeUSSDDialString(command string) string {
	var b strings.Builder
	const hex = "0123456789ABCDEF"
	for _, c := range []byte(command) {
		switch {
		case c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == '*':
			b.WriteByte(c)
		case c == '#':
			b.WriteString("%23")
		default:
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0f])
		}
	}
	return b.String()
}

// extractTag extracts the tag parameter from a SIP header value.
func extractTag(value string) string {
	for _, part := range strings.Split(value, ";") {
		key, raw, ok := strings.Cut(strings.TrimSpace(part), "=")
		if ok && strings.EqualFold(strings.TrimSpace(key), "tag") {
			return strings.Trim(strings.TrimSpace(raw), `"`)
		}
	}
	return ""
}

// parseContactURI extracts the URI from a Contact header value.
func parseContactURI(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if start := strings.IndexByte(value, '<'); start >= 0 {
		if end := strings.IndexByte(value[start+1:], '>'); end >= 0 {
			return strings.TrimSpace(value[start+1 : start+1+end])
		}
	}
	if semi := strings.IndexByte(value, ';'); semi >= 0 {
		value = value[:semi]
	}
	return strings.TrimSpace(strings.Trim(value, "<>"))
}

// getRecordRoute extracts Record-Route headers from a SIP response (reversed order).
func getRecordRoute(res *sip.Response) []string {
	var routes []string
	for _, hdr := range res.GetHeaders("Record-Route") {
		value := strings.TrimSpace(hdr.Value())
		if value != "" {
			routes = append(routes, value)
		}
	}
	// Reverse order for Route set
	for i, j := 0, len(routes)-1; i < j; i, j = i+1, j-1 {
		routes[i], routes[j] = routes[j], routes[i]
	}
	return routes
}

// replaceCSeqMethod replaces the method in a CSeq header value.
func replaceCSeqMethod(cseqValue, method string) string {
	parts := strings.Fields(strings.TrimSpace(cseqValue))
	if len(parts) >= 2 {
		return parts[0] + " " + method
	}
	return "1 " + method
}
