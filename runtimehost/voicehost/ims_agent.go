package voicehost

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
)

var ErrIMSVoiceAgentNotReady = errors.New("ims voice agent not ready")

// IMSOutboundAgent implements OutboundCallAgent, DialogTerminatorWithResult,
// and DialogCancellerWithResult using sipgo's native transaction API.
//
// This is the V2 rewrite of vowifi-go's IMSOutboundAgent, replacing the
// custom SIPRequestTransport abstraction with direct sipgo.Client usage.
// Phase 1 implements the core call flow: INVITE → 200 OK → ACK → RTP relay
// → BYE/CANCEL. Advanced features (PRACK, digest challenge retry, redirect
// handling, SRTP negotiation) will be added in later phases.
type IMSOutboundAgent struct {
	// Transport is the sipgo Client that sends SIP requests through the
	// SWu-tunnel-bound transport already configured by voiceclient.
	Transport *sipgo.Client

	// UA is the sipgo UserAgent (for branch/tag generation etc).
	UA *sipgo.UserAgent

	// Profile carries IMS identity and domain information.
	Profile IMSProfile

	// Registration carries the SIP registration binding (ContactURI,
	// Service-Route, etc.) obtained from the 200 OK of REGISTER.
	Registration IMSRegistrationBinding

	// Domain is the IMS home domain (e.g. "ims.mnc001.mcc001.3gppnetwork.org").
	Domain string

	// UserAgent is the SIP User-Agent header value.
	UserAgent string

	// LocalTag is the tag used in the From header for outbound dialogs.
	LocalTag string

	// SessionExpires / SessionRefresher control session timers (RFC 4028).
	SessionExpires   int
	SessionRefresher string

	// MediaRelay configures the RTP relay between the Linphone client
	// and the IMS media path. nil disables media relay (call setup only).
	MediaRelay *RTPRelayConfig

	mu      sync.Mutex
	dialogs map[string]*imsDialogState
}

// IMSProfile carries the IMS identity information needed to build
// SIP dialog requests (INVITE, BYE, etc.).
type IMSProfile struct {
	IMPI      string // IMS private identity
	IMPU      string // IMS public identity (sip:user@domain)
	Domain    string // IMS home domain
	LocalIP   string // tunnel virtual IP
	UserAgent string // SIP User-Agent header
}

// IMSRegistrationBinding carries the SIP registration binding state
// obtained from the 200 OK of REGISTER.
type IMSRegistrationBinding struct {
	ContactURI string   // Contact header value from REGISTER 200 OK
	RouteSet   []string // Service-Route / Record-Route headers
	Expires    int      // registration expiry in seconds
}

// IMSRegistrationUpdate is passed to UpdateIMSRegistration to
// refresh the agent's transport and registration state.
type IMSRegistrationUpdate struct {
	Transport        *sipgo.Client
	UA               *sipgo.UserAgent
	Profile          IMSProfile
	Registration     IMSRegistrationBinding
	Domain           string
	UserAgent        string
	SessionExpires   int
	SessionRefresher string
	MediaRelay       *RTPRelayConfig
}

// IMSRegistrationUpdater is implemented by agents that can receive
// registration updates (used by vohive-next when IMS re-registers).
type IMSRegistrationUpdater interface {
	UpdateIMSRegistration(IMSRegistrationUpdate)
}

func (a *IMSOutboundAgent) UpdateIMSRegistration(update IMSRegistrationUpdate) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if update.Transport != nil {
		a.Transport = update.Transport
	}
	if update.UA != nil {
		a.UA = update.UA
	}
	if strings.TrimSpace(update.Profile.IMPU) != "" || strings.TrimSpace(update.Profile.IMPI) != "" {
		a.Profile = update.Profile
	}
	if strings.TrimSpace(update.Registration.ContactURI) != "" {
		a.Registration = update.Registration
	}
	if strings.TrimSpace(update.Domain) != "" {
		a.Domain = strings.TrimSpace(update.Domain)
	}
	if strings.TrimSpace(update.UserAgent) != "" {
		a.UserAgent = strings.TrimSpace(update.UserAgent)
	}
	if update.SessionExpires > 0 {
		a.SessionExpires = update.SessionExpires
	}
	if refresher := normalizeSessionRefresher(update.SessionRefresher); refresher != "" {
		a.SessionRefresher = refresher
	}
	if update.MediaRelay != nil {
		a.MediaRelay = update.MediaRelay
	}
}

type imsDialogState struct {
	callID       string
	cseq         int
	localTag     string
	remoteTag    string
	contactURI   string
	routeSet     []string
	remoteTarget string
	relay        *RTPRelaySession
	localSDP     []byte
	remoteSDP    SDPInfo
	established  bool
	terminating  bool
}

func (a *IMSOutboundAgent) storeDialog(callID string, state *imsDialogState) {
	if a == nil || strings.TrimSpace(callID) == "" {
		return
	}
	a.mu.Lock()
	if a.dialogs == nil {
		a.dialogs = make(map[string]*imsDialogState)
	}
	a.dialogs[strings.TrimSpace(callID)] = state
	a.mu.Unlock()
}

func (a *IMSOutboundAgent) loadDialog(callID string) (*imsDialogState, bool) {
	if a == nil {
		return nil, false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	d, ok := a.dialogs[strings.TrimSpace(callID)]
	return d, ok
}

func (a *IMSOutboundAgent) deleteDialog(callID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	delete(a.dialogs, strings.TrimSpace(callID))
	a.mu.Unlock()
}

// StartOutboundCall implements OutboundCallAgent. It sends an INVITE
// to the IMS network (via the P-CSCF), waits for a final response,
// sends ACK on 200 OK, and starts the RTP relay if configured.
func (a *IMSOutboundAgent) StartOutboundCall(ctx context.Context, req OutboundCallRequest) (OutboundCallResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if a == nil || a.Transport == nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS voice transport unavailable"}, ErrIMSVoiceAgentNotReady
	}
	if strings.TrimSpace(req.CallID) == "" {
		return OutboundCallResult{Accepted: false, Reason: "Call-ID empty"}, errors.New("Call-ID is empty")
	}
	callee := strings.TrimSpace(req.Callee)
	if callee == "" {
		return OutboundCallResult{Accepted: false, Reason: "callee empty"}, errors.New("callee is empty")
	}

	// Build remote URI
	domain := strings.TrimSpace(a.Domain)
	if domain == "" {
		domain = strings.TrimSpace(a.Profile.Domain)
	}
	remoteURI := fmt.Sprintf("sip:%s@%s", callee, domain)
	if strings.HasPrefix(callee, "sip:") {
		remoteURI = callee
	}

	// Parse remote URI
	var parsedRemote sip.Uri
	if err := sip.ParseUri(remoteURI, &parsedRemote); err != nil {
		return OutboundCallResult{Accepted: false, Reason: "invalid callee URI"}, fmt.Errorf("parse remote URI: %w", err)
	}

	// Build local identity
	localURI := strings.TrimSpace(a.Profile.IMPU)
	if localURI == "" {
		localURI = fmt.Sprintf("sip:%s@%s", strings.TrimSpace(a.Profile.IMPI), domain)
	}

	// Generate tag
	localTag := strings.TrimSpace(a.LocalTag)
	if localTag == "" {
		localTag = sip.GenerateTagN(16)
	}

	// Build INVITE request
	callID := strings.TrimSpace(req.CallID)
	inviteReq := sip.NewRequest(sip.INVITE, parsedRemote)
	if len(req.RawSDP) > 0 {
		inviteReq.SetBody(append([]byte(nil), req.RawSDP...))
	}
	inviteReq.AppendHeader(sip.NewHeader("From", fmt.Sprintf("<%s>;tag=%s", localURI, localTag)))
	inviteReq.AppendHeader(sip.NewHeader("To", fmt.Sprintf("<%s>", remoteURI)))
	inviteReq.AppendHeader(sip.NewHeader("Call-ID", callID))
	inviteReq.AppendHeader(sip.NewHeader("CSeq", "1 INVITE"))
	inviteReq.AppendHeader(sip.NewHeader("Via", sip.GenerateBranch()))
	contactURI := strings.TrimSpace(a.Registration.ContactURI)
	if contactURI == "" {
		localIP := strings.TrimSpace(a.Profile.LocalIP)
		if localIP == "" {
			localIP = "0.0.0.0"
		}
		contactURI = fmt.Sprintf("sip:%s@%s", strings.TrimSpace(a.Profile.IMPI), localIP)
	}
	inviteReq.AppendHeader(sip.NewHeader("Contact", contactURI))
	ua := strings.TrimSpace(a.UserAgent)
	if ua == "" {
		ua = strings.TrimSpace(a.Profile.UserAgent)
	}
	if ua == "" {
		ua = "vowifi-core"
	}
	ua = strings.TrimSpace(ua)
	if len(ua) > len("User-Agent:") && strings.EqualFold(ua[:len("User-Agent:")], "User-Agent:") {
		ua = strings.TrimSpace(ua[len("User-Agent:"):])
	}
	inviteReq.AppendHeader(sip.NewHeader("User-Agent", ua))
	if len(req.RawSDP) > 0 {
		inviteReq.AppendHeader(sip.NewHeader("Content-Type", "application/sdp"))
	}
	// Add Route headers from registration
	for _, route := range a.Registration.RouteSet {
		inviteReq.AppendHeader(sip.NewHeader("Route", route))
	}
	// Add extra headers from request
	for key, value := range req.Headers {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || value == "" || isProtectedDialogHeader(key) {
			continue
		}
		inviteReq.AppendHeader(sip.NewHeader(key, value))
	}

	// Setup RTP relay
	var relay *RTPRelaySession
	closeRelayOnError := true
	defer func() {
		if closeRelayOnError && relay != nil {
			_ = relay.Close()
		}
	}()
	if a.MediaRelay != nil {
		createdRelay, relayErr := NewRTPRelaySession(ctx, *a.MediaRelay, req.RemoteSDP)
		if relayErr != nil {
			return OutboundCallResult{Accepted: false, Reason: "RTP relay setup failed"}, relayErr
		}
		relay = createdRelay
		// Rewrite SDP media endpoint to point to the relay's IMS-side address
		imsEP := relay.IMSEndpoint()
		inviteBody := RewriteSDPMediaEndpoint(req.RawSDP, imsEP)
		inviteReq.SetBody(inviteBody)
	}

	// Send INVITE
	tx, err := a.Transport.TransactionRequest(ctx, inviteReq)
	if err != nil {
		return OutboundCallResult{Accepted: false, Reason: "IMS INVITE send failed", RegistrationRecoveryNeeded: true}, fmt.Errorf("send INVITE: %w", err)
	}

	// Wait for final response
	var finalResp *sip.Response
	for {
		select {
		case <-ctx.Done():
			// Send CANCEL
			cancelReq := sip.NewRequest(sip.CANCEL, parsedRemote)
			sip.CopyHeaders("From", inviteReq, cancelReq)
			sip.CopyHeaders("To", inviteReq, cancelReq)
			sip.CopyHeaders("Call-ID", inviteReq, cancelReq)
			sip.CopyHeaders("Via", inviteReq, cancelReq)
			sip.CopyHeaders("Route", inviteReq, cancelReq)
			_ = a.Transport.WriteRequest(cancelReq)
			return OutboundCallResult{Accepted: false, Reason: ctx.Err().Error()}, ctx.Err()
		case resp, ok := <-tx.Responses():
			if !ok {
				return OutboundCallResult{Accepted: false, Reason: "no response from IMS", RegistrationRecoveryNeeded: true}, errors.New("IMS INVITE: transaction closed without final response")
			}
			if resp.StatusCode >= 100 && resp.StatusCode < 200 {
				// Provisional response — keep waiting
				continue
			}
			finalResp = resp
		}
		if finalResp != nil {
			break
		}
	}

	// Handle final response
	if finalResp.StatusCode >= 300 {
		reason := strings.TrimSpace(finalResp.Reason)
		if reason == "" {
			reason = fmt.Sprintf("IMS INVITE rejected: %d", finalResp.StatusCode)
		}
		return OutboundCallResult{Accepted: false, StatusCode: finalResp.StatusCode, Reason: reason}, nil
	}

	// 200 OK — extract dialog parameters from response
	remoteTag := ""
	if to := finalResp.To(); to != nil {
		if tag, ok := to.Params.Get("tag"); ok {
			remoteTag = strings.TrimSpace(tag)
		}
	}
	remoteContact := ""
	if contact := finalResp.Contact(); contact != nil {
		remoteContact = strings.TrimSpace(contact.Address.String())
	}
	// Build route set from Record-Route headers
	var routeSet []string
	for _, rr := range finalResp.GetHeaders("Record-Route") {
		routeSet = append(routeSet, strings.TrimSpace(rr.Value()))
	}

	// Parse remote SDP from 200 OK
	remoteSDP, err := ParseSDP(finalResp.Body())
	var localSDPBody []byte
	if err == nil && relay != nil {
		_ = relay.SetIMSRemote(remoteSDP)
		clientEP := relay.ClientEndpoint()
		localSDPBody = BuildSDPAnswer(SDPInfo{
			ConnectionIP: clientEP.ConnectionIP,
			MediaPort:    clientEP.MediaPort,
			Payloads:     remoteSDP.Payloads,
			Direction:    "sendrecv",
		})
	}

	// Send ACK
	ackReq := sip.NewRequest(sip.ACK, parsedRemote)
	sip.CopyHeaders("From", inviteReq, ackReq)
	sip.CopyHeaders("To", inviteReq, ackReq)
	sip.CopyHeaders("Call-ID", inviteReq, ackReq)
	sip.CopyHeaders("Via", inviteReq, ackReq)
	sip.CopyHeaders("Route", inviteReq, ackReq)
	if remoteTag != "" {
		if to := ackReq.To(); to != nil {
			to.Params.Add("tag", remoteTag)
		}
	}
	_ = a.Transport.WriteRequest(ackReq, sipgo.ClientRequestBuild)

	// Store dialog state
	dialogState := &imsDialogState{
		callID:       callID,
		cseq:         1,
		localTag:     localTag,
		remoteTag:    remoteTag,
		contactURI:   remoteContact,
		routeSet:     routeSet,
		remoteTarget: remoteContact,
		relay:        relay,
		localSDP:     localSDPBody,
		remoteSDP:    remoteSDP,
		established:  true,
	}
	a.storeDialog(callID, dialogState)
	closeRelayOnError = false

	// Build result
	result := OutboundCallResult{
		Accepted:   true,
		StatusCode: finalResp.StatusCode,
		Reason:     "OK",
		Headers:    map[string]string{},
	}
	if len(localSDPBody) > 0 {
		result.RawSDP = localSDPBody
	} else if relay != nil {
		ce := relay.ClientEndpoint()
		result.LocalSDP = SDPInfo{
			ConnectionIP: ce.ConnectionIP,
			MediaPort:    ce.MediaPort,
			Payloads:     remoteSDP.Payloads,
			Direction:    "sendrecv",
		}
	}
	return result, nil
}

// EndVoiceCallWithResult implements DialogTerminatorWithResult.
func (a *IMSOutboundAgent) EndVoiceCallWithResult(ctx context.Context, dialog DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	callID := strings.TrimSpace(dialog.CallID)
	state, ok := a.loadDialog(callID)
	if !ok {
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}

	// Build BYE request
	var byeURI sip.Uri
	if err := sip.ParseUri(state.remoteTarget, &byeURI); err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "invalid remote target"}, err
	}
	byeReq := sip.NewRequest(sip.BYE, byeURI)
	byeReq.AppendHeader(sip.NewHeader("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", a.Profile.IMPI, a.Domain, state.localTag)))
	byeReq.AppendHeader(sip.NewHeader("To", fmt.Sprintf("<sip:%s@%s>;tag=%s", dialog.Callee, a.Domain, state.remoteTag)))
	byeReq.AppendHeader(sip.NewHeader("Call-ID", callID))
	byeReq.AppendHeader(sip.NewHeader("CSeq", strconv.Itoa(state.cseq+1)+" BYE"))
	byeReq.AppendHeader(sip.NewHeader("Via", sip.GenerateBranchN(16)))
	for _, route := range state.routeSet {
		byeReq.AppendHeader(sip.NewHeader("Route", route))
	}

	tx, err := a.Transport.TransactionRequest(ctx, byeReq)
	if err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "BYE send failed"}, err
	}

	// Wait for 200 OK
	var finalResp *sip.Response
	for {
		resp, ok := <-tx.Responses()
		if !ok {
			break
		}
		if resp.StatusCode >= 200 {
			finalResp = resp
			break
		}
	}

	// Close RTP relay
	if state.relay != nil {
		_ = state.relay.Close()
	}
	a.deleteDialog(callID)

	if finalResp == nil {
		return DialogInfoResult{Accepted: false, StatusCode: 503, Reason: "no response to BYE"}, nil
	}
	return DialogInfoResult{
		Accepted:   finalResp.StatusCode >= 200 && finalResp.StatusCode < 300,
		StatusCode: finalResp.StatusCode,
		Reason:     finalResp.Reason,
	}, nil
}

// CancelVoiceCallWithResult implements DialogCancellerWithResult.
func (a *IMSOutboundAgent) CancelVoiceCallWithResult(ctx context.Context, dialog DialogInfo) (DialogInfoResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	callID := strings.TrimSpace(dialog.CallID)
	state, ok := a.loadDialog(callID)
	if !ok {
		return DialogInfoResult{Accepted: false, StatusCode: 481, Reason: "dialog not found"}, nil
	}

	// Build CANCEL request (same CSeq as INVITE)
	var remoteURI sip.Uri
	if err := sip.ParseUri(state.remoteTarget, &remoteURI); err != nil {
		return DialogInfoResult{Accepted: false, StatusCode: 500, Reason: "invalid remote target"}, err
	}
	cancelReq := sip.NewRequest(sip.CANCEL, remoteURI)
	cancelReq.AppendHeader(sip.NewHeader("From", fmt.Sprintf("<sip:%s@%s>;tag=%s", a.Profile.IMPI, a.Domain, state.localTag)))
	cancelReq.AppendHeader(sip.NewHeader("To", fmt.Sprintf("<sip:%s@%s>", dialog.Callee, a.Domain)))
	cancelReq.AppendHeader(sip.NewHeader("Call-ID", callID))
	cancelReq.AppendHeader(sip.NewHeader("CSeq", strconv.Itoa(state.cseq)+" CANCEL"))
	cancelReq.AppendHeader(sip.NewHeader("Via", sip.GenerateBranchN(16)))
	for _, route := range state.routeSet {
		cancelReq.AppendHeader(sip.NewHeader("Route", route))
	}

	_ = a.Transport.WriteRequest(cancelReq)

	// Close RTP relay
	if state.relay != nil {
		_ = state.relay.Close()
	}
	a.deleteDialog(callID)

	return DialogInfoResult{Accepted: true, StatusCode: 200, Reason: "OK"}, nil
}

// normalizeSessionRefresher validates and normalizes the session
// refresher value (RFC 4028). Empty or "uac"/"uas" are accepted.
func normalizeSessionRefresher(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "uac", "uas":
		return value
	default:
		return ""
	}
}
