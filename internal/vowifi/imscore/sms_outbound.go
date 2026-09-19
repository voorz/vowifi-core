package imscore

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/voorz/sipgo/sip"
	"github.com/voorz/swu-go/pkg/logger"
	"github.com/voorz/vowifi-core/runtimehost/messaging"
)

const smsContentType = "application/vnd.3gpp.sms"

// sendSMS submits each of parts as a separate SIP MESSAGE (3GPP TS 24.341),
// expecting the immediate 202 Accepted per part, and records delivery
// tracking via DeliveryStore.
//
// This is the imscore-owned version of voiceclient.Client.SendSMS, moved
// here as part of the architecture refactoring.
func (s *Service) sendSMS(ctx context.Context, peer, content string, parts []messaging.SMSPart) (messaging.SendOutcome, error) {
	if len(parts) == 0 {
		return messaging.SendOutcome{}, fmt.Errorf("imscore: no parts to send")
	}
	logger.Info(fmt.Sprintf("[%s] IMS SMS 发送开始", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("peer", peer),
		logger.Int("parts", len(parts)))
	serviceCentreURI, err := s.smsServiceCentreURI()
	if err != nil {
		return messaging.SendOutcome{}, err
	}

	messageID := uuid.NewString()
	now := time.Now()

	if s.cfg.DeliveryStore != nil {
		if err := s.cfg.DeliveryStore.CreateSMSDelivery(messageID, "", s.cfg.DeviceID, peer, content, len(parts), now); err != nil {
			return messaging.SendOutcome{}, fmt.Errorf("imscore: CreateSMSDelivery: %w", err)
		}
	}

	for partIndex, part := range parts {
		partNo := partIndex + 1
		req, err := s.newRequest(sip.MESSAGE, serviceCentreURI, false)
		if err != nil {
			return messaging.SendOutcome{}, err
		}
		req.AppendHeader(sip.NewHeader("Content-Type", smsContentType))
		req.SetBody(part.Body)

		res, err := s.doTransaction(ctx, req)
		if err != nil {
			logger.Warn(fmt.Sprintf("[%s] IMS SMS 发送失败", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("peer", peer),
				logger.Int("part", partNo),
				logger.String("error", err.Error()))
			return messaging.SendOutcome{}, fmt.Errorf("imscore: submit part %d: %w", partNo, err)
		}
		if res.StatusCode != 202 {
			logger.Warn(fmt.Sprintf("[%s] IMS SMS 响应异常", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
				logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
				logger.String("peer", peer),
				logger.Int("part", partNo),
				logger.Int("sip_code", res.StatusCode),
				logger.String("reason", res.Reason))
			return messaging.SendOutcome{}, fmt.Errorf("imscore: submit part %d: unexpected response %d %s", partNo, res.StatusCode, res.Reason)
		}
		logger.Info(fmt.Sprintf("[%s] IMS SMS 分片已提交", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("peer", peer),
			logger.Int("part", partNo),
			logger.Int("parts_total", len(parts)),
			logger.Int("sip_code", res.StatusCode))

		if s.cfg.DeliveryStore != nil {
			callID := req.CallID().Value()
			if err := s.cfg.DeliveryStore.UpsertSMSDeliveryPart(messageID, partNo, callID, int(part.RPMR), "pending", now); err != nil {
				return messaging.SendOutcome{}, fmt.Errorf("imscore: UpsertSMSDeliveryPart: %w", err)
			}
		}
	}

	logger.Info(fmt.Sprintf("[%s] IMS SMS 发送完成", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("peer", peer),
		logger.Int("parts_total", len(parts)),
		logger.String("message_id", messageID))
	return messaging.SendOutcome{
		MessageID:     messageID,
		PartsTotal:    len(parts),
		DeliveryState: "pending",
	}, nil
}

// SendSMSPart implements messaging.SMSTransport by sending a single SMS part
// via SIP MESSAGE.
//
// This is the imscore-owned version of voiceclient.Client.SendSMSPart.
func (s *Service) SendSMSPart(ctx context.Context, req messaging.SMSSendRequest) (messaging.SMSSendResult, error) {
	part := req.Part
	logger.Info(fmt.Sprintf("[%s] IMS SMS 分片发送", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("peer", req.Peer),
		logger.Int("part_no", part.PartNo),
		logger.Int("total_parts", part.TotalParts))
	tpdu, err := messaging.BuildSMSSubmitTPDU(req.Peer, part, byte(req.Part.PartNo))
	if err != nil {
		return messaging.SMSSendResult{State: "failed", ErrorText: fmt.Sprintf("TPDU encode: %v", err)}, err
	}
	rpData, err := messaging.BuildSMSRPData(byte(req.Part.PartNo), s.cfg.SMSC, tpdu)
	if err != nil {
		return messaging.SMSSendResult{State: "failed", ErrorText: fmt.Sprintf("RP-DATA encode: %v", err)}, err
	}

	smscURI, err := s.smsServiceCentreURI()
	if err != nil {
		return messaging.SMSSendResult{State: "failed", ErrorText: fmt.Sprintf("SMSC URI: %v", err)}, err
	}

	sipReq, err := s.newRequest(sip.MESSAGE, smscURI, false)
	if err != nil {
		return messaging.SMSSendResult{State: "failed", ErrorText: fmt.Sprintf("SIP request: %v", err)}, err
	}

	sipReq.AppendHeader(sip.NewHeader("Content-Type", messaging.IMS3GPPSMSContentType))
	sipReq.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+s.basePublicURI+">"))
	sipReq.AppendHeader(sip.NewHeader("P-Asserted-Identity", "<"+s.basePublicURI+">"))
	sipReq.SetBody(rpData)

	res, err := s.doTransaction(ctx, sipReq)
	if err != nil {
		logger.Warn(fmt.Sprintf("[%s] IMS SMS 分片发送失败", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("peer", req.Peer),
			logger.Int("part_no", part.PartNo),
			logger.String("error", err.Error()))
		return messaging.SMSSendResult{
			CallID:    sipReq.CallID().Value(),
			RPMR:      req.Part.PartNo,
			State:     "failed",
			SIPCode:   0,
			ErrorText: err.Error(),
		}, err
	}

	result := messaging.SMSSendResult{
		CallID:  sipReq.CallID().Value(),
		RPMR:    req.Part.PartNo,
		SIPCode: res.StatusCode,
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		result.State = "failed"
		result.ErrorText = res.Reason
		logger.Warn(fmt.Sprintf("[%s] IMS SMS 分片响应异常", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
			logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
			logger.String("peer", req.Peer),
			logger.Int("part_no", part.PartNo),
			logger.Int("sip_code", res.StatusCode),
			logger.String("reason", res.Reason))
		return result, fmt.Errorf("SIP MESSAGE failed: %d %s", res.StatusCode, res.Reason)
	}

	result.State = "sent"
	if res.StatusCode == 202 {
		result.State = "accepted"
	}
	logger.Info(fmt.Sprintf("[%s] IMS SMS 分片已提交", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("trace_id", strings.TrimSpace(s.cfg.TraceID)),
		logger.String("device_id", strings.TrimSpace(s.cfg.DeviceID)),
		logger.String("peer", req.Peer),
		logger.Int("part_no", part.PartNo),
		logger.Int("sip_code", res.StatusCode),
		logger.String("state", result.State))
	return result, nil
}

// smsServiceCentreURI constructs the SIP URI for the SMS service centre.
func (s *Service) smsServiceCentreURI() (string, error) {
	raw := strings.TrimSpace(s.cfg.SMSC)
	if raw == "" {
		return "", fmt.Errorf("imscore: SMS service centre is unavailable")
	}
	lower := strings.ToLower(raw)
	if strings.HasPrefix(lower, "sip:") || strings.HasPrefix(lower, "sips:") {
		return raw, nil
	}
	if strings.HasPrefix(lower, "tel:") {
		raw = strings.TrimSpace(raw[4:])
	}
	if strings.Contains(raw, "@") {
		return "sip:" + raw, nil
	}
	number := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "").Replace(raw)
	if number == "" {
		return "", fmt.Errorf("imscore: SMS service centre is invalid")
	}
	digits := number
	if strings.HasPrefix(digits, "+") {
		digits = digits[1:]
	}
	if digits == "" {
		return "", fmt.Errorf("imscore: SMS service centre is invalid")
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("imscore: SMS service centre is invalid")
		}
	}
	domain := strings.TrimSpace(s.cfg.HomeDomain)
	if domain == "" {
		return "", fmt.Errorf("imscore: IMS home domain is unavailable for SMS service centre")
	}
	return "sip:" + number + "@" + domain + ";user=phone", nil
}
