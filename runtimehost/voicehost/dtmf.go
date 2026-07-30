package voicehost

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

const (
	DTMFInfoPackage       = "dtmf"
	DTMFRelayContentType  = "application/dtmf-relay"
	DefaultDTMFDurationMS = 160
	MaxDTMFDurationMS     = 5000
	DialogDTMFRouteRTP    = "rtp"
	DialogDTMFRouteInfo   = "info"
)

var ErrInvalidDTMF = errors.New("invalid DTMF relay")

type DialogDTMFSender interface {
	SendDialogDTMF(context.Context, DialogDTMFRequest) (DialogDTMFResult, error)
}

type DialogAutoDTMFSender interface {
	SendDialogAutoDTMF(context.Context, DialogDTMFRequest) (DialogAutoDTMFResult, error)
}

type DialogRTPDTMFSender interface {
	SendDialogRTPDTMF(context.Context, DialogRTPDTMFRequest) (DialogRTPDTMFResult, error)
}

type DialogDTMFRequest struct {
	DeviceID   string
	CallID     string
	Signal     string
	DurationMS int
	Headers    map[string]string
}

type DialogDTMFResult = DialogInfoResult

type DialogRTPDTMFRequest struct {
	DeviceID       string
	CallID         string
	Direction      RTPDTMFDirection
	Signal         string
	DurationMS     int
	StepMS         int
	EndPacketCount int
	Volume         uint8
	SequenceNumber uint16
	Timestamp      uint32
	SSRC           uint32
	PayloadType    uint8
	ClockRate      int
}

type DialogRTPDTMFResult struct {
	Accepted   bool
	StatusCode int
	Reason     string
	RTP        RTPRelayDTMFResult
}

type DialogAutoDTMFResult struct {
	Accepted                   bool
	StatusCode                 int
	Reason                     string
	Route                      string
	RegistrationRecoveryNeeded bool
	RetryAfter                 time.Duration
	RTP                        DialogRTPDTMFResult
	INFO                       DialogDTMFResult
}

// V2 (IMS Agent) methods — SendDialogDTMF, SendDialogRTPDTMF on
// *IMSOutboundAgent and *IMSInboundAgent — are omitted here because
// those types live in ims_agent.go / ims_inbound_agent.go which have
// not been ported yet (V2/V2b scope).  They will be restored when
// those files are ported.

func BuildDialogDTMFInfoRequest(req DialogDTMFRequest) (DialogInfoRequest, error) {
	body, err := BuildDTMFRelayBody(req.Signal, req.DurationMS)
	if err != nil {
		return DialogInfoRequest{}, err
	}
	return DialogInfoRequest{
		DeviceID:    strings.TrimSpace(req.DeviceID),
		CallID:      strings.TrimSpace(req.CallID),
		ContentType: DTMFRelayContentType,
		InfoPackage: DTMFInfoPackage,
		Body:        body,
		Headers:     cloneDTMFHeaders(req.Headers),
	}, nil
}

func BuildDTMFRelayBody(signal string, durationMS int) ([]byte, error) {
	signal, err := NormalizeDTMFSignal(signal)
	if err != nil {
		return nil, err
	}
	if durationMS <= 0 {
		durationMS = DefaultDTMFDurationMS
	}
	if durationMS > MaxDTMFDurationMS {
		return nil, fmt.Errorf("%w: duration %dms exceeds %dms", ErrInvalidDTMF, durationMS, MaxDTMFDurationMS)
	}
	body := "Signal=" + signal + "\r\nDuration=" + strconv.Itoa(durationMS) + "\r\n"
	return []byte(body), nil
}

func ParseDTMFRelayBody(body []byte) (signal string, durationMS int, err error) {
	var rawSignal string
	for _, line := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "signal":
			rawSignal = strings.TrimSpace(value)
		case "duration":
			durationMS, err = strconv.Atoi(strings.TrimSpace(value))
			if err != nil {
				return "", 0, fmt.Errorf("%w: invalid duration", ErrInvalidDTMF)
			}
		}
	}
	signal, err = NormalizeDTMFSignal(rawSignal)
	if err != nil {
		return "", 0, err
	}
	if durationMS <= 0 {
		return "", 0, fmt.Errorf("%w: duration is empty", ErrInvalidDTMF)
	}
	if durationMS > MaxDTMFDurationMS {
		return "", 0, fmt.Errorf("%w: duration %dms exceeds %dms", ErrInvalidDTMF, durationMS, MaxDTMFDurationMS)
	}
	return signal, durationMS, nil
}

func dialogRTPDTMFRelayRequest(req DialogRTPDTMFRequest) RTPRelayDTMFRequest {
	direction := req.Direction
	if direction == "" {
		direction = RTPDTMFClientToIMS
	}
	return RTPRelayDTMFRequest{
		Direction:      direction,
		Signal:         req.Signal,
		DurationMS:     req.DurationMS,
		StepMS:         req.StepMS,
		EndPacketCount: req.EndPacketCount,
		Volume:         req.Volume,
		SequenceNumber: req.SequenceNumber,
		Timestamp:      req.Timestamp,
		SSRC:           req.SSRC,
		PayloadType:    req.PayloadType,
		ClockRate:      req.ClockRate,
	}
}

func dialogRTPDTMFErrorStatus(err error) int {
	switch {
	case errors.Is(err, ErrInvalidDTMF):
		return 400
	case errors.Is(err, ErrRTPRelayConfig):
		return 409
	default:
		return 500
	}
}

func NormalizeDTMFSignal(signal string) (string, error) {
	signal = strings.ToUpper(strings.TrimSpace(signal))
	if len(signal) != 1 {
		return "", fmt.Errorf("%w: signal must be one DTMF digit", ErrInvalidDTMF)
	}
	ch := signal[0]
	if (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'D') || ch == '*' || ch == '#' {
		return signal, nil
	}
	return "", fmt.Errorf("%w: unsupported signal %q", ErrInvalidDTMF, signal)
}

func cloneDTMFHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for key, value := range headers {
		out[key] = value
	}
	return out
}
