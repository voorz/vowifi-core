package runtimehost

import (
	"context"
	"fmt"
	"net"
	"strings"

	swulogger "github.com/voorz/swu-go/pkg/logger"
)

// epdgCandidate represents a single ePDG address candidate with metadata
// about where it came from (user config, system profile, or 3GPP standard).
type epdgCandidate struct {
	Host   string
	Port   string
	Source string // "prepared" | "3gpp_default"
}

// buildEPDGCandidates constructs an ordered list of ePDG address candidates.
//
// The list follows the user's "dual-link" design:
//
//  1. The primary candidate comes from PrepareStart (which already resolves
//     the correct ePDG address through the dual-link chain: DB user config →
//     embedded JSON profile → 3GPP standard). This is "your address or my
//     address" — whoever's link is active.
//  2. The fallback candidate is always the 3GPP standard FQDN
//     (epdg.epc.mnc{mnc3}.mcc{mcc}.pub.3gppnetwork.org).
//
// If the primary candidate IS the 3GPP standard address (i.e., no one
// configured a custom ePDG), the list contains only one entry — there's
// no point trying the same address twice.
//
// The two candidates are independent and never mixed: if the primary
// fails (DNS resolution or tunnel establishment), the fallback is tried
// as a completely fresh attempt.
func buildEPDGCandidates(req StartRequest) []epdgCandidate {
	mcc := strings.TrimSpace(req.Profile.MCC)
	mnc := strings.TrimSpace(req.Profile.MNC)
	if mcc == "" || mnc == "" {
		return nil
	}
	mnc3 := mnc
	if len(mnc3) < 3 {
		mnc3 = strings.Repeat("0", 3-len(mnc3)) + mnc3
	}
	stdFQDN := fmt.Sprintf("epdg.epc.mnc%s.mcc%s.pub.3gppnetwork.org", mnc3, mcc)

	var candidates []epdgCandidate

	// Primary: from PrepareStart (resolves user config → system profile → 3GPP)
	primaryHost, primaryPort := resolveEPDGHost(req)
	if primaryHost != "" {
		primary := epdgCandidate{
			Host:   primaryHost,
			Port:   primaryPort,
			Source: "prepared",
		}
		// If PrepareStart already told us where the address came from,
		// use that for better logging.
		if req.Prepared != nil {
			switch req.Prepared.EPDGSource {
			case "carrier_override":
				primary.Source = "carrier_config"
			case "redirect":
				primary.Source = "runtime_override"
			case "3gpp_default":
				primary.Source = "3gpp_default"
			}
		}
		candidates = append(candidates, primary)
	}

	// Fallback: 3GPP standard address (only if different from primary)
	if primaryHost != stdFQDN {
		// Check if the primary is the standard address by value —
		// resolveEPDGHost might produce the same string via a different code path.
		alreadyHave := false
		for _, c := range candidates {
			if c.Host == stdFQDN {
				alreadyHave = true
				break
			}
		}
		if !alreadyHave {
			candidates = append(candidates, epdgCandidate{
				Host:   stdFQDN,
				Port:   "500",
				Source: "3gpp_default",
			})
		}
	}

	return candidates
}

// epdgTunnelResult holds the outcome of a successful tunnel establishment.
type epdgTunnelResult struct {
	Snapshot  swuSnapshot
	LocalIP   net.IP
	Dataplane swuInnerDataplane
	Mobike    func(string, string) error
	EpdgIP    string
	EpdgPort  string
	Cancel    context.CancelFunc // tunnel context cancel for cleanup by caller
}

// tryEPDGCandidates iterates through the candidate list, attempting DNS
// resolution and SWu tunnel establishment for each one. The first success
// returns immediately. If all candidates fail, the last error is returned.
//
// Each candidate is tried independently: a failed DNS lookup or tunnel
// error on candidate N does not affect candidate N+1.
func (i *Instance) tryEPDGCandidates(
	ctx context.Context,
	req StartRequest,
	generation uint64,
	candidates []epdgCandidate,
) (*epdgTunnelResult, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no ePDG candidates available")
	}

	// IKERetryCount: controls IKE retransmission count for ALL candidates
	// in the fallback chain. If the caller (front-end global setting) has
	// configured a value (e.g. 1 = 1 send + 1 retransmit), use it as-is.
	// If unset (0 = use swu-go default 5), default to 1 for fast fallback.
	// This ensures the front-end "IKE 重传次数" setting remains effective
	// across both primary and 3GPP fallback candidates.
	if req.IKERetryCount == 0 {
		req.IKERetryCount = 1
	}

	var lastErr error
	for idx, c := range candidates {
		// Check for cancellation before each attempt
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("ePDG fallback cancelled: %w", ctx.Err())
		default:
		}

		attemptLabel := fmt.Sprintf("candidate %d/%d (%s: %s)", idx+1, len(candidates), c.Source, c.Host)
		swulogger.Info("ePDG 候选地址尝试",
			swulogger.String("device_id", i.deviceID),
			swulogger.String("trace_id", i.traceID),
			swulogger.String("attempt", attemptLabel))

		// DNS resolution
		resolvedIPs, dnsErr := net.LookupHost(c.Host)
		if dnsErr != nil || len(resolvedIPs) == 0 {
			swulogger.Warn("ePDG DNS 解析失败，尝试下一个候选",
				swulogger.String("device_id", i.deviceID),
				swulogger.String("trace_id", i.traceID),
				swulogger.String("host", c.Host),
				swulogger.String("source", c.Source),
				swulogger.Err(dnsErr))
			lastErr = fmt.Errorf("ePDG DNS failed: %s -> %v", c.Host, dnsErr)
			continue
		}

		epdgIP := resolvedIPs[0]

		// Update stage for tunnel connect
		if !i.setStageForGeneration(ctx, generation, StageTunnelConnect, "建立 SWu 隧道", func(s *State) {
			s.LastReason = fmt.Sprintf("tunnel_starting ePDG=%s:%s (source=%s)", epdgIP, c.Port, c.Source)
		}) {
			return nil, fmt.Errorf("pipeline superseded before tunnel attempt")
		}

		// Tunnel establishment
		tunnelCtx, cancel := context.WithCancel(context.Background())
		if !i.installSWUCancel(generation, cancel) {
			cancel()
			return nil, fmt.Errorf("pipeline superseded: SWu cancel install failed")
		}

		swulogger.Info("ePDG 隧道建立中",
			swulogger.String("device_id", i.deviceID),
			swulogger.String("trace_id", i.traceID),
			swulogger.String("epdg_ip", epdgIP),
			swulogger.String("epdg_port", c.Port),
			swulogger.String("source", c.Source))

		snapshot, localIP, dataplane, mobike, err := i.startSWuSession(tunnelCtx, req, epdgIP, c.Port)
		if err != nil {
			reason := classifyTunnelFailure(err)
			swulogger.Warn("ePDG 隧道建立失败，尝试下一个候选",
				swulogger.String("device_id", i.deviceID),
				swulogger.String("trace_id", i.traceID),
				swulogger.String("epdg_ip", epdgIP),
				swulogger.String("source", c.Source),
				swulogger.String("failure_reason", formatTunnelFailureReason(reason, err)),
				swulogger.Err(err))
			cancel()
			// Note: OnTunnelDown is NOT called here. It is called once
			// by runStagedPipeline only after ALL candidates have failed.
			// Calling it per-candidate would trigger premature auto-recovery
			// (via the tunnel_down_auto_recover goroutine), interrupting
			// the fallback mechanism before the next candidate can run.
			lastErr = err
			continue
		}

		// Success
		swulogger.Info("ePDG 隧道建立成功",
			swulogger.String("device_id", i.deviceID),
			swulogger.String("trace_id", i.traceID),
			swulogger.String("epdg_ip", epdgIP),
			swulogger.String("source", c.Source),
			swulogger.String("attempt", fmt.Sprintf("%d/%d", idx+1, len(candidates))))

		return &epdgTunnelResult{
			Snapshot:  snapshot,
			LocalIP:   localIP,
			Dataplane: dataplane,
			Mobike:    mobike,
			EpdgIP:    epdgIP,
			EpdgPort:  c.Port,
			Cancel:    cancel,
		}, nil
	}

	// All candidates exhausted
	return nil, fmt.Errorf("all ePDG candidates failed: %w", lastErr)
}