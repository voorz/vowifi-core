//go:build linux

package runtimehost

import (
	"strings"

	externalswu "github.com/voorz/swu-go/pkg/swu"
	"github.com/voorz/vowifi-core/profiles"
)

func applySimAdminSWuProfile(cfg *externalswu.Config, mcc, mnc string) {
	if cfg == nil {
		return
	}
	// Load carrier-specific IKE/ESP/EAP settings from embedded JSON profiles.
	if p, err := profiles.Lookup(mcc, mnc); err == nil && p != nil {
		if len(p.IKE.Proposals) > 0 {
			cfg.IKEProposals = append([]string(nil), p.IKE.Proposals...)
		}
		if len(p.IKE.ESPProposals) > 0 {
			cfg.ESPProposals = append([]string(nil), p.IKE.ESPProposals...)
		}
		if p.IKE.DPDInterval > 0 {
			cfg.DPDInterval = p.IKE.DPDInterval
		}
		if p.IKE.NATKeepalive > 0 {
			cfg.NATKeepaliveInterval = p.IKE.NATKeepalive
		}
		if p.IKE.ReauthInterval > 0 {
			cfg.ReauthInterval = p.IKE.ReauthInterval
		}
		if p.IKE.IPStack != "" {
			cfg.IPStack = p.IKE.IPStack
		}
		if p.IKE.APN != "" {
			cfg.APN = p.IKE.APN
		}
		if p.EAP.ChallengeMode != "" {
			cfg.AKAChallengeMode = p.EAP.ChallengeMode
		}
		if p.EAP.DeviceModel != "" {
			cfg.DeviceModel = p.EAP.DeviceModel
		}
		if p.EAP.DeviceIdentityEnabled != nil {
			cfg.DeviceIdentityEnabled = p.EAP.DeviceIdentityEnabled
		}
		return
	}
	// Generic fallback: broad compatibility proposal set.
	cfg.IKEProposals = []string{
		"aes256-sha256-prfsha512-modp2048",
		"aes256-sha512-prfsha512-modp2048",
		"aes256-sha256-prfsha256-modp2048",
		"aes256-sha256-prfsha1-modp2048",
		"aes128-sha256-prfsha1-modp2048",
		"aes128-sha256-prfsha256-modp2048",
		"aes128-sha256-modp2048",
	}
	cfg.ESPProposals = []string{"aes256-sha256", "aes128-sha256", "aes256-sha512", "aes128-sha1"}
}

func simAdminIMSTransport(mcc, mnc string) string {
	if p, err := profiles.Lookup(mcc, mnc); err == nil && p != nil {
		if tm := strings.TrimSpace(p.IMS.TransportMode); tm != "" {
			return strings.ToLower(tm)
		}
	}
	return "auto"
}
