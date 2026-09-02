//go:build linux

package runtimehost

import (
	"strings"

	externalswu "github.com/voorz/swu-go/pkg/swu"
	"github.com/voorz/vowifi-core/runtimehost/carrier"
)

func applySimAdminSWuProfile(cfg *externalswu.Config, mcc, mnc, spn string) {
	if cfg == nil {
		return
	}
	// Load carrier-specific IKE/ESP/EAP settings.
	// Uses LookupWithIdentity which checks: DB user config → embedded profiles/*.json → Generic.
	// This ensures system default profiles work even when no user config is active.
	if p, err := carrier.LookupWithIdentity(mcc, mnc, "", "", spn); err == nil && p != nil {
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
		if p.IKE.TicketRequestEnabled != nil {
			cfg.TicketRequestEnabled = p.IKE.TicketRequestEnabled
		}
		if p.IKE.CPInFirstAuth != nil {
			cfg.CPInFirstAuth = p.IKE.CPInFirstAuth
		}
		if p.IKE.EnableESN {
			cfg.EnableESN = true
		}
		cfg.EAPMACValidation = p.IKE.EAPMACValidation
		if p.IKE.ReplayWindow > 0 {
			cfg.ReplayWindow = p.IKE.ReplayWindow
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

func simAdminIMSTransport(mcc, mnc, spn string) string {
	if p, err := carrier.LookupWithIdentity(mcc, mnc, "", "", spn); err == nil && p != nil {
		if tm := strings.TrimSpace(p.IMS.TransportMode); tm != "" {
			return strings.ToLower(tm)
		}
	}
	return "auto"
}
