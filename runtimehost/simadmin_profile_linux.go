//go:build linux

package runtimehost

import (
	"fmt"
	"strings"

	externalswu "github.com/voorz/swu-go/pkg/swu"
	"github.com/voorz/vowifi-core/profiles"
)

type simAdminSWuProfile struct {
	ikeProposals []string
	espProposals []string
	imsTransport string
}

var simAdminSWuProfiles = map[string]simAdminSWuProfile{
	// giffgaff (O2 MVNO) — IKE/ESP 提议对齐 SimAdmin GB_EE_23433
	"234-10": {
		ikeProposals: []string{
			"aes256-sha512-prfsha512-modp2048",
		},
		espProposals: []string{"aes256-sha512"},
		imsTransport: "auto",
	},
	"234-33": {
		ikeProposals: []string{
			"aes128-sha256-modp2048",
			"aes128-sha256-prfsha1-modp2048",
			"aes128-sha1-modp2048",
			"aes256-sha256-prfsha1-modp2048",
			"aes256-sha256-modp2048",
		},
		espProposals: []string{"aes128-sha256", "aes128-sha1", "aes256-sha512"},
		imsTransport: "auto",
	},
	"204-04": {
		ikeProposals: []string{"aes256-sha256-prfsha512-modp2048"},
		espProposals: []string{"aes256-sha256"},
		imsTransport: "tcp",
	},
	"310-260": {
		ikeProposals: []string{"aes128-sha256-modp2048"},
		espProposals: []string{"aes128-sha256", "aes128-sha1"},
		imsTransport: "tcp",
	},
	"310-410": {
		ikeProposals: []string{"aes128-sha256-modp2048"},
		espProposals: []string{"aes128-sha256"},
		imsTransport: "tcp",
	},
	"262-07": {
		ikeProposals: []string{"aes256-sha256-prfsha1-modp2048"},
		espProposals: []string{"aes256-sha256"},
		imsTransport: "tcp",
	},
	"530-05": {
		ikeProposals: []string{"aes256-sha256-prfsha256-modp2048"},
		espProposals: []string{"aes256-sha256"},
		imsTransport: "tcp",
	},
}

func applySimAdminSWuProfile(cfg *externalswu.Config, mcc, mnc string) {
	if cfg == nil {
		return
	}
	// JSON-first: try embedded profiles before falling back to hardcoded map.
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
	profile, ok := simAdminSWuProfiles[simAdminProfileKey(mcc, mnc)]
	if !ok {
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
		return
	}
	cfg.IKEProposals = append([]string(nil), profile.ikeProposals...)
	cfg.ESPProposals = append([]string(nil), profile.espProposals...)
}

func simAdminProfileKey(mcc, mnc string) string {
	mcc = strings.TrimSpace(mcc)
	mnc = strings.TrimSpace(mnc)
	if len(mnc) > 2 {
		mnc = strings.TrimLeft(mnc, "0")
	}
	if mnc == "" {
		mnc = "0"
	}
	if len(mnc) == 1 {
		mnc = "0" + mnc
	}
	return fmt.Sprintf("%s-%s", mcc, mnc)
}

func simAdminIMSTransport(mcc, mnc string) string {
	// JSON-first: try embedded profiles before falling back to hardcoded map.
	if p, err := profiles.Lookup(mcc, mnc); err == nil && p != nil {
		if tm := strings.TrimSpace(p.IMS.TransportMode); tm != "" {
			return strings.ToLower(tm)
		}
	}
	profile, ok := simAdminSWuProfiles[simAdminProfileKey(mcc, mnc)]
	if !ok || strings.TrimSpace(profile.imsTransport) == "" {
		return "auto"
	}
	return strings.ToLower(strings.TrimSpace(profile.imsTransport))
}
