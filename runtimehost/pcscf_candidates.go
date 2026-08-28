package runtimehost

import (
	"net"
	"strings"
)

const defaultPCSCFPort = "5060"

// resolvePCSCFCandidates collects registrar endpoints for IMS REGISTER probing.
//
// Priority order:
//  1. Carrier profile override (pcscf_addr) — when set, it takes precedence
//     over all auto-discovered addresses so the operator can pin a specific
//     P-CSCF (e.g. one that returns AKAv1-MD5 instead of plain MD5).
//  2. UE inner IPv6 (when the tunnel assigns an IPv6 inner address, the UE
//     itself often hosts the P-CSCF on its link-local or ULA).
//  3. IKEv2 Configuration Payload P-CSCF addresses (from ePDG).
//
// When the carrier override is set it becomes the *only* candidate — we do not
// mix operator-pinned and auto-discovered addresses to avoid hitting a
// different P-CSCF that may have incompatible auth requirements.
func resolvePCSCFCandidates(snapshot swuSnapshot, override string, localIP net.IP) []string {
	if v := strings.TrimSpace(override); v != "" {
		return []string{v}
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 1+len(snapshot.PCSCFv4)+len(snapshot.PCSCFv6))

	if localIP != nil && localIP.To4() == nil {
		if addr := formatPCSCFAddr(localIP); addr != "" {
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}

	groups := [][]net.IP{snapshot.PCSCFv4, snapshot.PCSCFv6}
	if localIP != nil && localIP.To4() == nil {
		groups = [][]net.IP{snapshot.PCSCFv6, snapshot.PCSCFv4}
	}
	for _, group := range groups {
		for _, ip := range group {
			if ip == nil {
				continue
			}
			addr := formatPCSCFAddr(ip)
			if _, ok := seen[addr]; ok {
				continue
			}
			seen[addr] = struct{}{}
			out = append(out, addr)
		}
	}
	return out
}

func resolvePCSCFAddr(snapshot swuSnapshot, override string, localIP net.IP) string {
	candidates := resolvePCSCFCandidates(snapshot, override, localIP)
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
}

func formatPCSCFAddr(ip net.IP) string {
	return net.JoinHostPort(ip.String(), defaultPCSCFPort)
}
