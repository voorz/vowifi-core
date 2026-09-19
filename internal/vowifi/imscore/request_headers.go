package imscore

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"crypto/rand"
	"math/big"

	"github.com/voorz/sipgo/sip"
	"github.com/voorz/vowifi-core/runtimehost/voiceclient"
)

// imsMmtelICSIRef is the default ICSI ref for MMTEL voice services.
const imsMmtelICSIRef = "urn%3Aurn-7%3A3gpp-service.ims.icsi.mmtel"

// ─── SecurityClientState ───

// securityClientState holds the IPSec parameters advertised in the
// Security-Client header during initial REGISTER.
type securityClientState struct {
	spiC  uint32
	spiS  uint32
	portC uint16
	portS uint16
}

func newSecurityClientState() securityClientState {
	return securityClientState{
		spiC:  randomNonZeroUint32(),
		spiS:  randomNonZeroUint32(),
		portC: randomEphemeralPort(),
		portS: randomEphemeralPort(),
	}
}

func randomNonZeroUint32() uint32 {
	for {
		n, err := rand.Int(rand.Reader, big.NewInt(0xFFFFFFFF))
		if err != nil {
			// Fallback to time-based if crypto/rand fails.
			return uint32(time.Now().UnixNano())
		}
		v := uint32(n.Int64())
		if v != 0 {
			return v
		}
	}
}

func randomEphemeralPort() uint16 {
	// RFC 6056 ephemeral port range: 49152–65535.
	rangeSize := uint32(65535 - 49152 + 1)
	n, err := rand.Int(rand.Reader, big.NewInt(int64(rangeSize)))
	if err != nil {
		return uint16(49152 + (uint32(time.Now().UnixNano()) % rangeSize))
	}
	return uint16(49152 + uint32(n.Int64()))
}

// ─── IMS Domain Helpers ───

func mccMncFromIMSDomain(domain string) (mcc, mnc string) {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if idx := strings.Index(domain, "mcc"); idx >= 0 {
		end := strings.Index(domain[idx:], ".")
		if end < 0 {
			end = len(domain) - idx
		}
		mcc = strings.TrimSpace(domain[idx+3 : idx+end])
	}
	if idx := strings.Index(domain, "mnc"); idx >= 0 {
		end := strings.Index(domain[idx:], ".")
		if end < 0 {
			end = len(domain) - idx
		}
		mnc = strings.TrimSpace(domain[idx+3 : idx+end])
	}
	return mcc, mnc
}

func plmnFromIMSDomain(domain string) string {
	mcc, mnc := mccMncFromIMSDomain(domain)
	if mcc == "" || mnc == "" {
		return ""
	}
	mncTrimmed := strings.TrimLeft(mnc, "0")
	if mncTrimmed == "" {
		mncTrimmed = "0"
	}
	return mcc + mncTrimmed
}

func netJoinHostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// ─── SIP Header Builders ───

// buildCellularNetworkInfo constructs the Cellular-Network-Info header value.
func buildCellularNetworkInfo(plmn, cellID string) string {
	plmn = strings.TrimSpace(plmn)
	if plmn == "" {
		plmn = "00000"
	}
	eci := strings.TrimSpace(cellID)
	if eci == "" {
		eci = "0000000"
	}
	return fmt.Sprintf("3GPP-E-UTRAN-FDD;utran-cell-id-3gpp=%s%s;cell-info-age=0", plmn, eci)
}

// buildPAccessNetworkInfo constructs the P-Access-Network-Info header value.
func buildPAccessNetworkInfo(profile voiceclient.RegisterProfile) string {
	if profile.IncludePANIAuthenticated {
		return "IEEE-802.11;i-wlan-node-id=000000000000;network-provided"
	}
	return "IEEE-802.11;i-wlan-node-id=000000000000"
}

// buildContactHeader constructs the Contact header for SIP REGISTER and
// non-REGISTER requests, including IMS-specific feature tags.
func (s *Service) buildContactHeader() string {
	transport := s.transportNetwork()
	user := strings.TrimSpace(s.contactUser)
	if user == "" {
		user = s.contactUserFromURI()
	}
	if user == "" {
		user = "anonymous"
	}
	localPort := s.imsCfg.LocalPort
	if localPort <= 0 {
		localPort = 5060
	}
	local := fmt.Sprintf("sip:%s@%s;transport=%s",
		user,
		netJoinHostPort(s.cfg.LocalIP.String(), localPort),
		transport,
	)
	var b strings.Builder
	b.WriteString("<")
	b.WriteString(local)
	b.WriteString(">")
	profile := s.registerProfile
	switch strings.ToLower(strings.TrimSpace(profile.ContactFeatures)) {
	case "phone_xiaomi":
		b.WriteString(`;+g.3gpp.accesstype="wlan1"`)
		b.WriteString(";audio")
		ref := strings.TrimSpace(profile.IcsiRef)
		if ref == "" {
			ref = imsMmtelICSIRef
		}
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(ref)
		b.WriteString(`"`)
		if strings.TrimSpace(s.sipInstanceURN) != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(s.sipInstanceURN)
			b.WriteString(`>"`)
		}
	case "sms_only":
		b.WriteString(`;+g.3gpp.accesstype="IEEE-802.11"`)
		b.WriteString(";+g.3gpp.smsip")
	default:
		b.WriteString(`;+g.3gpp.accesstype="IEEE-802.11"`)
		b.WriteString(";audio")
		b.WriteString(";+g.3gpp.smsip")
		ref := strings.TrimSpace(profile.IcsiRef)
		if ref == "" {
			ref = imsMmtelICSIRef
		}
		b.WriteString(`;+g.3gpp.icsi-ref="`)
		b.WriteString(ref)
		b.WriteString(`"`)
		if strings.TrimSpace(s.sipInstanceURN) != "" {
			b.WriteString(`;+sip.instance="<`)
			b.WriteString(s.sipInstanceURN)
			b.WriteString(`>"`)
		}
	}
	b.WriteString(";expires=")
	b.WriteString(fmt.Sprintf("%d", int(s.contactExpires(profile).Seconds())))
	return b.String()
}

// contactExpires returns the REGISTER expiration duration.
func (s *Service) contactExpires(profile voiceclient.RegisterProfile) time.Duration {
	if profile.RegisterExpirySeconds > 0 {
		return time.Duration(profile.RegisterExpirySeconds) * time.Second
	}
	if s.cfg.RegisterExpirySeconds > 0 {
		return time.Duration(s.cfg.RegisterExpirySeconds) * time.Second
	}
	return 3600 * time.Second
}

// buildSecurityClientHeader constructs the Security-Client header for initial REGISTER.
func buildSecurityClientHeader(profile voiceclient.RegisterProfile, state securityClientState) string {
	alg, ealg, proto, mode := "hmac-sha-1-96", "aes-cbc", "esp", "trans"
	switch strings.ToLower(strings.TrimSpace(profile.SecurityClientFormat)) {
	case "phone_multi":
		combos := []struct{ alg, ealg string }{
			{"hmac-md5-96", "des-ede3-cbc"},
			{"hmac-md5-96", "aes-cbc"},
			{"hmac-md5-96", "null"},
			{"hmac-sha-1-96", "des-ede3-cbc"},
			{"hmac-sha-1-96", "aes-cbc"},
			{"hmac-sha-1-96", "null"},
		}
		parts := make([]string, 0, len(combos))
		for _, combo := range combos {
			parts = append(parts, fmt.Sprintf(
				"ipsec-3gpp; alg=%s; ealg=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
				combo.alg, combo.ealg, state.spiC, state.spiS, state.portC, state.portS,
			))
		}
		return strings.Join(parts, ",")
	case "minimal_spaced":
		return fmt.Sprintf(
			"ipsec-3gpp; alg=%s; ealg=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
			alg, ealg, state.spiC, state.spiS, state.portC, state.portS,
		)
	default:
		return fmt.Sprintf(
			"ipsec-3gpp; alg=%s; ealg=%s; prot=%s; mod=%s; spi-c=%d; spi-s=%d; port-c=%d; port-s=%d",
			alg, ealg, proto, mode, state.spiC, state.spiS, state.portC, state.portS,
		)
	}
}

// buildInitialAuthorization constructs the initial Authorization header for REGISTER.
func buildInitialAuthorization(cfg Config, profile voiceclient.RegisterProfile, requestURI string) string {
	switch strings.ToLower(strings.TrimSpace(profile.InitialAuthorization)) {
	case "none":
		return ""
	case "aka_empty_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
		)
	case "aka_empty":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="",algorithm=AKAv1-MD5`,
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
			quoteSipParam(requestURI),
		)
	case "aka_zero_response":
		return fmt.Sprintf(
			`Digest username="%s",realm="%s",nonce="",uri="%s",response="00000000000000000000000000000000",algorithm=AKAv1-MD5`,
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
			quoteSipParam(requestURI),
		)
	case "aka_zero_response_uri_first":
		return fmt.Sprintf(
			`Digest uri="%s",username="%s",algorithm=AKAv1-MD5,response="00000000000000000000000000000000",realm="%s",nonce=""`,
			quoteSipParam(requestURI),
			quoteSipParam(authorizationUsername(cfg, profile)),
			quoteSipParam(strings.TrimSpace(cfg.Realm)),
		)
	default:
		return ""
	}
}

func authorizationUsername(cfg Config, profile voiceclient.RegisterProfile) string {
	return strings.TrimSpace(cfg.PrivateID)
}

func quoteSipParam(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// Escape backslashes and double quotes per RFC 3261.
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return value
}

// appendHeaderToken appends a token to a SIP header if not already present.
func appendHeaderToken(req *sip.Request, headerName, token string) {
	if req == nil {
		return
	}
	for _, header := range req.GetHeaders(headerName) {
		if header == nil {
			continue
		}
		for _, existing := range strings.Split(header.Value(), ",") {
			if strings.EqualFold(strings.TrimSpace(existing), token) {
				return
			}
		}
	}
	req.AppendHeader(sip.NewHeader(headerName, token))
}

// ─── Transport helpers ───

// contactUserFromURI extracts the user part from basePublicURI.
// If basePublicURI is "sip:user@domain", returns "user".
// Falls back to basePrivateID if no user part is found.
func (s *Service) contactUserFromURI() string {
	publicURI := strings.TrimSpace(s.basePublicURI)
	if strings.HasPrefix(strings.ToLower(publicURI), "sip:") {
		publicURI = publicURI[4:]
	}
	if idx := strings.Index(publicURI, "@"); idx > 0 {
		return publicURI[:idx]
	}
	return strings.TrimSpace(s.basePrivateID)
}

// transportNetwork returns the transport protocol string ("tcp" or "udp").
func (s *Service) transportNetwork() string {
	t := strings.ToLower(strings.TrimSpace(s.imsCfg.Transport))
	if t == "tcp" || t == "udp" {
		return t
	}
	// Default to TCP for IMS over IPSec.
	return "tcp"
}
