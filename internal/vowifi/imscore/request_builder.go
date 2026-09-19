package imscore

import (
	"fmt"
	"strings"

	"github.com/voorz/sipgo/sip"
)

// newRequest builds a non-REGISTER SIP request with all IMS security headers
// (Security-Verify, Supported, Allow, etc.) properly set.
//
// REGISTER requests are NOT supported here — use buildRegisterRequest (initial
// registration) or buildRefreshRegister (refresh) instead.
//
// For non-REGISTER requests (MESSAGE, SUBSCRIBE, INVITE, etc.):
//   - Adds Service-Route as Route headers
//   - Adds Security-Verify
//   - Routes through P-CSCF
func (s *Service) newRequest(method sip.RequestMethod, target string, initialRegister bool) (*sip.Request, error) {
	if method == sip.REGISTER {
		return nil, fmt.Errorf("imscore: newRequest does not support REGISTER; use buildRegisterRequest or buildRefreshRegister instead")
	}
	recipient, err := s.requestURI(target)
	if err != nil {
		return nil, err
	}
	req := sip.NewRequest(method, recipient)

	// Service-Route (as Route headers) applies to all non-REGISTER requests
	// (MESSAGE, SUBSCRIBE, INVITE, etc.) per IMS routing rules.
	{
		for _, route := range s.serviceRoutes {
			if value := strings.TrimSpace(route); value != "" {
				req.AppendHeader(sip.NewHeader("Route", value))
			}
		}
	}

	if method == sip.MESSAGE {
		if identity := strings.TrimSpace(s.basePublicURI); identity != "" {
			req.AppendHeader(sip.NewHeader("P-Preferred-Identity", "<"+identity+">"))
		}
	}

	req.AppendHeader(sip.NewHeader("From", "<"+s.basePublicURI+">;tag="+sip.GenerateTagN(16)))

	toURI := s.registerToURI()
	if method == sip.MESSAGE {
		toURI = recipient.String()
	}
	req.AppendHeader(sip.NewHeader("To", "<"+toURI+">"))
	req.AppendHeader(sip.NewHeader("Contact", s.buildContactHeader()))

	// Security-Verify must be present on all protected non-REGISTER requests.
	if verify := strings.TrimSpace(s.verifyHeader); verify != "" {
		req.AppendHeader(sip.NewHeader("Security-Verify", verify))
		if s.registerProfile.IncludeRequireSecAgree {
			appendHeaderToken(req, "Require", "sec-agree")
			appendHeaderToken(req, "Proxy-Require", "sec-agree")
		}
	}
	if v := strings.TrimSpace(s.registerProfile.VoiceSupportedHeader); v != "" {
		req.AppendHeader(sip.NewHeader("Supported", v))
	}
	if v := strings.TrimSpace(s.registerProfile.VoiceAllowHeader); v != "" {
		req.AppendHeader(sip.NewHeader("Allow", v))
	} else {
		req.AppendHeader(sip.NewHeader("Allow", "INVITE,ACK,CANCEL,BYE,UPDATE,PRACK,MESSAGE,REFER,NOTIFY,INFO,OPTIONS"))
	}
	if v := strings.TrimSpace(s.registerProfile.VoiceAcceptContact); v != "" {
		req.AppendHeader(sip.NewHeader("Accept-Contact", v))
	}
	if v := strings.TrimSpace(s.registerProfile.VoicePPreferredService); v != "" {
		req.AppendHeader(sip.NewHeader("P-Preferred-Service", v))
	}

	if s.transportNetwork() == "udp" {
		req.SetTransport("UDP")
	} else {
		req.SetTransport("TCP")
	}

	// Route through the P-CSCF.
	if strings.TrimSpace(s.cfg.PCSCFAddr) != "" {
		req.SetDestination(s.cfg.PCSCFAddr)
	}

	return req, nil
}

func (s *Service) registerToURI() string {
	return strings.TrimSpace(s.basePublicURI)
}

func (s *Service) requestURI(target string) (sip.Uri, error) {
	raw := strings.TrimSpace(target)
	if !strings.HasPrefix(strings.ToLower(raw), "sip:") && !strings.HasPrefix(strings.ToLower(raw), "sips:") {
		raw = "sip:" + raw
	}
	recipient := sip.Uri{}
	if err := sip.ParseUri(raw, &recipient); err != nil {
		return sip.Uri{}, fmt.Errorf("imscore: parse target uri %q: %w", raw, err)
	}
	return recipient, nil
}
