package policy

import (
	"testing"
)

// TestResolveIMSRegisterTemplateJSONFirst verifies that the JSON-first path in
// ResolveIMSRegisterTemplate produces templates with the same ID as the
// hardcoded fallback for every known PLMN.
func TestResolveIMSRegisterTemplateJSONFirst(t *testing.T) {
	cases := []struct {
		mcc, mnc string
		wantID   string
	}{
		{"234", "30", "ee_uk_23430"},
		{"234", "33", "cmlink_uk_23433"},
		{"234", "15", "vodafone_uk_23415"},
		{"234", "10", "giffgaff"},
		{"234", "20", "three_uk_23420"},
		{"310", "260", "T-Mobile_260"},
		{"310", "240", "T-Mobile_240"},
		{"310", "280", "att_310280"},
		{"310", "410", "LycaMobile_310410"},
		{"204", "4", "vodafone_nl_20404_ios"},
		{"530", "5", "spark_nz_53005"},
		{"530", "24", "2degrees_nz_53024"},
		{"530", "1", "one_nz_53001"},
		{"262", "3", "O2_de_26203"},
		{"262", "7", "O2_de_26203"},
		{"454", "3", "three_hk_454003"},
		{"454", "0", "csl_454000"},
		{"228", "2", "sunrise_22802"},
		{"460", "0", "cmcc_46000"},
		{"460", "1", "china_unicom_46001"},
		{"460", "3", "china_telecom_46003"},
	}
	for _, c := range cases {
		t.Run(c.mcc+":"+c.mnc, func(t *testing.T) {
			tmpl := ResolveIMSRegisterTemplate(c.mcc, c.mnc)
			if tmpl.ID != c.wantID {
				t.Errorf("template ID = %q, want %q", tmpl.ID, c.wantID)
			}
		})
	}
}

// TestResolveIMSRegisterTemplateJSONMatchesHardcoded verifies that for a subset
// of carriers with rich hardcoded templates, the JSON-derived template matches
// the hardcoded one on critical fields.
func TestResolveIMSRegisterTemplateJSONMatchesHardcoded(t *testing.T) {
	// Vodafone UK: rich template with many fields
	t.Run("VodafoneUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "15")
		want := VodafoneUKTemplate()

		if tmpl.ID != want.ID {
			t.Errorf("ID = %q, want %q", tmpl.ID, want.ID)
		}
		if tmpl.SecAgreeMode != want.SecAgreeMode {
			t.Errorf("SecAgreeMode = %q, want %q", tmpl.SecAgreeMode, want.SecAgreeMode)
		}
		if tmpl.UsePlainDigestPlaceholder != want.UsePlainDigestPlaceholder {
			t.Errorf("UsePlainDigestPlaceholder = %v, want %v", tmpl.UsePlainDigestPlaceholder, want.UsePlainDigestPlaceholder)
		}
		if tmpl.IncludePANI != want.IncludePANI {
			t.Errorf("IncludePANI = %v, want %v", tmpl.IncludePANI, want.IncludePANI)
		}
		if tmpl.OmitRoute != want.OmitRoute {
			t.Errorf("OmitRoute = %v, want %v", tmpl.OmitRoute, want.OmitRoute)
		}
		if tmpl.UserAgent != want.UserAgent {
			t.Errorf("UserAgent = %q, want %q", tmpl.UserAgent, want.UserAgent)
		}
		if tmpl.SupportedHeader != want.SupportedHeader {
			t.Errorf("SupportedHeader = %q, want %q", tmpl.SupportedHeader, want.SupportedHeader)
		}
	})

	// EE UK / CMLink UK: EE base template
	t.Run("CMLinkUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "33")
		want := CMlinkUKTemplate()

		if tmpl.ID != want.ID {
			t.Errorf("ID = %q, want %q", tmpl.ID, want.ID)
		}
		if tmpl.SecAgreeMode != want.SecAgreeMode {
			t.Errorf("SecAgreeMode = %q, want %q", tmpl.SecAgreeMode, want.SecAgreeMode)
		}
		if tmpl.IncludePANI != want.IncludePANI {
			t.Errorf("IncludePANI = %v, want %v", tmpl.IncludePANI, want.IncludePANI)
		}
		if tmpl.RequireSecAgree != want.RequireSecAgree {
			t.Errorf("RequireSecAgree = %v, want %v", tmpl.RequireSecAgree, want.RequireSecAgree)
		}
		if tmpl.UserAgent != want.UserAgent {
			t.Errorf("UserAgent = %q, want %q", tmpl.UserAgent, want.UserAgent)
		}
		if tmpl.FixedPANI != want.FixedPANI {
			t.Errorf("FixedPANI = %q, want %q", tmpl.FixedPANI, want.FixedPANI)
		}
	})

	// Three UK: sec-agree required, specific security mechanisms
	t.Run("ThreeUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "20")
		want := ThreeUKTemplate()

		if tmpl.ID != want.ID {
			t.Errorf("ID = %q, want %q", tmpl.ID, want.ID)
		}
		if tmpl.RequireSecAgree != want.RequireSecAgree {
			t.Errorf("RequireSecAgree = %v, want %v", tmpl.RequireSecAgree, want.RequireSecAgree)
		}
		if tmpl.ProxyRequireSecAgree != want.ProxyRequireSecAgree {
			t.Errorf("ProxyRequireSecAgree = %v, want %v", tmpl.ProxyRequireSecAgree, want.ProxyRequireSecAgree)
		}
		if len(tmpl.SecurityClientMechanisms) != len(want.SecurityClientMechanisms) {
			t.Errorf("SecurityClientMechanisms len = %d, want %d", len(tmpl.SecurityClientMechanisms), len(want.SecurityClientMechanisms))
		}
	})

	// ATT: register policy with status codes
	t.Run("ATT", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("310", "280")
		want := ATTTemplate()

		if tmpl.ID != want.ID {
			t.Errorf("ID = %q, want %q", tmpl.ID, want.ID)
		}
		if tmpl.EnableInitialRejectFallback != want.EnableInitialRejectFallback {
			t.Errorf("EnableInitialRejectFallback = %v, want %v", tmpl.EnableInitialRejectFallback, want.EnableInitialRejectFallback)
		}
		if !sliceEqual(tmpl.RegisterPolicy.TemporaryStatusCodes, want.RegisterPolicy.TemporaryStatusCodes) {
			t.Errorf("TemporaryStatusCodes = %v, want %v", tmpl.RegisterPolicy.TemporaryStatusCodes, want.RegisterPolicy.TemporaryStatusCodes)
		}
		if !sliceEqual(tmpl.RegisterPolicy.InitialRejectFallbackStatusCodes, want.RegisterPolicy.InitialRejectFallbackStatusCodes) {
			t.Errorf("InitialRejectFallbackStatusCodes = %v, want %v", tmpl.RegisterPolicy.InitialRejectFallbackStatusCodes, want.RegisterPolicy.InitialRejectFallbackStatusCodes)
		}
	})
}

func sliceEqual(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
