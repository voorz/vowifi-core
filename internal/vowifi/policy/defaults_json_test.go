package policy

import (
	"testing"
)

// TestResolveIMSRegisterTemplateJSONFirst verifies that the JSON-first path in
// ResolveIMSRegisterTemplate produces templates with the expected ID for every
// known PLMN.
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

// TestResolveIMSRegisterTemplateJSONFields verifies that JSON-derived templates
// for key carriers have the expected carrier-specific field values.
func TestResolveIMSRegisterTemplateJSONFields(t *testing.T) {
	// Vodafone UK: rich template with many fields
	t.Run("VodafoneUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "15")

		if tmpl.ID != "vodafone_uk_23415" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "vodafone_uk_23415")
		}
		if tmpl.SecAgreeMode != "on" {
			t.Errorf("SecAgreeMode = %q, want %q", tmpl.SecAgreeMode, "on")
		}
		if !tmpl.UsePlainDigestPlaceholder {
			t.Error("UsePlainDigestPlaceholder = false, want true")
		}
		if tmpl.IncludePANI {
			t.Error("IncludePANI = true, want false")
		}
		if !tmpl.OmitRoute {
			t.Error("OmitRoute = false, want true")
		}
		if tmpl.UserAgent != "Vodafone VOLTE Qualcomm" {
			t.Errorf("UserAgent = %q, want %q", tmpl.UserAgent, "Vodafone VOLTE Qualcomm")
		}
		if tmpl.SupportedHeader != "path,sec-agree" {
			t.Errorf("SupportedHeader = %q, want %q", tmpl.SupportedHeader, "path,sec-agree")
		}
	})

	// EE UK / CMLink UK: EE base template
	t.Run("CMLinkUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "33")

		if tmpl.ID != "cmlink_uk_23433" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "cmlink_uk_23433")
		}
		if tmpl.SecAgreeMode != "on" {
			t.Errorf("SecAgreeMode = %q, want %q", tmpl.SecAgreeMode, "on")
		}
		if !tmpl.IncludePANI {
			t.Error("IncludePANI = false, want true")
		}
		if !tmpl.RequireSecAgree {
			t.Error("RequireSecAgree = false, want true")
		}
		if tmpl.UserAgent != "EE VoWiFi UE/1.0 (Qualcomm IMS)" {
			t.Errorf("UserAgent = %q, want %q", tmpl.UserAgent, "EE VoWiFi UE/1.0 (Qualcomm IMS)")
		}
		if tmpl.FixedPANI == "" {
			t.Error("FixedPANI is empty, expected non-empty")
		}
	})

	// Three UK: sec-agree required, specific security mechanisms
	t.Run("ThreeUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "20")

		if tmpl.ID != "three_uk_23420" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "three_uk_23420")
		}
		if !tmpl.RequireSecAgree {
			t.Error("RequireSecAgree = false, want true")
		}
		if !tmpl.ProxyRequireSecAgree {
			t.Error("ProxyRequireSecAgree = false, want true")
		}
		if len(tmpl.SecurityClientMechanisms) != 1 {
			t.Errorf("SecurityClientMechanisms len = %d, want 1", len(tmpl.SecurityClientMechanisms))
		}
	})

	// ATT: register policy with status codes
	t.Run("ATT", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("310", "280")

		if tmpl.ID != "att_310280" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "att_310280")
		}
		if !tmpl.EnableInitialRejectFallback {
			t.Error("EnableInitialRejectFallback = false, want true")
		}
		if !sliceEqual(tmpl.RegisterPolicy.TemporaryStatusCodes, []int{403, 480, 500, 503, 504}) {
			t.Errorf("TemporaryStatusCodes = %v, want [403 480 500 503 504]", tmpl.RegisterPolicy.TemporaryStatusCodes)
		}
		if !sliceEqual(tmpl.RegisterPolicy.InitialRejectFallbackStatusCodes, []int{400, 403, 480, 500}) {
			t.Errorf("InitialRejectFallbackStatusCodes = %v, want [400 403 480 500]", tmpl.RegisterPolicy.InitialRejectFallbackStatusCodes)
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
