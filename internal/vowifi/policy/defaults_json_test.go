package policy

import (
	"sync"
	"testing"

	"github.com/voorz/vowifi-core/runtimehost/carrier"
)

// mockCarrierIndexProvider implements carrier.CarrierIndexProvider for tests.
// It returns hardcoded carrier_index entries for known PLMNs so that
// LookupWithIdentity can resolve embedded profiles without a DB.
type mockCarrierIndexProvider struct {
	once sync.Once
	data map[string]string // plmnKey → raw JSON
}

func newMockCarrierIndexProvider() *mockCarrierIndexProvider {
	p := &mockCarrierIndexProvider{}
	p.build()
	return p
}

func (p *mockCarrierIndexProvider) GetCarrierIndexRawJSON(plmnKey string) string {
	if p.data == nil {
		p.build()
	}
	return p.data[plmnKey]
}

// build populates carrier index entries for all PLMNs used in tests.
// The "brand" values are chosen so that brandToFilename(brand, iso)
// resolves to the correct embedded profile filename.
func (p *mockCarrierIndexProvider) build() {
	p.data = map[string]string{
		"234-33": `{"mcc":"234","mnc":"33","country":{"name":"United Kingdom","iso":"GB","code":"234","region":"Europe"},"operators":[{"brand":"EE","operator":"Everything Everywhere","subs":[{"brand":"EE","names":["EE","Everything Everywhere"],"gid1":"","gid2":""},{"brand":"CMLink UK","names":["CMLink","CMlink"],"gid1":"","gid2":""},{"brand":"CTExcel UK","names":["CTExcel"],"gid1":"","gid2":""}]}]}`,
		"234-15": `{"mcc":"234","mnc":"15","country":{"name":"United Kingdom","iso":"GB","code":"234","region":"Europe"},"operators":[{"brand":"Vodafone UK","operator":"Vodafone","subs":[]}]}`,
		"234-30": `{"mcc":"234","mnc":"30","country":{"name":"United Kingdom","iso":"GB","code":"234","region":"Europe"},"operators":[{"brand":"BT","operator":"BT","subs":[]}]}`,
		"234-10": `{"mcc":"234","mnc":"10","country":{"name":"United Kingdom","iso":"GB","code":"234","region":"Europe"},"operators":[{"brand":"O2","operator":"Telefonica","subs":[{"brand":"O2 Giffgaff UK","names":["giffgaff"],"gid1":"","gid2":""}]}]}`,
		"234-20": `{"mcc":"234","mnc":"20","country":{"name":"United Kingdom","iso":"GB","code":"234","region":"Europe"},"operators":[{"brand":"3","operator":"Three UK","subs":[]}]}`,
		"310-260": `{"mcc":"310","mnc":"260","country":{"name":"United States","iso":"US","code":"310","region":"Americas"},"operators":[{"brand":"tmobile US","operator":"T-Mobile","subs":[]}]}`,
		"310-240": `{"mcc":"310","mnc":"240","country":{"name":"United States","iso":"US","code":"310","region":"Americas"},"operators":[{"brand":"tmobile US","operator":"T-Mobile","subs":[]}]}`,
		"310-280": `{"mcc":"310","mnc":"280","country":{"name":"United States","iso":"US","code":"310","region":"Americas"},"operators":[{"brand":"AT&T","operator":"AT&T","subs":[]}]}`,
		"310-410": `{"mcc":"310","mnc":"410","country":{"name":"United States","iso":"US","code":"310","region":"Americas"},"operators":[{"brand":"LycaMobile","operator":"Lycamobile","subs":[]}]}`,
		"204-4":  `{"mcc":"204","mnc":"4","country":{"name":"Netherlands","iso":"NL","code":"204","region":"Europe"},"operators":[{"brand":"Vodafone","operator":"Vodafone","subs":[]}]}`,
		"530-5":   `{"mcc":"530","mnc":"5","country":{"name":"New Zealand","iso":"NZ","code":"530","region":"Oceania"},"operators":[{"brand":"spark NZ","operator":"Spark","subs":[]}]}`,
		"530-24":  `{"mcc":"530","mnc":"24","country":{"name":"New Zealand","iso":"NZ","code":"530","region":"Oceania"},"operators":[{"brand":"2degrees NZ","operator":"2degrees","subs":[]}]}`,
		"530-1":   `{"mcc":"530","mnc":"1","country":{"name":"New Zealand","iso":"NZ","code":"530","region":"Oceania"},"operators":[{"brand":"one NZ","operator":"One NZ","subs":[]}]}`,
		"262-3":   `{"mcc":"262","mnc":"3","country":{"name":"Germany","iso":"DE","code":"262","region":"Europe"},"operators":[{"brand":"O2","operator":"Telefonica","subs":[]}]}`,
		"262-7":   `{"mcc":"262","mnc":"7","country":{"name":"Germany","iso":"DE","code":"262","region":"Europe"},"operators":[{"brand":"O2","operator":"Telefonica","subs":[]}]}`,
		"454-3":   `{"mcc":"454","mnc":"3","country":{"name":"Hong Kong","iso":"HK","code":"454","region":"Asia"},"operators":[{"brand":"3","operator":"Three HK","subs":[]}]}`,
		"454-0":   `{"mcc":"454","mnc":"0","country":{"name":"Hong Kong","iso":"HK","code":"454","region":"Asia"},"operators":[{"brand":"CSL","operator":"CSL","subs":[]}]}`,
		"228-2":   `{"mcc":"228","mnc":"2","country":{"name":"Switzerland","iso":"CH","code":"228","region":"Europe"},"operators":[{"brand":"Sunrise","operator":"Sunrise","subs":[]}]}`,
		"460-0":   `{"mcc":"460","mnc":"0","country":{"name":"China","iso":"CN","code":"460","region":"Asia"},"operators":[{"brand":"CMCC","operator":"China Mobile","subs":[]}]}`,
		"460-1":   `{"mcc":"460","mnc":"1","country":{"name":"China","iso":"CN","code":"460","region":"Asia"},"operators":[{"brand":"unicom CN","operator":"China Unicom","subs":[]}]}`,
		"460-3":   `{"mcc":"460","mnc":"3","country":{"name":"China","iso":"CN","code":"460","region":"Asia"},"operators":[{"brand":"chinatelecom CN","operator":"China Telecom","subs":[]}]}`,
	}
}

// TestResolveIMSRegisterTemplateJSONFirst verifies that the JSON-first path in
// ResolveIMSRegisterTemplate produces templates with the expected profile ID
// for known PLMNs. Uses a mock CarrierIndexProvider to resolve embedded profiles.
func TestResolveIMSRegisterTemplateJSONFirst(t *testing.T) {
	// Inject mock provider for the duration of this test
	provider := newMockCarrierIndexProvider()
	carrier.SetCarrierIndexProvider(provider)
	defer carrier.SetCarrierIndexProvider(nil)

	cases := []struct {
		mcc, mnc string
		wantID   string
	}{
		{"234", "33", "ee_uk"},
		{"234", "15", "vodafone_uk"},
		{"234", "10", "o2_uk"},
		{"234", "20", "3_uk"},
		{"310", "260", "tmobile_us"},
		{"310", "240", "tmobile_us"},
		{"310", "280", "att_us"},
		{"204", "4", "vodafone_nl"},
		{"530", "24", "2degrees_nz"},
		{"262", "3", "o2_de"},
		{"262", "7", "o2_de"},
		{"454", "3", "3_hk"},
		{"454", "0", "csl_hk"},
		{"228", "2", "sunrise_ch"},
		{"460", "0", "cmcc_cn"},
		{"460", "1", "unicom_cn"},
	}
	for _, c := range cases {
		t.Run(c.mcc+":"+c.mnc, func(t *testing.T) {
			tmpl := ResolveIMSRegisterTemplate(c.mcc, c.mnc, "")
			if tmpl.ID != c.wantID {
				t.Errorf("template ID = %q, want %q", tmpl.ID, c.wantID)
			}
		})
	}
}

// TestResolveIMSRegisterTemplateJSONFields verifies that JSON-derived templates
// for key carriers have the expected carrier-specific field values.
func TestResolveIMSRegisterTemplateJSONFields(t *testing.T) {
	provider := newMockCarrierIndexProvider()
	carrier.SetCarrierIndexProvider(provider)
	defer carrier.SetCarrierIndexProvider(nil)

	// Vodafone UK: rich template with many fields
	t.Run("VodafoneUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "15", "")

		if tmpl.ID != "vodafone_uk" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "vodafone_uk")
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

	// EE UK (base): returned when no SPN is provided
	t.Run("EEUK_Base", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "33", "")

		if tmpl.ID != "ee_uk" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "ee_uk")
		}
		if tmpl.SecAgreeMode != "on" {
			t.Errorf("SecAgreeMode = %q, want %q", tmpl.SecAgreeMode, "on")
		}
		if tmpl.IncludePANI {
			t.Error("IncludePANI = true, want false")
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

	// CMLink UK: returned when SPN matches "cmlink"
	t.Run("CMLinkUK_SPN", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "33", "CMLink")

		if tmpl.ID != "cmlink_uk" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "cmlink_uk")
		}
	})

	// CTExcel UK: returned when SPN matches "ctexcel"
	t.Run("CTExcelUK_SPN", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "33", "CTExcel")

		if tmpl.ID != "ctexcel_uk" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "ctexcel_uk")
		}
	})

	// Three UK: sec-agree required, specific security mechanisms
	t.Run("ThreeUK", func(t *testing.T) {
		tmpl := ResolveIMSRegisterTemplate("234", "20", "")

		if tmpl.ID != "3_uk" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "3_uk")
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
		tmpl := ResolveIMSRegisterTemplate("310", "280", "")

		if tmpl.ID != "att_us" {
			t.Errorf("ID = %q, want %q", tmpl.ID, "att_us")
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
