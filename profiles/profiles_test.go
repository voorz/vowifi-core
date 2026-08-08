package profiles

import (
	"reflect"
	"testing"
)

// TestEPDGHostsMatchHardcoded verifies that every PLMN with a hardcoded ePDG
// host in simAdminEPDGHost() has the same value in its JSON profile's ike.addr.
func TestEPDGHostsMatchHardcoded(t *testing.T) {
	cases := []struct {
		mcc, mnc string
		want     string
	}{
		{"234", "33", "epdg.epc.mnc033.mcc234.pub.3gppnetwork.org"},
		{"204", "04", "epdg.epc.mnc004.mcc204.pub.3gppnetwork.org"},
		{"204", "4", "epdg.epc.mnc004.mcc204.pub.3gppnetwork.org"},
		{"310", "260", "epdg.epc.mnc260.mcc310.pub.3gppnetwork.org"},
		{"310", "410", "epdg.epc.att.net"},
		{"262", "07", "epdg.epc.mnc007.mcc262.pub.3gppnetwork.org"},
		{"262", "7", "epdg.epc.mnc007.mcc262.pub.3gppnetwork.org"},
		{"530", "05", "epdg.epc.mnc005.mcc530.pub.3gppnetwork.spark.co.nz"},
		{"530", "5", "epdg.epc.mnc005.mcc530.pub.3gppnetwork.spark.co.nz"},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			p, err := Lookup(c.mcc, c.mnc)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if p == nil {
				t.Fatal("profile not found")
			}
			if p.IKE.Addr != c.want {
				t.Errorf("ike.addr = %q, want %q", p.IKE.Addr, c.want)
			}
		})
	}
}

// TestSWuProposalsMatchHardcoded verifies that IKE/ESP proposals in JSON profiles
// match the expected values for carriers with known SWu configurations.
func TestSWuProposalsMatchHardcoded(t *testing.T) {
	cases := []struct {
		mcc, mnc      string
		ikeProposals  []string
		espProposals  []string
		imsTransport  string
	}{
		{
			mcc: "234", mnc: "10",
			ikeProposals: []string{"aes256-sha512-prfsha512-modp2048"},
			espProposals: []string{"aes256-sha512"},
			imsTransport: "auto",
		},
		{
			mcc: "234", mnc: "33",
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
		{
			mcc: "204", mnc: "04",
			ikeProposals: []string{"aes256-sha256-prfsha512-modp2048"},
			espProposals: []string{"aes256-sha256"},
			imsTransport: "tcp",
		},
		{
			mcc: "310", mnc: "260",
			ikeProposals: []string{"aes128-sha256-modp2048"},
			espProposals: []string{"aes128-sha256", "aes128-sha1"},
			imsTransport: "tcp",
		},
		{
			mcc: "310", mnc: "410",
			ikeProposals: []string{"aes128-sha256-modp2048"},
			espProposals: []string{"aes128-sha256"},
			imsTransport: "tcp",
		},
		{
			mcc: "262", mnc: "07",
			ikeProposals: []string{"aes256-sha256-prfsha1-modp2048"},
			espProposals: []string{"aes256-sha256"},
			imsTransport: "tcp",
		},
		{
			mcc: "530", mnc: "05",
			ikeProposals: []string{"aes256-sha256-prfsha256-modp2048"},
			espProposals: []string{"aes256-sha256"},
			imsTransport: "tcp",
		},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			p, err := Lookup(c.mcc, c.mnc)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if p == nil {
				t.Fatal("profile not found")
			}
			if !reflect.DeepEqual(p.IKE.Proposals, c.ikeProposals) {
				t.Errorf("IKE proposals = %v, want %v", p.IKE.Proposals, c.ikeProposals)
			}
			if !reflect.DeepEqual(p.IKE.ESPProposals, c.espProposals) {
				t.Errorf("ESP proposals = %v, want %v", p.IKE.ESPProposals, c.espProposals)
			}
			if p.IMS.TransportMode != c.imsTransport {
				t.Errorf("IMS transport = %q, want %q", p.IMS.TransportMode, c.imsTransport)
			}
		})
	}
}

// TestPLMNAliasesResolved verifies that MNC aliases resolve to the correct
// canonical profile.
func TestPLMNAliasesResolved(t *testing.T) {
	cases := []struct {
		mcc, mnc string
		wantID   string
	}{
		// CMCC aliases
		{"460", "0", "cmcc_46000"},
		{"460", "2", "cmcc_46000"},
		{"460", "4", "cmcc_46000"},
		{"460", "7", "cmcc_46000"},
		// China Unicom aliases
		{"460", "1", "china_unicom_46001"},
		{"460", "6", "china_unicom_46001"},
		{"460", "9", "china_unicom_46001"},
		// China Telecom aliases
		{"460", "3", "china_telecom_46003"},
		{"460", "5", "china_telecom_46003"},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			p, err := Lookup(c.mcc, c.mnc)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if p == nil {
				t.Fatal("profile not found")
			}
			if p.ID != c.wantID {
				t.Errorf("profile ID = %q, want %q", p.ID, c.wantID)
			}
		})
	}
}

// TestMNCNormalization verifies that leading-zero MNC variants resolve correctly.
func TestMNCNormalization(t *testing.T) {
	cases := []struct {
		mcc, mnc string
		wantID   string
	}{
		{"204", "4", "vodafone_nl_20404_ios"},
		{"204", "04", "vodafone_nl_20404_ios"},
		{"204", "004", "vodafone_nl_20404_ios"},
		{"262", "7", "O2_de_26203"},
		{"262", "07", "O2_de_26203"},
		{"530", "5", "spark_nz_53005"},
		{"530", "05", "spark_nz_53005"},
	}
	for _, c := range cases {
		t.Run(c.mcc+"-"+c.mnc, func(t *testing.T) {
			p, err := Lookup(c.mcc, c.mnc)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}
			if p == nil {
				t.Fatal("profile not found")
			}
			if p.ID != c.wantID {
				t.Errorf("profile ID = %q, want %q", p.ID, c.wantID)
			}
		})
	}
}

// TestAllProfilesLoaded verifies that all expected carrier profiles are loaded.
func TestAllProfilesLoaded(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatalf("All() error: %v", err)
	}
	expectedPLMNs := []string{
		"234-10", "234-15", "234-20", "234-30", "234-33",
		"204-4",
		"262-3", "262-7",
		"228-2",
		"310-260", "310-280", "310-410", "310-240",
		"454-0", "454-3",
		"530-1", "530-5", "530-24",
		"460-0", "460-1", "460-3", "460-11",
	}
	for _, plmn := range expectedPLMNs {
		if _, ok := all[plmn]; !ok {
			t.Errorf("missing profile for PLMN %s", plmn)
		}
	}
}

// TestGenericProfile verifies the generic fallback profile loads correctly.
func TestGenericProfile(t *testing.T) {
	g, err := Generic()
	if err != nil {
		t.Fatalf("Generic() error: %v", err)
	}
	if g == nil {
		t.Fatal("generic profile is nil")
	}
	if g.ID == "" {
		t.Error("generic profile has empty ID")
	}
}
