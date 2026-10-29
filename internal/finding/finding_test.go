package finding

import "testing"

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  Severity
	}{
		{0, SeverityUnknown},
		{0.1, SeverityLow},
		{3.9, SeverityLow},
		{4.0, SeverityMedium},
		{6.9, SeverityMedium},
		{7.0, SeverityHigh},
		{8.9, SeverityHigh},
		{9.0, SeverityCritical},
		{10, SeverityCritical},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%v) = %v, quero %v", c.score, got, c.want)
		}
	}
}

func TestFingerprintIgnoresTitleAndSeverity(t *testing.T) {
	a := Finding{Source: "osv", Rule: "GHSA-1", Package: "jsoup", Version: "1.21.1", Title: "um", Severity: SeverityHigh}
	b := a
	b.Title = "outro texto"
	b.Severity = SeverityLow
	if a.Fingerprint() != b.Fingerprint() {
		t.Fatal("texto e severidade não podem mudar a impressão digital")
	}
	b.Version = "1.23.2"
	if a.Fingerprint() == b.Fingerprint() {
		t.Fatal("versão diferente é outro achado")
	}
}

func TestDedupeKeepsFirst(t *testing.T) {
	a := Finding{Source: "osv", Rule: "GHSA-1", Package: "p", Title: "primeiro"}
	b := Finding{Source: "osv", Rule: "GHSA-1", Package: "p", Title: "segundo"}
	c := Finding{Source: "osv", Rule: "GHSA-2", Package: "p"}
	got := Dedupe([]Finding{a, b, c})
	if len(got) != 2 || got[0].Title != "primeiro" {
		t.Fatalf("Dedupe = %+v", got)
	}
}

func TestCVEsFiltersAliases(t *testing.T) {
	f := Finding{Aliases: []string{"GHSA-xxxx", "CVE-2026-1", "CVE-2026-2"}}
	if got := f.CVEs(); len(got) != 2 || got[0] != "CVE-2026-1" {
		t.Fatalf("CVEs = %v", got)
	}
}
