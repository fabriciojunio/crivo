package priority

import (
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
)

var now = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

func TestDecideRules(t *testing.T) {
	cve := []string{"CVE-2026-1"}
	cases := []struct {
		name  string
		f     finding.Finding
		epss  float64
		kev   bool
		level Level
	}{
		{"KEV vence severidade baixa", finding.Finding{Severity: finding.SeverityLow, Aliases: cve}, 0, true, P1},
		{"crítica sem exploração", finding.Finding{Severity: finding.SeverityCritical}, 0, false, P1},
		{"média com EPSS alto", finding.Finding{Severity: finding.SeverityMedium, Aliases: cve}, 0.6, false, P1},
		{"alta", finding.Finding{Severity: finding.SeverityHigh}, 0, false, P2},
		{"baixa com EPSS acima da média", finding.Finding{Severity: finding.SeverityLow, Aliases: cve}, 0.2, false, P2},
		{"média", finding.Finding{Severity: finding.SeverityMedium}, 0, false, P3},
		{"desconhecida", finding.Finding{}, 0, false, P4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Decide(c.f, map[string]float64{"CVE-2026-1": c.epss}, map[string]bool{"CVE-2026-1": c.kev}, now)
			if got.Level != c.level {
				t.Fatalf("nível = %v (%s), quero %v", got.Level, got.Reason, c.level)
			}
			if !got.Due.Equal(now.Add(SLA[c.level])) {
				t.Fatalf("prazo = %v", got.Due)
			}
		})
	}
}

func TestDecideIgnoresNonCVEAliases(t *testing.T) {
	// EPSS e KEV são indexados por CVE; um GHSA com o mesmo número não pode
	// herdar a nota.
	f := finding.Finding{Severity: finding.SeverityLow, Aliases: []string{"GHSA-x"}}
	got := Decide(f, map[string]float64{"GHSA-x": 0.9}, map[string]bool{"GHSA-x": true}, now)
	if got.Level != P4 || got.KEV {
		t.Fatalf("got %+v", got)
	}
}

func TestSortByLevelThenEPSS(t *testing.T) {
	all := []Triage{
		{Level: P3, EPSS: 0.9},
		{Level: P1, EPSS: 0.1},
		{Level: P1, EPSS: 0.7},
	}
	Sort(all)
	if all[0].EPSS != 0.7 || all[1].EPSS != 0.1 || all[2].Level != P3 {
		t.Fatalf("ordem = %+v", all)
	}
}
