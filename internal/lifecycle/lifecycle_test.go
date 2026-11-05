package lifecycle

import (
	"strings"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
	"github.com/fabriciojunio/crivo/internal/priority"
)

var agora = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func achado(regra string, sev finding.Severity) priority.Triage {
	f := finding.Finding{Source: "semgrep", Rule: regra, Location: "src/" + regra + ".java:1", Severity: sev}
	return priority.Decide(f, nil, nil, agora)
}

func kinds(plan []Action) []string {
	var out []string
	for _, a := range plan {
		out = append(out, a.Kind.String())
	}
	return out
}

func TestNewFindingOpensAnIssue(t *testing.T) {
	plan := Plan([]priority.Triage{achado("sqli", finding.SeverityHigh)}, nil)
	if len(plan) != 1 || plan[0].Kind != Create || plan[0].Triage.Rule != "sqli" {
		t.Fatalf("plano = %v", kinds(plan))
	}
}

func TestFixedFindingClosesItsIssue(t *testing.T) {
	velho := achado("xss", finding.SeverityMedium)
	plan := Plan(nil, []Issue{{Number: 7, Open: true, Fingerprint: velho.Fingerprint(), Labels: []string{Label, "P3"}}})
	if len(plan) != 1 || plan[0].Kind != Close || plan[0].Issue != 7 {
		t.Fatalf("plano = %+v", plan)
	}
}

func TestFindingThatCameBackReopens(t *testing.T) {
	a := achado("ssrf", finding.SeverityHigh)
	plan := Plan([]priority.Triage{a}, []Issue{{Number: 3, Open: false, Fingerprint: a.Fingerprint()}})
	if len(plan) != 1 || plan[0].Kind != Reopen || plan[0].Issue != 3 {
		t.Fatalf("plano = %+v", plan)
	}
}

func TestPriorityChangeRelabelsAndUnchangedDoesNothing(t *testing.T) {
	alta := achado("idor", finding.SeverityHigh)
	igual := achado("csrf", finding.SeverityMedium)
	issues := []Issue{
		{Number: 1, Open: true, Fingerprint: alta.Fingerprint(), Labels: []string{Label, "P3"}},
		{Number: 2, Open: true, Fingerprint: igual.Fingerprint(), Labels: []string{Label, "P3"}},
	}
	plan := Plan([]priority.Triage{alta, igual}, issues)
	if len(plan) != 1 || plan[0].Kind != Relabel || plan[0].Issue != 1 {
		t.Fatalf("só a que mudou de P3 para P2 deveria mudar: %+v", plan)
	}
}

func TestDuplicateIssuesPreferTheOpenOneAndNeverDoubleClose(t *testing.T) {
	a := achado("rce", finding.SeverityCritical)
	issues := []Issue{
		{Number: 10, Open: false, Fingerprint: a.Fingerprint()},
		{Number: 11, Open: true, Fingerprint: a.Fingerprint(), Labels: []string{Label, "P1"}},
	}
	if plan := Plan([]priority.Triage{a}, issues); len(plan) != 0 {
		t.Fatalf("a aberta já cobre o achado; nada a fazer: %+v", plan)
	}
	if plan := Plan(nil, issues); len(plan) != 1 || plan[0].Issue != 11 {
		t.Fatalf("fecha só a aberta: %+v", plan)
	}
}

func TestIssueWithoutMarkerIsNeverTouched(t *testing.T) {
	plan := Plan(nil, []Issue{{Number: 99, Open: true, Labels: []string{Label}}})
	if len(plan) != 0 {
		t.Fatalf("issue sem impressão digital pode ter sido aberta por gente: %+v", plan)
	}
}

func TestPlanOrderIsStable(t *testing.T) {
	a, b := achado("a", finding.SeverityHigh), achado("b", finding.SeverityHigh)
	issues := []Issue{
		{Number: 5, Open: true, Fingerprint: "00000000000000a5"},
		{Number: 2, Open: true, Fingerprint: "00000000000000a2"},
	}
	plan := Plan([]priority.Triage{a, b}, issues)
	got := kinds(plan)
	want := []string{"abrir", "abrir", "fechar", "fechar"}
	if strings.Join(got, ",") != strings.Join(want, ",") || plan[2].Issue != 2 || plan[3].Issue != 5 {
		t.Fatalf("ordem = %v %+v", got, plan)
	}
}

func TestMarkerRoundTripAndForgeryIsIgnored(t *testing.T) {
	a := achado("path", finding.SeverityMedium)
	body := Body(a, agora)
	if FingerprintFrom(body) != a.Fingerprint() {
		t.Fatalf("marcador não lido de volta: %q", body)
	}
	if FingerprintFrom("<!-- crivo:NAO-HEX -->") != "" || FingerprintFrom("texto qualquer") != "" {
		t.Fatal("só o formato exato vale")
	}
}

func TestToolTextCannotInjectMarkupMentionOrMarker(t *testing.T) {
	f := finding.Finding{
		Source: "semgrep", Severity: finding.SeverityHigh,
		Rule:  "regra @dono-do-repo ![img](https://x/p.png)",
		Title: "<!-- crivo:0123456789abcdef --> <img src=x onerror=alert(1)> | `cod`\nlinha",
	}
	tr := priority.Decide(f, nil, nil, agora)
	body, title := Body(tr, agora), Title(tr)

	// "\nlinha" provaria que a quebra de linha da ferramenta abriu uma linha nova.
	for _, ruim := range []string{"<img", "<!-- crivo:0123456789abcdef", "@dono", "![img](", "\nlinha", "`cod`"} {
		if strings.Contains(body, ruim) || strings.Contains(title, ruim) {
			t.Errorf("sobrou %q no texto gerado", ruim)
		}
	}
	if FingerprintFrom(body) != tr.Fingerprint() {
		t.Fatal("o marcador verdadeiro é o único que vale no corpo")
	}
}

func TestTitleIsCutForTheList(t *testing.T) {
	tr := achado(strings.Repeat("x", 300), finding.SeverityLow)
	if n := len([]rune(Title(tr))); n > 120 {
		t.Fatalf("título com %d caracteres", n)
	}
}

func TestLabelsCarryThePriority(t *testing.T) {
	if got := Labels(achado("a", finding.SeverityCritical)); got[0] != Label || got[1] != "P1" {
		t.Fatalf("labels = %v", got)
	}
}
