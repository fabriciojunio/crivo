package accept

import (
	"strings"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
)

const arquivo = `[
  {"regra":"GHSA-1","pacote":"npm:deepmerge","motivo":"só nos testes","ate":"2026-12-31"},
  {"regra":"GHSA-2","motivo":"não se aplica","ate":"2026-01-01"}
]`

func TestMatchValidExpiredAndOtherPackage(t *testing.T) {
	list, err := Load(strings.NewReader(arquivo))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

	ok, _ := list.Match(finding.Finding{Rule: "GHSA-1", Package: "npm:deepmerge"}, now)
	if !ok {
		t.Error("aceite válido não casou")
	}
	ok, _ = list.Match(finding.Finding{Rule: "GHSA-1", Package: "npm:outro"}, now)
	if ok {
		t.Error("aceite de um pacote não vale para outro")
	}
	ok, expired := list.Match(finding.Finding{Rule: "GHSA-2", Package: "qualquer"}, now)
	if ok || expired == nil || expired.Rule != "GHSA-2" {
		t.Errorf("aceite vencido deveria voltar como aberto e ser apontado: ok=%v expired=%v", ok, expired)
	}
}

func TestAcceptanceValidUntilEndOfDay(t *testing.T) {
	list, _ := Load(strings.NewReader(arquivo))
	lastMinute := time.Date(2026, 12, 31, 23, 59, 0, 0, time.UTC)
	if ok, _ := list.Match(finding.Finding{Rule: "GHSA-1", Package: "npm:deepmerge"}, lastMinute); !ok {
		t.Fatal("o aceite vale até o fim do dia informado")
	}
}

func TestLoadRejectsIncompleteAcceptances(t *testing.T) {
	for name, body := range map[string]string{
		"sem motivo":     `[{"regra":"X","motivo":" ","ate":"2026-12-31"}]`,
		"sem data":       `[{"regra":"X","motivo":"m"}]`,
		"data inválida":  `[{"regra":"X","motivo":"m","ate":"31/12/2026"}]`,
		"campo estranho": `[{"regra":"X","motivo":"m","ate":"2026-12-31","para_sempre":true}]`,
	} {
		if _, err := Load(strings.NewReader(body)); err == nil {
			t.Errorf("%s: deveria recusar", name)
		}
	}
}
