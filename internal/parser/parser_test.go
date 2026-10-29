package parser

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/fabriciojunio/crivo/internal/finding"
)

func parseFile(t *testing.T, format Format, name string) []finding.Finding {
	t.Helper()
	data, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(format, bytes.NewReader(data))
	if err != nil {
		t.Fatalf("Parse(%s): %v", name, err)
	}
	return got
}

// Saída real do OSV-Scanner sobre o aplicativo do ConectAgente.
func TestParseOSVRealOutput(t *testing.T) {
	got := parseFile(t, FormatOSV, "osv.json")
	var deepmerge *finding.Finding
	for i := range got {
		if got[i].Rule == "GHSA-gcqx-w48m-w2h4" {
			deepmerge = &got[i]
		}
	}
	if deepmerge == nil {
		t.Fatal("GHSA-gcqx-w48m-w2h4 não foi lido")
	}
	if deepmerge.Package != "npm:deepmerge" || deepmerge.Version != "4.3.1" {
		t.Errorf("pacote = %s %s", deepmerge.Package, deepmerge.Version)
	}
	if deepmerge.CVSS != 5.3 || deepmerge.Severity != finding.SeverityMedium {
		t.Errorf("nota = %v %v", deepmerge.CVSS, deepmerge.Severity)
	}
	if len(deepmerge.CVEs()) != 1 {
		t.Errorf("CVE não veio dos aliases: %v", deepmerge.Aliases)
	}
}

// Saída real do Semgrep sobre um arquivo vulnerável de propósito.
func TestParseSARIFRealOutput(t *testing.T) {
	got := parseFile(t, FormatSARIF, "semgrep.sarif")
	if len(got) != 4 {
		t.Fatalf("achados = %d, quero 4", len(got))
	}
	// Os resultados vêm sem nível e herdam o da regra: "error" vira alta e
	// "warning" vira média, que é o caso da regra de escrita direta na resposta.
	want := map[string]finding.Severity{
		"ajinabraham.njsscan.eval.eval_node.eval_nodejs":                                    finding.SeverityHigh,
		"ajinabraham.njsscan.xss.xss_node.express_xss":                                      finding.SeverityHigh,
		"javascript.express.security.audit.xss.direct-response-write.direct-response-write": finding.SeverityMedium,
	}
	for _, f := range got {
		if f.Source != "Semgrep OSS" || !strings.HasPrefix(f.Location, "vulneravel.js:") {
			t.Errorf("achado mal lido: %+v", f)
		}
		if w, ok := want[f.Rule]; ok && f.Severity != w {
			t.Errorf("%s: severidade %v, quero %v", f.Rule, f.Severity, w)
		}
		if f.Severity == finding.SeverityUnknown {
			t.Errorf("%s: nível da regra não foi herdado", f.Rule)
		}
	}
}

func TestParseSARIFUsesSecuritySeverity(t *testing.T) {
	sarif := `{"runs":[{"tool":{"driver":{"name":"CodeQL","rules":[
	  {"id":"java/sql-injection","properties":{"security-severity":"8.8"}}]}},
	  "results":[{"ruleId":"java/sql-injection","level":"error","message":{"text":"x"}}]}]}`
	got, err := Parse(FormatSARIF, strings.NewReader(sarif))
	if err != nil {
		t.Fatal(err)
	}
	if got[0].CVSS != 8.8 || got[0].Severity != finding.SeverityHigh {
		t.Fatalf("got %+v", got[0])
	}
}

// Relatório real do ZAP baseline contra o AURORA publicado.
func TestParseZAPRealOutput(t *testing.T) {
	got := parseFile(t, FormatZAP, "zap.json")
	var cors bool
	for _, f := range got {
		if f.Rule == "10098" {
			cors = true
			if f.Severity != finding.SeverityMedium || len(f.Aliases) == 0 || f.Aliases[0] != "CWE-264" {
				t.Errorf("CORS mal lido: %+v", f)
			}
		}
	}
	if !cors {
		t.Fatal("alerta 10098 não foi lido")
	}
}

func TestParseRejectsOversizedInput(t *testing.T) {
	big := strings.NewReader(strings.Repeat(" ", MaxInput+1))
	if _, err := Parse(FormatOSV, big); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("erro = %v, quero ErrTooLarge", err)
	}
}

func TestParseRejectsUnknownFormatAndBadJSON(t *testing.T) {
	if _, err := Parse("xml", strings.NewReader("{}")); err == nil {
		t.Error("formato desconhecido deveria falhar")
	}
	if _, err := Parse(FormatOSV, strings.NewReader("{")); err == nil {
		t.Error("JSON quebrado deveria falhar")
	}
}

// O arquivo vem de fora. Qualquer entrada pode dar erro, nenhuma pode derrubar
// o processo.
func FuzzParse(f *testing.F) {
	for _, name := range []string{"osv.json", "semgrep.sarif", "zap.json"} {
		if data, err := os.ReadFile("../../testdata/" + name); err == nil {
			f.Add(data)
		}
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, format := range []Format{FormatSARIF, FormatOSV, FormatZAP} {
			_, _ = Parse(format, bytes.NewReader(data))
		}
	})
}
