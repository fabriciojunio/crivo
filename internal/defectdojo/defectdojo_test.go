package defectdojo

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
	"github.com/fabriciojunio/crivo/internal/priority"
)

var agora = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

func triagem(f finding.Finding, kev bool) priority.Triage {
	k := map[string]bool{}
	for _, c := range f.CVEs() {
		k[c] = kev
	}
	return priority.Decide(f, map[string]float64{}, k, agora)
}

func TestSeverityFollowsCrivoPriorityNotTheTool(t *testing.T) {
	media := finding.Finding{Source: "osv", Rule: "GHSA-aaaa", Severity: finding.SeverityMedium,
		Aliases: []string{"GHSA-aaaa", "CVE-2026-0001"}, Package: "npm:lib", Version: "1.0.0"}

	r := Convert([]priority.Triage{triagem(media, true)}, agora)

	f := r.Findings[0]
	if f.Severity != "Critical" {
		t.Fatalf("média no KEV deveria entrar como Critical, veio %q", f.Severity)
	}
	if !strings.Contains(f.Description, "média") || !strings.Contains(f.Description, "KEV") {
		t.Fatalf("a descrição tem que guardar a severidade original e o motivo: %q", f.Description)
	}
	if f.CVE != "CVE-2026-0001" || f.ComponentName != "npm:lib" || f.ComponentVersion != "1.0.0" {
		t.Fatalf("campos do componente errados: %+v", f)
	}
}

func TestUniqueIDIsTheFingerprintSoReimportDoesNotDuplicate(t *testing.T) {
	f := finding.Finding{Source: "semgrep", Rule: "java.sqli", Location: "src/A.java:10", Severity: finding.SeverityHigh}
	tr := triagem(f, false)

	r := Convert([]priority.Triage{tr, tr}, agora)

	if r.Findings[0].UniqueIDFromTool != f.Fingerprint() || r.Findings[0].UniqueIDFromTool != r.Findings[1].UniqueIDFromTool {
		t.Fatalf("o id único tem que ser a impressão digital: %+v", r.Findings)
	}
	if r.Findings[0].Title != "java.sqli em src/A.java:10" || r.Findings[0].FilePath != "src/A.java:10" {
		t.Fatalf("título ou caminho errado: %+v", r.Findings[0])
	}
}

func TestZapIsDynamicEverythingElseStatic(t *testing.T) {
	zap := triagem(finding.Finding{Source: "zap", Rule: "10038", Location: "https://app/x", Severity: finding.SeverityMedium}, false)
	sast := triagem(finding.Finding{Source: "codeql", Rule: "js/xss", Location: "a.js:1", Severity: finding.SeverityHigh}, false)

	r := Convert([]priority.Triage{zap, sast}, agora)

	if !r.Findings[0].DynamicFinding || r.Findings[0].StaticFinding {
		t.Fatalf("ZAP é análise dinâmica: %+v", r.Findings[0])
	}
	if r.Findings[1].DynamicFinding || !r.Findings[1].StaticFinding {
		t.Fatalf("CodeQL é análise estática: %+v", r.Findings[1])
	}
}

func TestWriteProducesTheImporterDocumentWithDate(t *testing.T) {
	var out bytes.Buffer
	tr := triagem(finding.Finding{Source: "osv", Rule: "GHSA-bbbb", Package: "pip:x", Severity: finding.SeverityLow}, false)

	if err := Write(&out, []priority.Triage{tr}, agora); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Findings []map[string]any `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("JSON inválido: %v", err)
	}
	if len(doc.Findings) != 1 || doc.Findings[0]["date"] != "2026-11-05" || doc.Findings[0]["severity"] != "Low" {
		t.Fatalf("documento inesperado: %s", out.String())
	}
}

func TestEmptyTriageStillWritesAValidDocument(t *testing.T) {
	var out bytes.Buffer
	if err := Write(&out, nil, agora); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "{\n  \"findings\": []\n}" {
		t.Fatalf("sem achado o DefectDojo espera lista vazia, não null: %q", out.String())
	}
}
