// Package defectdojo escreve a triagem no formato de importação genérica do
// DefectDojo ("Generic Findings Import"), para quem gerencia o ciclo de vida
// das falhas lá: dono, prazo, reteste e histórico.
//
// A severidade enviada é a prioridade do crivo, não a da ferramenta de origem.
// Uma falha "média" que está no KEV entra como Critical, e o SLA padrão do
// DefectDojo (7, 30, 90 dias) passa a bater com o prazo que o crivo calculou.
// A severidade original fica na descrição.
package defectdojo

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/priority"
)

// Finding segue os campos do importador genérico do DefectDojo.
type Finding struct {
	Title            string `json:"title"`
	Description      string `json:"description"`
	Severity         string `json:"severity"`
	Date             string `json:"date"`
	UniqueIDFromTool string `json:"unique_id_from_tool"`
	VulnIDFromTool   string `json:"vuln_id_from_tool,omitempty"`
	CVE              string `json:"cve,omitempty"`
	ComponentName    string `json:"component_name,omitempty"`
	ComponentVersion string `json:"component_version,omitempty"`
	FilePath         string `json:"file_path,omitempty"`
	StaticFinding    bool   `json:"static_finding"`
	DynamicFinding   bool   `json:"dynamic_finding"`
}

// Report é o documento que o DefectDojo importa.
type Report struct {
	Findings []Finding `json:"findings"`
}

var severityByLevel = map[priority.Level]string{
	priority.P1: "Critical",
	priority.P2: "High",
	priority.P3: "Medium",
	priority.P4: "Low",
}

// Convert monta o documento. O unique_id_from_tool é a impressão digital do
// crivo: é ela que faz o DefectDojo reconhecer o mesmo achado na próxima
// importação, em vez de abrir outro.
func Convert(open []priority.Triage, generated time.Time) Report {
	out := Report{Findings: make([]Finding, 0, len(open))}
	for _, t := range open {
		f := Finding{
			Title:            title(t),
			Description:      description(t),
			Severity:         severityByLevel[t.Level],
			Date:             generated.Format(time.DateOnly),
			UniqueIDFromTool: t.Fingerprint(),
			VulnIDFromTool:   t.Rule,
			ComponentName:    t.Package,
			ComponentVersion: t.Version,
			FilePath:         t.Location,
			DynamicFinding:   t.Source == "zap",
		}
		f.StaticFinding = !f.DynamicFinding
		if cves := t.CVEs(); len(cves) > 0 {
			f.CVE = cves[0]
		}
		if f.Severity == "" {
			f.Severity = "Info"
		}
		out.Findings = append(out.Findings, f)
	}
	return out
}

// Write escreve o documento indentado.
func Write(w io.Writer, open []priority.Triage, generated time.Time) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(Convert(open, generated))
}

func title(t priority.Triage) string {
	alvo := t.Package
	if alvo == "" {
		alvo = t.Location
	}
	if alvo == "" {
		return t.Rule
	}
	return fmt.Sprintf("%s em %s", t.Rule, alvo)
}

func description(t priority.Triage) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", t.Title)
	fmt.Fprintf(&b, "Prioridade do crivo: %s (%s). Prazo: %s.\n", t.Level, t.Reason, t.Due.Format(time.DateOnly))
	fmt.Fprintf(&b, "Severidade na ferramenta de origem (%s): %s.\n", t.Source, t.Severity)
	if t.EPSS > 0 {
		fmt.Fprintf(&b, "EPSS: %.1f%%.\n", t.EPSS*100)
	}
	if t.KEV {
		b.WriteString("No catálogo KEV da CISA: explorada de verdade.\n")
	}
	if len(t.Aliases) > 0 {
		fmt.Fprintf(&b, "Identificadores: %s.\n", strings.Join(t.Aliases, ", "))
	}
	return b.String()
}
