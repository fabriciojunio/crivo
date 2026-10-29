package parser

import (
	"github.com/fabriciojunio/crivo/internal/finding"
)

// Relatório JSON tradicional do OWASP ZAP (report_json.json).
type zapReport struct {
	Site []struct {
		Name   string `json:"@name"`
		Alerts []struct {
			PluginID string `json:"pluginid"`
			Name     string `json:"name"`
			RiskCode string `json:"riskcode"`
			CWE      string `json:"cweid"`
		} `json:"alerts"`
	} `json:"site"`
}

func parseZAP(data []byte) ([]finding.Finding, error) {
	var rep zapReport
	if err := decode(data, &rep); err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, site := range rep.Site {
		for _, a := range site.Alerts {
			f := finding.Finding{
				Source:   "zap",
				Rule:     a.PluginID,
				Title:    a.Name,
				Severity: severityFromRisk(a.RiskCode),
				Location: site.Name,
			}
			// O ZAP usa -1 e 0 quando não há CWE associado.
			if a.CWE != "" && a.CWE != "-1" && a.CWE != "0" {
				f.Aliases = []string{"CWE-" + a.CWE}
			}
			out = append(out, f)
		}
	}
	return out, nil
}

// O ZAP mede risco de 0 (informativo) a 3 (alto), sem nível crítico.
func severityFromRisk(code string) finding.Severity {
	switch code {
	case "3":
		return finding.SeverityHigh
	case "2":
		return finding.SeverityMedium
	case "1":
		return finding.SeverityLow
	default:
		return finding.SeverityUnknown
	}
}
