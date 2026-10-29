package parser

import (
	"strconv"

	"github.com/fabriciojunio/crivo/internal/finding"
)

// Saída JSON do OSV-Scanner (`--format json`).
type osvOutput struct {
	Results []struct {
		Source struct {
			Path string `json:"path"`
		} `json:"source"`
		Packages []struct {
			Package struct {
				Name      string `json:"name"`
				Version   string `json:"version"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Vulnerabilities []struct {
				ID      string   `json:"id"`
				Aliases []string `json:"aliases"`
				Summary string   `json:"summary"`
			} `json:"vulnerabilities"`
			// O OSV agrupa ids que são a mesma falha e calcula a maior nota do
			// grupo. É a nota que vale, e não precisa reinterpretar vetor CVSS.
			Groups []struct {
				IDs         []string `json:"ids"`
				MaxSeverity string   `json:"max_severity"`
			} `json:"groups"`
		} `json:"packages"`
	} `json:"results"`
}

func parseOSV(data []byte) ([]finding.Finding, error) {
	var out osvOutput
	if err := decode(data, &out); err != nil {
		return nil, err
	}
	var findings []finding.Finding
	for _, res := range out.Results {
		for _, pkg := range res.Packages {
			score := map[string]float64{}
			for _, g := range pkg.Groups {
				// Nota que não é número fica zero e vira severidade desconhecida.
				s, _ := strconv.ParseFloat(g.MaxSeverity, 64)
				for _, id := range g.IDs {
					score[id] = s
				}
			}
			for _, v := range pkg.Vulnerabilities {
				findings = append(findings, finding.Finding{
					Source:   "osv-scanner",
					Rule:     v.ID,
					Title:    v.Summary,
					CVSS:     score[v.ID],
					Severity: finding.SeverityFromCVSS(score[v.ID]),
					Aliases:  v.Aliases,
					Package:  pkg.Package.Ecosystem + ":" + pkg.Package.Name,
					Version:  pkg.Package.Version,
					Location: res.Source.Path,
				})
			}
		}
	}
	return findings, nil
}
