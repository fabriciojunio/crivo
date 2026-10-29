package parser

import (
	"fmt"
	"strconv"

	"github.com/fabriciojunio/crivo/internal/finding"
)

// SARIF 2.1.0, o formato do CodeQL e do Semgrep. Só os campos usados.
type sarifLog struct {
	Runs []struct {
		Tool struct {
			Driver struct {
				Name  string `json:"name"`
				Rules []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties struct {
						// O CodeQL publica a nota no formato CVSS aqui, como texto.
						SecuritySeverity string `json:"security-severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func parseSARIF(data []byte) ([]finding.Finding, error) {
	var log sarifLog
	if err := decode(data, &log); err != nil {
		return nil, err
	}
	var out []finding.Finding
	for _, run := range log.Runs {
		levels := map[string]string{}
		scores := map[string]float64{}
		for _, rule := range run.Tool.Driver.Rules {
			levels[rule.ID] = rule.DefaultConfiguration.Level
			if s, err := strconv.ParseFloat(rule.Properties.SecuritySeverity, 64); err == nil {
				scores[rule.ID] = s
			}
		}
		for _, res := range run.Results {
			f := finding.Finding{
				Source: run.Tool.Driver.Name,
				Rule:   res.RuleID,
				Title:  res.Message.Text,
				CVSS:   scores[res.RuleID],
			}
			if f.CVSS > 0 {
				f.Severity = finding.SeverityFromCVSS(f.CVSS)
			} else {
				level := res.Level
				if level == "" {
					// Resultado sem nível herda o da regra, pela especificação.
					level = levels[res.RuleID]
				}
				f.Severity = severityFromLevel(level)
			}
			if len(res.Locations) > 0 {
				loc := res.Locations[0].PhysicalLocation
				f.Location = location(loc.ArtifactLocation.URI, loc.Region.StartLine)
			}
			out = append(out, f)
		}
	}
	return out, nil
}

func severityFromLevel(level string) finding.Severity {
	switch level {
	case "error":
		return finding.SeverityHigh
	case "warning":
		return finding.SeverityMedium
	case "note":
		return finding.SeverityLow
	default:
		return finding.SeverityUnknown
	}
}

// location escreve arquivo:linha. Há ferramenta que, em alguns sistemas,
// grava o achado sem o arquivo; aí sobra a linha, dita por extenso.
func location(uri string, line int) string {
	switch {
	case uri != "" && line > 0:
		return fmt.Sprintf("%s:%d", uri, line)
	case uri != "":
		return uri
	case line > 0:
		return fmt.Sprintf("linha %d", line)
	default:
		return ""
	}
}
