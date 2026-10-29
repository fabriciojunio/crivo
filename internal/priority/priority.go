// Package priority decide a ordem de correção. Severidade sozinha erra nos
// dois sentidos: uma "crítica" que ninguém explora pode esperar, e uma "média"
// que está sendo explorada agora não pode. Por isso entram o KEV e o EPSS.
package priority

import (
	"fmt"
	"slices"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
)

// Level é a prioridade de P1 (mais urgente) a P4.
type Level int

const (
	P1 Level = iota + 1
	P2
	P3
	P4
)

func (l Level) String() string { return fmt.Sprintf("P%d", int(l)) }

// SLA é o prazo de correção de cada nível, contado a partir da triagem.
var SLA = map[Level]time.Duration{
	P1: 7 * 24 * time.Hour,
	P2: 30 * 24 * time.Hour,
	P3: 90 * 24 * time.Hour,
	P4: 180 * 24 * time.Hour,
}

// Limiares do EPSS. A FIRST publica que poucas vulnerabilidades passam de
// 10% de chance de exploração em 30 dias; quem passa merece fila própria.
const (
	epssUrgent = 0.5
	epssHigh   = 0.1
)

// Triage é um achado com a prioridade decidida e o porquê.
type Triage struct {
	finding.Finding
	Level  Level     `json:"prioridade"`
	Reason string    `json:"motivo"`
	EPSS   float64   `json:"epss,omitempty"`
	KEV    bool      `json:"kev,omitempty"`
	Due    time.Time `json:"prazo"`
}

// Decide aplica as regras na ordem: o primeiro motivo que se aplica vence.
func Decide(f finding.Finding, epss map[string]float64, kev map[string]bool, now time.Time) Triage {
	t := Triage{Finding: f}
	for _, cve := range f.CVEs() {
		t.EPSS = max(t.EPSS, epss[cve])
		t.KEV = t.KEV || kev[cve]
	}
	switch {
	case t.KEV:
		t.Level, t.Reason = P1, "explorada de verdade (catálogo KEV da CISA)"
	case f.Severity == finding.SeverityCritical:
		t.Level, t.Reason = P1, "severidade crítica"
	case t.EPSS >= epssUrgent:
		t.Level, t.Reason = P1, fmt.Sprintf("EPSS %.0f%%: exploração provável", t.EPSS*100)
	case f.Severity == finding.SeverityHigh:
		t.Level, t.Reason = P2, "severidade alta"
	case t.EPSS >= epssHigh:
		t.Level, t.Reason = P2, fmt.Sprintf("EPSS %.0f%%, acima da média", t.EPSS*100)
	case f.Severity == finding.SeverityMedium:
		t.Level, t.Reason = P3, "severidade média"
	default:
		t.Level, t.Reason = P4, "severidade baixa ou não informada"
	}
	t.Due = now.Add(SLA[t.Level])
	return t
}

// Sort ordena por prioridade e, dentro dela, pelo EPSS maior primeiro.
func Sort(all []Triage) {
	slices.SortStableFunc(all, func(a, b Triage) int {
		if a.Level != b.Level {
			return int(a.Level) - int(b.Level)
		}
		switch {
		case a.EPSS > b.EPSS:
			return -1
		case a.EPSS < b.EPSS:
			return 1
		default:
			return 0
		}
	})
}
