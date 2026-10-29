// Package finding define o achado de segurança normalizado: o mesmo formato
// para o que vem do CodeQL, do Semgrep, do OSV-Scanner e do ZAP.
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Severity é a gravidade declarada pela ferramenta de origem, já traduzida
// para uma escala só. A ordem numérica importa: maior é mais grave.
type Severity int

const (
	SeverityUnknown Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityLow:
		return "baixa"
	case SeverityMedium:
		return "média"
	case SeverityHigh:
		return "alta"
	case SeverityCritical:
		return "crítica"
	default:
		return "desconhecida"
	}
}

// SeverityFromCVSS converte a nota CVSS (0 a 10) pelas faixas da própria
// especificação do CVSS.
func SeverityFromCVSS(score float64) Severity {
	switch {
	case score >= 9.0:
		return SeverityCritical
	case score >= 7.0:
		return SeverityHigh
	case score >= 4.0:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityUnknown
	}
}

// Finding é um achado de qualquer ferramenta.
type Finding struct {
	Source   string   `json:"fonte"`
	Rule     string   `json:"regra"`
	Title    string   `json:"titulo"`
	Severity Severity `json:"severidade"`
	CVSS     float64  `json:"cvss,omitempty"`
	// Aliases guarda CVE e GHSA. O enriquecimento por EPSS e KEV só funciona
	// com CVE, e o OSV costuma devolver o GHSA como id principal.
	Aliases  []string `json:"aliases,omitempty"`
	Package  string   `json:"pacote,omitempty"`
	Version  string   `json:"versao,omitempty"`
	Location string   `json:"local,omitempty"`
}

// Fingerprint identifica o mesmo problema entre execuções e entre
// ferramentas. Fica de fora o que muda sem o problema mudar, como o texto da
// descrição ou a severidade que a ferramenta resolveu ajustar.
func (f Finding) Fingerprint() string {
	sum := sha256.Sum256([]byte(strings.Join([]string{f.Source, f.Rule, f.Package, f.Version, f.Location}, "\x00")))
	return hex.EncodeToString(sum[:8])
}

// CVEs devolve só os aliases que são CVE.
func (f Finding) CVEs() []string {
	var cves []string
	for _, a := range f.Aliases {
		if strings.HasPrefix(a, "CVE-") {
			cves = append(cves, a)
		}
	}
	return cves
}

// Dedupe tira repetições pela impressão digital, guardando a primeira.
// Ferramentas diferentes podem achar a mesma coisa; a mesma ferramenta pode
// listar o mesmo achado duas vezes em arquivos de lock diferentes.
func Dedupe(all []Finding) []Finding {
	seen := make(map[string]bool, len(all))
	out := make([]Finding, 0, len(all))
	for _, f := range all {
		fp := f.Fingerprint()
		if seen[fp] {
			continue
		}
		seen[fp] = true
		out = append(out, f)
	}
	return out
}
