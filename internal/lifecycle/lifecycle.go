// Package lifecycle decide o que fazer com as issues de vulnerabilidade a cada
// varredura: abrir a do achado novo, fechar a do que foi corrigido, reabrir a
// do que voltou e trocar a prioridade quando ela muda. É só lógica, sem rede:
// quem fala com o GitHub é o pacote github, a partir do plano devolvido aqui.
//
// A issue é reconhecida pela impressão digital do achado, guardada no corpo
// num comentário HTML. Título e número podem mudar; a impressão digital não.
package lifecycle

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fabriciojunio/crivo/internal/priority"
)

// Label marca as issues que o crivo gerencia. Issue sem ela não é tocada.
const Label = "crivo"

// Issue é o que importa de uma issue existente.
type Issue struct {
	Number      int
	Open        bool
	Fingerprint string
	Labels      []string
}

// Kind é o tipo de ação.
type Kind int

const (
	Create Kind = iota + 1
	Close
	Reopen
	Relabel
)

func (k Kind) String() string {
	return map[Kind]string{Create: "abrir", Close: "fechar", Reopen: "reabrir", Relabel: "atualizar prioridade"}[k]
}

// Action é um passo do plano. Triage vem vazio no Close. Labels são as que a
// issue já tem, para quem aplica o plano trocar só a da prioridade.
type Action struct {
	Kind   Kind
	Issue  int
	Triage priority.Triage
	Labels []string
}

// Plan compara a varredura com as issues. A ordem do resultado é estável:
// primeiro o que abre ou reabre, na ordem de prioridade da triagem, depois o
// que fecha, pelo número da issue.
func Plan(open []priority.Triage, issues []Issue) []Action {
	byFP := make(map[string]Issue, len(issues))
	for _, is := range issues {
		if is.Fingerprint == "" {
			continue
		}
		// Duas issues com a mesma impressão digital: vale a aberta, ou a mais
		// recente. Não duplica, e não fecha por engano a que está em uso.
		if cur, ok := byFP[is.Fingerprint]; ok && (cur.Open || cur.Number > is.Number) {
			continue
		}
		byFP[is.Fingerprint] = is
	}

	var plan []Action
	seen := make(map[string]bool, len(open))
	for _, t := range open {
		fp := t.Fingerprint()
		if seen[fp] {
			continue
		}
		seen[fp] = true
		is, ok := byFP[fp]
		switch {
		case !ok:
			plan = append(plan, Action{Kind: Create, Triage: t})
		case !is.Open:
			plan = append(plan, Action{Kind: Reopen, Issue: is.Number, Triage: t, Labels: is.Labels})
		case !slices.Contains(is.Labels, t.Level.String()):
			plan = append(plan, Action{Kind: Relabel, Issue: is.Number, Triage: t, Labels: is.Labels})
		}
	}

	var closing []Action
	for fp, is := range byFP {
		if is.Open && !seen[fp] {
			closing = append(closing, Action{Kind: Close, Issue: is.Number})
		}
	}
	slices.SortFunc(closing, func(a, b Action) int { return a.Issue - b.Issue })
	return append(plan, closing...)
}

var markerRe = regexp.MustCompile(`<!-- crivo:([0-9a-f]{16}) -->`)

// Marker é o comentário que guarda a impressão digital no corpo da issue.
func Marker(fingerprint string) string { return "<!-- crivo:" + fingerprint + " -->" }

// FingerprintFrom lê a impressão digital do corpo. Só aceita o formato exato
// gerado pelo crivo; o resto do corpo pode ter sido editado por gente.
func FingerprintFrom(body string) string {
	if m := markerRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// Labels da issue de um achado: a do crivo e a da prioridade.
func Labels(t priority.Triage) []string { return []string{Label, t.Level.String()} }

var levelLabel = regexp.MustCompile(`^P[1-4]$`)

// Merge troca só a label de prioridade e garante a do crivo. As outras foram
// postas por gente (time, componente, "em andamento") e ficam.
func Merge(current []string, t priority.Triage) []string {
	out := []string{Label}
	for _, l := range current {
		if l != Label && !levelLabel.MatchString(l) {
			out = append(out, l)
		}
	}
	return append(out, t.Level.String())
}

// Title da issue, curto o bastante para a lista.
func Title(t priority.Triage) string {
	alvo := t.Package
	if alvo == "" {
		alvo = t.Location
	}
	titulo := fmt.Sprintf("[%s] %s", t.Level, t.Rule)
	if alvo != "" {
		titulo += " em " + alvo
	}
	return safe(titulo, 120)
}

// Body da issue. Cada campo que veio da ferramenta passa pelo safe: a issue
// avisa gente, e o texto, no fim, vem de quem escreveu o código analisado.
func Body(t priority.Triage, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "**%s**\n\n", safe(t.Title, 300))
	b.WriteString("| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Prioridade | %s: %s |\n", t.Level, safe(t.Reason, 200))
	fmt.Fprintf(&b, "| Prazo | %s |\n", t.Due.Format(time.DateOnly))
	fmt.Fprintf(&b, "| Ferramenta | %s |\n", safe(t.Source, 40))
	fmt.Fprintf(&b, "| Regra | %s |\n", safe(t.Rule, 200))
	if t.Package != "" {
		fmt.Fprintf(&b, "| Componente | %s %s |\n", safe(t.Package, 200), safe(t.Version, 60))
	}
	if t.Location != "" {
		fmt.Fprintf(&b, "| Local | %s |\n", safe(t.Location, 300))
	}
	if t.EPSS > 0 {
		fmt.Fprintf(&b, "| EPSS | %.1f%% |\n", t.EPSS*100)
	}
	if t.KEV {
		b.WriteString("| KEV | explorada de verdade |\n")
	}
	fmt.Fprintf(&b, "\nAberta pelo crivo em %s. Fecha sozinha quando a varredura deixar de achar o problema.\n\n",
		now.Format(time.DateOnly))
	b.WriteString(Marker(t.Fingerprint()))
	return b.String()
}

// safe tira o que viraria marcação, menção ou link, e corta no tamanho.
// O "<" some primeiro: sem ele não há HTML nem marcador forjado de outra issue.
func safe(s string, max int) string {
	r := strings.NewReplacer(
		"\r", " ", "\n", " ", "<", "&lt;", ">", "&gt;", "|", "\\|",
		"`", "'", "[", "\\[", "]", "\\]", "@", "@​",
	)
	s = r.Replace(s)
	if utf8.RuneCountInString(s) > max {
		s = string([]rune(s)[:max-1]) + "…"
	}
	return s
}
