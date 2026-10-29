// Package report escreve o resultado da triagem: Markdown para gente ler no
// pull request e JSON para outra ferramenta consumir.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/accept"
	"github.com/fabriciojunio/crivo/internal/priority"
)

// Result é tudo o que a triagem produziu.
type Result struct {
	Generated time.Time           `json:"gerado_em"`
	Open      []priority.Triage   `json:"abertos"`
	Accepted  int                 `json:"aceitos"`
	Expired   []accept.Acceptance `json:"aceites_vencidos,omitempty"`
	Offline   bool                `json:"sem_enriquecimento,omitempty"`
	Summary   string              `json:"resumo,omitempty"`
}

// Count devolve quantos achados abertos há em cada nível.
func (r Result) Count() map[priority.Level]int {
	c := map[priority.Level]int{}
	for _, t := range r.Open {
		c[t.Level]++
	}
	return c
}

// JSON escreve o resultado indentado.
func JSON(w io.Writer, r Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// Markdown escreve a tabela de triagem.
func Markdown(w io.Writer, r Result) error {
	var b strings.Builder
	c := r.Count()
	fmt.Fprintf(&b, "# Triagem de segurança\n\n")
	fmt.Fprintf(&b, "Gerada em %s. Abertos: P1 %d, P2 %d, P3 %d, P4 %d. Aceitos com prazo: %d.\n\n",
		r.Generated.Format(time.DateOnly), c[priority.P1], c[priority.P2], c[priority.P3], c[priority.P4], r.Accepted)
	if r.Offline {
		b.WriteString("Sem EPSS e KEV nesta execução (modo offline): a prioridade usou só a severidade.\n\n")
	}
	if r.Summary != "" {
		fmt.Fprintf(&b, "## Resumo\n\n%s\n\n", r.Summary)
	}
	if len(r.Expired) > 0 {
		b.WriteString("## Aceites vencidos\n\n")
		for _, a := range r.Expired {
			fmt.Fprintf(&b, "- `%s` venceu em %s. Motivo registrado: %s\n", a.Rule, a.Until, cell(a.Reason))
		}
		b.WriteString("\n")
	}
	if len(r.Open) == 0 {
		b.WriteString("Nenhum achado aberto.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}
	b.WriteString("| Prioridade | Prazo | Fonte | Regra | Onde | Motivo |\n|---|---|---|---|---|---|\n")
	for _, t := range r.Open {
		where := t.Location
		if t.Package != "" {
			where = t.Package + "@" + t.Version
		}
		fmt.Fprintf(&b, "| %s | %s | %s | `%s` | %s | %s |\n",
			t.Level, t.Due.Format(time.DateOnly), cell(t.Source), cell(t.Rule), cell(where), cell(t.Reason))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// cell neutraliza o que quebraria a tabela ou viraria HTML no relatório. O
// texto vem da ferramenta de origem e, no fim, de quem escreveu o código
// analisado: ele não pode injetar marcação no comentário do pull request.
func cell(s string) string {
	r := strings.NewReplacer("|", "\\|", "\n", " ", "\r", " ", "<", "&lt;", ">", "&gt;", "`", "'")
	return r.Replace(s)
}
