// Package accept lê a lista de riscos aceitos. Aceite sem prazo vira
// esquecimento; por isso todo aceite tem data de revisão, e o vencido volta a
// contar como achado aberto.
package accept

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
)

// Acceptance é um risco aceito. Package vazio vale para qualquer pacote.
type Acceptance struct {
	Rule    string `json:"regra"`
	Package string `json:"pacote,omitempty"`
	Reason  string `json:"motivo"`
	Until   string `json:"ate"`
	until   time.Time
}

// List é o conjunto de aceites lido do arquivo.
type List []Acceptance

// Load lê e valida o arquivo. Aceite sem motivo ou sem data é recusado na
// leitura: é exatamente o tipo de aceite que ninguém consegue revisar depois.
func Load(r io.Reader) (List, error) {
	var list List
	dec := json.NewDecoder(io.LimitReader(r, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&list); err != nil {
		return nil, fmt.Errorf("arquivo de aceites inválido: %w", err)
	}
	for i := range list {
		a := &list[i]
		if a.Rule == "" || strings.TrimSpace(a.Reason) == "" {
			return nil, fmt.Errorf("aceite %d sem regra ou sem motivo", i+1)
		}
		t, err := time.Parse(time.DateOnly, a.Until)
		if err != nil {
			return nil, fmt.Errorf("aceite de %s com data inválida %q: use AAAA-MM-DD", a.Rule, a.Until)
		}
		a.until = t
	}
	return list, nil
}

// Match diz se o achado está aceito na data informada, e devolve o aceite
// vencido quando houver, para o relatório avisar.
func (l List) Match(f finding.Finding, now time.Time) (accepted bool, expired *Acceptance) {
	for i := range l {
		a := &l[i]
		if a.Rule != f.Rule || (a.Package != "" && a.Package != f.Package) {
			continue
		}
		// O aceite vale até o fim do dia informado.
		if now.Before(a.until.AddDate(0, 0, 1)) {
			return true, nil
		}
		expired = a
	}
	return false, expired
}
