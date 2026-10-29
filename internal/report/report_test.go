package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
	"github.com/fabriciojunio/crivo/internal/priority"
)

var gen = time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)

func TestMarkdownNeutralizesInjectedText(t *testing.T) {
	r := Result{Generated: gen, Open: []priority.Triage{{
		Finding: finding.Finding{Source: "zap", Rule: "x|y", Location: "<script>alert(1)</script>\n| P1 | falso |"},
		Level:   priority.P2, Reason: "severidade alta", Due: gen,
	}}}
	var b bytes.Buffer
	if err := Markdown(&b, r); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "<script>") {
		t.Error("HTML do achado chegou cru ao relatório")
	}
	// Só o cabeçalho, o separador e uma linha de achado: a quebra de linha
	// injetada não pode criar uma segunda linha na tabela.
	if n := strings.Count(out, "\n| "); n != 2 {
		t.Errorf("linhas de tabela = %d, quero 2:\n%s", n, out)
	}
}

func TestMarkdownCountsAndEmpty(t *testing.T) {
	var b bytes.Buffer
	_ = Markdown(&b, Result{Generated: gen, Accepted: 3, Offline: true})
	out := b.String()
	for _, want := range []string{"Aceitos com prazo: 3", "modo offline", "Nenhum achado aberto"} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q em:\n%s", want, out)
		}
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var b bytes.Buffer
	r := Result{Generated: gen, Open: []priority.Triage{{Level: priority.P1, Reason: "KEV"}}}
	if err := JSON(&b, r); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(b.Bytes(), &back); err != nil {
		t.Fatal(err)
	}
	if len(back["abertos"].([]any)) != 1 {
		t.Fatalf("json = %s", b.String())
	}
}
