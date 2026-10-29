// Package summary pede a um modelo de linguagem local um resumo da triagem
// para quem decide, em português simples. É opcional: sem ele, o crivo faz a
// mesma triagem.
//
// Só aceita endereço da própria máquina. O resumo leva nomes de pacote, regras
// e caminhos do código; mandar isso para um serviço de terceiro por um erro de
// configuração seria vazar o mapa de falhas do projeto.
package summary

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/priority"
)

// DefaultURL é a API local do Ollama.
const DefaultURL = "http://127.0.0.1:11434/api/generate"

// ErrNotLocal recusa endereço fora da máquina.
var ErrNotLocal = errors.New("o resumo só usa modelo local (127.0.0.1, ::1 ou localhost)")

// Client fala com o Ollama.
type Client struct {
	HTTP  *http.Client
	URL   string
	Model string
}

// New cria o cliente. Modelo local em máquina comum demora; um minuto cobre
// o primeiro carregamento sem prender o pipeline indefinidamente.
func New(model string) *Client {
	return &Client{HTTP: &http.Client{Timeout: time.Minute}, URL: DefaultURL, Model: model}
}

func checkLocal(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return ErrNotLocal
}

// Prompt monta o pedido só com o necessário: contagem, os dez primeiros
// achados e o motivo de cada um. Texto livre da ferramenta de origem fica de
// fora, porque é por ele que alguém tentaria injetar instrução no modelo.
func Prompt(open []priority.Triage) string {
	var b strings.Builder
	b.WriteString("Você resume uma triagem de vulnerabilidades para uma pessoa que decide prioridades. ")
	b.WriteString("Escreva em português, em até cinco frases, sem inventar achado que não está na lista. ")
	b.WriteString("Diga o que corrigir primeiro e por quê.\n\nAchados:\n")
	for i, t := range open {
		if i == 10 {
			fmt.Fprintf(&b, "- e mais %d achados de prioridade menor\n", len(open)-10)
			break
		}
		fmt.Fprintf(&b, "- %s, prazo %s, %s %s: %s\n", t.Level, t.Due.Format(time.DateOnly), t.Package, t.Rule, t.Reason)
	}
	return b.String()
}

// Summarize pede o resumo ao modelo.
func (c *Client) Summarize(ctx context.Context, open []priority.Triage) (string, error) {
	if err := checkLocal(c.URL); err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]any{"model": c.Model, "prompt": Prompt(open), "stream": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return "", fmt.Errorf("modelo local indisponível: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("modelo local respondeu %d", resp.StatusCode)
	}
	var out struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil {
		return "", err
	}
	return strings.TrimSpace(out.Response), nil
}
