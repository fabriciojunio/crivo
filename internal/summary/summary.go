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
	"regexp"
	"strings"
	"time"
	"unicode"

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

// New cria o cliente. O tempo vem de quem roda: em máquina com GPU um minuto
// sobra; num runner de CI só com CPU, um modelo de 3B leva alguns minutos.
func New(model string, timeout time.Duration) *Client {
	return &Client{HTTP: &http.Client{Timeout: timeout}, URL: DefaultURL, Model: model}
}

// maxTokens limita a resposta no próprio modelo: cinco frases cabem com
// folga, e o modelo não gasta tempo escrevendo o que vai ser cortado.
const maxTokens = 300

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
	// Modelo pequeno se perde com instrução vaga: o texto diz o que é a lista,
	// o formato da resposta e o que não fazer.
	b.WriteString("Abaixo está a lista de vulnerabilidades encontradas num projeto de software, ")
	b.WriteString("já ordenada por prioridade (P1 é a mais urgente) e com o prazo de correção de cada uma.\n")
	b.WriteString("Escreva um resumo em português do Brasil, em no máximo cinco frases, para a gerente do projeto: ")
	b.WriteString("quantas falhas existem, quais corrigir primeiro e por quê, citando o pacote e o prazo.\n")
	b.WriteString("Use só o que está na lista. Não invente falha, não escreva link nem código.\n\nVulnerabilidades:\n")
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
	body, _ := json.Marshal(map[string]any{
		"model": c.Model, "prompt": Prompt(open), "stream": false,
		"options": map[string]any{"num_predict": maxTokens},
	})
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
	return Neutralize(out.Response), nil
}

// MaxRunes limita o resumo: cinco frases cabem com folga, e um modelo
// manipulado não consegue encher o pull request de texto.
const MaxRunes = 1500

var (
	markdownImage = regexp.MustCompile(`!\[[^\]]*\]\([^)]*\)`)
	markdownLink  = regexp.MustCompile(`\[([^\]]*)\]\([^)]*\)`)
	rawAddress    = regexp.MustCompile(`(?i)\b(?:[a-z][a-z0-9+.-]*://|www\.)\S+`)
	mention       = regexp.MustCompile(`@([A-Za-z0-9])`)
)

// Neutralize trata a resposta do modelo como texto não confiável. Ela vai
// para um comentário no pull request, e o prompt carrega nome de pacote e de
// regra que vieram do código analisado: quem controla esses nomes pode tentar
// fazer o modelo escrever uma imagem que vaza dados ao carregar, um link de
// phishing ou uma menção que notifica alguém. Sobra só o texto.
func Neutralize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
	s = markdownImage.ReplaceAllString(s, "")
	s = markdownLink.ReplaceAllString(s, "$1")
	s = rawAddress.ReplaceAllString(s, "[endereço removido]")
	s = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;").Replace(s)
	s = mention.ReplaceAllString(s, "@\u200b$1")
	if r := []rune(s); len(r) > MaxRunes {
		s = string(r[:MaxRunes]) + "…"
	}
	return strings.TrimSpace(s)
}
