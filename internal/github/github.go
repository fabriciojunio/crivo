// Package github aplica o plano do ciclo de vida nas issues de um repositório,
// pela API REST do GitHub, só com a biblioteca padrão.
//
// O token é de quem roda o crivo e abre issue em nome dele, então três
// cuidados: o repositório é validado antes de virar caminho de URL, o token só
// sai por HTTPS (HTTP só para localhost, nos testes) e o cliente não segue
// redirecionamento, para o cabeçalho de autorização não ir parar em outro host.
package github

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/lifecycle"
)

const (
	DefaultAPI = "https://api.github.com"
	// Uma página de 100 issues tem poucas centenas de KB; o limite folgado
	// protege a memória de uma resposta adulterada.
	maxResponse = 10 << 20
	perPage     = 100
	// 50 páginas são 5.000 issues: mais que isso é sinal de erro, não de fila.
	maxPages = 50
)

var repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)

// Client fala com a API de issues de um repositório.
type Client struct {
	HTTP  *http.Client
	API   string
	Token string
	Repo  string
}

// New valida o repositório e o token e devolve um cliente com tempo limite.
func New(repo, token string) (*Client, error) {
	// "." e ".." passam na expressão (ponto é válido em nome de repositório,
	// como em .github), mas o JoinPath limparia o caminho e o pedido, com o
	// token, iria para outro endpoint da API.
	dono, nome, _ := strings.Cut(repo, "/")
	if !repoRe.MatchString(repo) || dono == "." || dono == ".." || nome == "." || nome == ".." {
		return nil, fmt.Errorf("repositório %q fora do formato dono/nome", repo)
	}
	if token == "" {
		return nil, errors.New("sem token: defina GITHUB_TOKEN")
	}
	return &Client{
		HTTP: &http.Client{
			Timeout: 30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		API:   DefaultAPI,
		Token: token,
		Repo:  repo,
	}, nil
}

func (c *Client) base() (*url.URL, error) {
	u, err := url.Parse(c.API)
	if err != nil {
		return nil, err
	}
	local := u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost"
	if u.Scheme != "https" && !(u.Scheme == "http" && local) {
		return nil, fmt.Errorf("a API precisa ser HTTPS para o token não trafegar aberto: %s", u.Redacted())
	}
	return u, nil
}

func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	u, err := c.base()
	if err != nil {
		return err
	}
	u = u.JoinPath(path)
	u.RawQuery = query.Encode()

	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), reader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "crivo")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// O corpo de erro da API não é repetido: pode ecoar o que foi enviado.
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s respondeu %d", method, path, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return fmt.Errorf("resposta de %s maior que o limite", path)
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

type apiIssue struct {
	Number      int    `json:"number"`
	State       string `json:"state"`
	Body        string `json:"body"`
	PullRequest *struct {
		URL string `json:"url"`
	} `json:"pull_request"`
	Labels []struct {
		Name string `json:"name"`
	} `json:"labels"`
}

// Issues lista as issues com a label do crivo, abertas e fechadas. Pull
// request também aparece nessa API e é descartado.
func (c *Client) Issues(ctx context.Context) ([]lifecycle.Issue, error) {
	var all []lifecycle.Issue
	for page := 1; page <= maxPages; page++ {
		q := url.Values{"labels": {lifecycle.Label}, "state": {"all"},
			"per_page": {fmt.Sprint(perPage)}, "page": {fmt.Sprint(page)}}
		var batch []apiIssue
		if err := c.do(ctx, http.MethodGet, "/repos/"+c.Repo+"/issues", q, nil, &batch); err != nil {
			return nil, err
		}
		for _, is := range batch {
			if is.PullRequest != nil {
				continue
			}
			var labels []string
			for _, l := range is.Labels {
				labels = append(labels, l.Name)
			}
			all = append(all, lifecycle.Issue{
				Number:      is.Number,
				Open:        is.State == "open",
				Fingerprint: lifecycle.FingerprintFrom(is.Body),
				Labels:      labels,
			})
		}
		if len(batch) < perPage {
			return all, nil
		}
	}
	return nil, fmt.Errorf("mais de %d issues com a label %s", maxPages*perPage, lifecycle.Label)
}

// Apply executa o plano na ordem e para no primeiro erro: o que já foi feito
// fica feito, e a próxima execução recalcula o plano a partir do estado real.
func (c *Client) Apply(ctx context.Context, plan []lifecycle.Action, now time.Time) (int, error) {
	issues := "/repos/" + c.Repo + "/issues"
	dia := now.Format(time.DateOnly)
	for i, a := range plan {
		path := fmt.Sprintf("%s/%d", issues, a.Issue)
		var err error
		switch a.Kind {
		case lifecycle.Create:
			err = c.do(ctx, http.MethodPost, issues, nil, map[string]any{
				"title": lifecycle.Title(a.Triage), "body": lifecycle.Body(a.Triage, now),
				"labels": lifecycle.Labels(a.Triage)}, nil)
		case lifecycle.Close:
			err = c.comment(ctx, path, "A varredura de "+dia+" não encontrou mais este achado. Fechada como corrigida.")
			if err == nil {
				err = c.do(ctx, http.MethodPatch, path, nil, map[string]any{"state": "closed", "state_reason": "completed"}, nil)
			}
		case lifecycle.Reopen:
			err = c.do(ctx, http.MethodPatch, path, nil, map[string]any{"state": "open",
				"title": lifecycle.Title(a.Triage), "body": lifecycle.Body(a.Triage, now),
				"labels": lifecycle.Merge(a.Labels, a.Triage)}, nil)
			if err == nil {
				err = c.comment(ctx, path, "Voltou a aparecer na varredura de "+dia+". Reaberta.")
			}
		case lifecycle.Relabel:
			err = c.do(ctx, http.MethodPatch, path, nil, map[string]any{
				"title": lifecycle.Title(a.Triage), "labels": lifecycle.Merge(a.Labels, a.Triage)}, nil)
		default:
			err = fmt.Errorf("ação desconhecida: %d", a.Kind)
		}
		if err != nil {
			return i, fmt.Errorf("%s: %w", a.Kind, err)
		}
	}
	return len(plan), nil
}

func (c *Client) comment(ctx context.Context, issuePath, text string) error {
	return c.do(ctx, http.MethodPost, issuePath+"/comments", nil, map[string]string{"body": text}, nil)
}
