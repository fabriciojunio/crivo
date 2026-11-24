package github

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/finding"
	"github.com/fabriciojunio/crivo/internal/lifecycle"
	"github.com/fabriciojunio/crivo/internal/priority"
)

var agora = time.Date(2026, 11, 5, 12, 0, 0, 0, time.UTC)

type chamada struct {
	Metodo, Caminho string
	Corpo           map[string]any
}

// servidor grava cada chamada e responde com o que a função devolver.
func servidor(t *testing.T, responder func(r *http.Request) (int, string)) (*Client, *[]chamada) {
	t.Helper()
	var mu sync.Mutex
	var chamadas []chamada
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			t.Errorf("token não enviado em %s %s", r.Method, r.URL.Path)
		}
		var corpo map[string]any
		if r.Body != nil {
			data, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(data, &corpo)
		}
		mu.Lock()
		chamadas = append(chamadas, chamada{r.Method, r.URL.Path, corpo})
		mu.Unlock()
		status, body := responder(r)
		w.WriteHeader(status)
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	c, err := New("dono/repo", "tok")
	if err != nil {
		t.Fatal(err)
	}
	c.API = srv.URL
	return c, &chamadas
}

func achado(regra string) priority.Triage {
	return priority.Decide(finding.Finding{Source: "semgrep", Rule: regra, Location: "a.go:1",
		Severity: finding.SeverityHigh}, nil, nil, agora)
}

func TestNewRejectsRepoThatWouldEscapeThePath(t *testing.T) {
	for _, repo := range []string{"dono", "dono/repo/../../admin", "dono/repo?x=1", "../repo", ""} {
		if _, err := New(repo, "tok"); err == nil {
			t.Errorf("%q deveria ser recusado", repo)
		}
	}
	for _, repo := range []string{"dono/..", "./repo", "dono/."} {
		if _, err := New(repo, "tok"); err == nil {
			t.Errorf("%q deveria ser recusado", repo)
		}
	}
	if _, err := New("dono/.github", "tok"); err != nil {
		t.Errorf(".github é nome de repositório válido: %v", err)
	}
	if _, err := New("dono/repo", ""); err == nil {
		t.Error("sem token não roda")
	}
}

func TestTokenNeverGoesOverPlainHTTPToAnotherHost(t *testing.T) {
	c, _ := New("dono/repo", "tok")
	c.API = "http://api.exemplo.com"
	if _, err := c.Issues(context.Background()); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("erro = %v", err)
	}
}

func TestIssuesPaginatesSkipsPullRequestsAndReadsTheMarker(t *testing.T) {
	a := achado("sqli")
	pagina1 := make([]map[string]any, 0, perPage)
	for i := 1; i <= perPage; i++ {
		pagina1 = append(pagina1, map[string]any{"number": i, "state": "closed", "body": ""})
	}
	pagina1[0] = map[string]any{"number": 1, "state": "open", "body": lifecycle.Body(a, agora),
		"labels": []map[string]string{{"name": "crivo"}, {"name": "P2"}}}
	pagina2 := []map[string]any{{"number": 200, "state": "open", "body": "", "pull_request": map[string]string{"url": "x"}}}

	c, chamadas := servidor(t, func(r *http.Request) (int, string) {
		if r.URL.Query().Get("labels") != "crivo" || r.URL.Query().Get("state") != "all" {
			t.Errorf("filtro errado: %s", r.URL.RawQuery)
		}
		data, _ := json.Marshal(map[string]any{"1": pagina1, "2": pagina2}[r.URL.Query().Get("page")])
		return 200, string(data)
	})

	issues, err := c.Issues(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(*chamadas) != 2 || len(issues) != perPage {
		t.Fatalf("%d chamadas, %d issues (o pull request não conta)", len(*chamadas), len(issues))
	}
	if issues[0].Fingerprint != a.Fingerprint() || !issues[0].Open || issues[0].Labels[1] != "P2" {
		t.Fatalf("primeira issue lida errado: %+v", issues[0])
	}
}

func TestApplyCreatesClosesReopensAndRelabels(t *testing.T) {
	c, chamadas := servidor(t, func(*http.Request) (int, string) { return 201, "{}" })
	plano := []lifecycle.Action{
		{Kind: lifecycle.Create, Triage: achado("novo")},
		{Kind: lifecycle.Close, Issue: 7},
		{Kind: lifecycle.Reopen, Issue: 8, Triage: achado("voltou"), Labels: []string{"crivo", "P4"}},
		{Kind: lifecycle.Relabel, Issue: 9, Triage: achado("subiu"), Labels: []string{"crivo", "P3", "time-x"}},
	}

	n, err := c.Apply(context.Background(), plano, agora)
	if err != nil || n != 4 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	var feito []string
	for _, ch := range *chamadas {
		feito = append(feito, ch.Metodo+" "+ch.Caminho)
	}
	want := []string{
		"POST /repos/dono/repo/issues",
		"POST /repos/dono/repo/issues/7/comments", "PATCH /repos/dono/repo/issues/7",
		"PATCH /repos/dono/repo/issues/8", "POST /repos/dono/repo/issues/8/comments",
		"PATCH /repos/dono/repo/issues/9",
	}
	if strings.Join(feito, "\n") != strings.Join(want, "\n") {
		t.Fatalf("chamadas:\n%s", strings.Join(feito, "\n"))
	}
	ch := *chamadas
	if ch[0].Corpo["labels"].([]any)[1] != "P2" || !strings.Contains(ch[0].Corpo["body"].(string), "<!-- crivo:") {
		t.Errorf("issue nova sem label ou sem marcador: %v", ch[0].Corpo)
	}
	if ch[2].Corpo["state"] != "closed" || ch[2].Corpo["state_reason"] != "completed" {
		t.Errorf("fechamento errado: %v", ch[2].Corpo)
	}
	if fmt.Sprint(ch[5].Corpo["labels"]) != "[crivo time-x P2]" {
		t.Errorf("a troca de prioridade apagou label de gente: %v", ch[5].Corpo["labels"])
	}
}

func TestApplyStopsAtFirstErrorAndReportsProgress(t *testing.T) {
	c, chamadas := servidor(t, func(r *http.Request) (int, string) {
		if r.Method == http.MethodPatch {
			return 403, `{"message":"eco do que foi enviado: tok"}`
		}
		return 201, "{}"
	})
	plano := []lifecycle.Action{
		{Kind: lifecycle.Create, Triage: achado("a")},
		{Kind: lifecycle.Relabel, Issue: 2, Triage: achado("b")},
		{Kind: lifecycle.Create, Triage: achado("c")},
	}

	n, err := c.Apply(context.Background(), plano, agora)
	if n != 1 || err == nil || len(*chamadas) != 2 {
		t.Fatalf("n=%d err=%v chamadas=%d", n, err, len(*chamadas))
	}
	if strings.Contains(err.Error(), "tok") {
		t.Fatalf("o erro não pode repetir o corpo da resposta: %v", err)
	}
}

func TestRedirectIsNotFollowed(t *testing.T) {
	outro := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("o pedido não podia chegar aqui (Authorization: %q)", r.Header.Get("Authorization"))
	}))
	defer outro.Close()
	c, _ := servidor(t, func(r *http.Request) (int, string) { return 302, "" })
	c.HTTP.Transport = &redirecionador{destino: outro.URL}

	if _, err := c.Issues(context.Background()); err == nil {
		t.Fatal("redirecionamento deveria virar erro")
	}
}

// redirecionador responde 302 para outro host sem passar pelo servidor de teste.
type redirecionador struct{ destino string }

func (r *redirecionador) RoundTrip(req *http.Request) (*http.Response, error) {
	h := http.Header{}
	h.Set("Location", r.destino)
	return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
}

func TestOversizedResponseIsRejected(t *testing.T) {
	c, _ := servidor(t, func(*http.Request) (int, string) {
		return 200, "[" + strings.Repeat(" ", maxResponse) + "]"
	})
	if _, err := c.Issues(context.Background()); err == nil || !strings.Contains(err.Error(), "limite") {
		t.Fatalf("erro = %v", err)
	}
}
