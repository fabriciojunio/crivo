package enrich

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestEPSSBatchesAndParses(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var data []string
		for _, cve := range strings.Split(r.URL.Query().Get("cve"), ",") {
			data = append(data, fmt.Sprintf(`{"cve":%q,"epss":"0.25"}`, cve))
		}
		fmt.Fprintf(w, `{"data":[%s]}`, strings.Join(data, ","))
	}))
	defer srv.Close()

	c := NewClient()
	c.EPSSURL = srv.URL
	var cves []string
	for i := range 120 {
		cves = append(cves, fmt.Sprintf("CVE-2026-%d", i))
	}
	got, err := c.EPSS(context.Background(), cves)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 {
		t.Errorf("chamadas = %d, quero 3 lotes de até 50", calls)
	}
	if len(got) != 120 || got["CVE-2026-7"] != 0.25 {
		t.Errorf("notas = %d, CVE-2026-7 = %v", len(got), got["CVE-2026-7"])
	}
}

func TestKEVParsesCatalog(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2024-3400"}]}`)
	}))
	defer srv.Close()

	c := NewClient()
	c.KEVURL = srv.URL
	got, err := c.KEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !got["CVE-2021-44228"] || got["CVE-2099-1"] {
		t.Errorf("kev = %v", got)
	}
}

func TestErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := NewClient()
	c.KEVURL = srv.URL
	if _, err := c.KEV(context.Background()); err == nil {
		t.Fatal("503 deveria virar erro, e não catálogo vazio")
	}
}

func TestRejectsOversizedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"vulnerabilities":"`)
		fmt.Fprint(w, strings.Repeat("a", maxResponse))
		fmt.Fprint(w, `"}`)
	}))
	defer srv.Close()

	c := NewClient()
	c.KEVURL = srv.URL
	if _, err := c.KEV(context.Background()); err == nil {
		t.Fatal("resposta acima do limite deveria ser recusada")
	}
}

func TestRespectsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(300 * time.Millisecond)
	}))
	defer srv.Close()

	c := NewClient()
	c.KEVURL = srv.URL
	c.HTTP.Timeout = 50 * time.Millisecond
	if _, err := c.KEV(context.Background()); err == nil {
		t.Fatal("servidor lento deveria estourar o tempo")
	}
}
