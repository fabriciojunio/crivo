package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestSyncSimulationWithoutTokenOnlyPrintsThePlan(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"sincronizar", "-simular", "-offline", "-osv", td + "osv.json"}, &out, &errOut, offlineDeps())
	if code != exitOK {
		t.Fatalf("código = %d, stderr = %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "abrir") {
		t.Fatalf("sem issues existentes, todo achado abre: %s", out.String())
	}
}

func TestSyncWithoutRepoOrTokenFails(t *testing.T) {
	for _, args := range [][]string{
		{"sincronizar", "-offline", "-osv", td + "osv.json"},
		{"sincronizar", "-offline", "-osv", td + "osv.json", "-repo", "../x"},
		{"sincronizar", "-offline"},
	} {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut, offlineDeps()); code != exitError {
			t.Errorf("%v: código = %d, stderr = %s", args, code, errOut.String())
		}
	}
}

func TestSyncAppliesThePlanAgainstTheAPI(t *testing.T) {
	var mu sync.Mutex
	var chamadas []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		mu.Lock()
		chamadas = append(chamadas, r.Method+" "+r.URL.Path)
		mu.Unlock()
		if r.Method == http.MethodGet {
			// Uma issue aberta de um achado que não aparece mais: tem que fechar.
			data, _ := json.Marshal([]map[string]any{{"number": 41, "state": "open",
				"body": "<!-- crivo:00000000000000ff -->", "labels": []map[string]string{{"name": "crivo"}}}})
			fmt.Fprint(w, string(data))
			return
		}
		w.WriteHeader(http.StatusCreated)
		fmt.Fprint(w, "{}")
	}))
	defer srv.Close()

	d := offlineDeps()
	d.githubAPI = srv.URL
	d.getenv = func(k string) string {
		return map[string]string{"GITHUB_TOKEN": "tok", "GITHUB_REPOSITORY": "dono/repo"}[k]
	}
	var out, errOut bytes.Buffer
	code := run([]string{"sincronizar", "-offline", "-osv", td + "osv.json"}, &out, &errOut, d)
	if code != exitOK {
		t.Fatalf("código = %d, stderr = %s, saída = %s", code, errOut.String(), out.String())
	}
	todas := strings.Join(chamadas, "\n")
	if !strings.Contains(todas, "POST /repos/dono/repo/issues\n") || !strings.Contains(todas, "PATCH /repos/dono/repo/issues/41") {
		t.Fatalf("chamadas:\n%s", todas)
	}
	if !strings.Contains(out.String(), "ações aplicadas") {
		t.Fatalf("saída sem o resumo: %s", out.String())
	}
}
