package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fabriciojunio/crivo/internal/enrich"
)

const td = "../../testdata/"

var fixed = func() time.Time { return time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC) }

func offlineDeps() deps { return deps{now: fixed, enrich: enrich.NewClient()} }

func TestOfflineTriageOfRealReports(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-offline", "-osv", td + "osv.json", "-sarif", td + "semgrep.sarif", "-zap", td + "zap.json", "-formato", "json"}, &out, &errOut, offlineDeps())
	// O Semgrep traz achados de nível alta (P2), e o limite padrão é P2.
	if code != exitBlocked {
		t.Fatalf("código = %d, quero %d; stderr: %s", code, exitBlocked, errOut.String())
	}
	var res struct {
		Abertos []struct {
			Prioridade int    `json:"prioridade"`
			Fonte      string `json:"fonte"`
		} `json:"abertos"`
	}
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	fontes := map[string]bool{}
	for _, a := range res.Abertos {
		fontes[a.Fonte] = true
	}
	for _, f := range []string{"osv-scanner", "Semgrep OSS", "zap"} {
		if !fontes[f] {
			t.Errorf("faltou achado de %s", f)
		}
	}
	for i := 1; i < len(res.Abertos); i++ {
		if res.Abertos[i].Prioridade < res.Abertos[i-1].Prioridade {
			t.Fatal("saída fora de ordem de prioridade")
		}
	}
}

func TestAcceptancesAndNeverBlock(t *testing.T) {
	dir := t.TempDir()
	aceites := filepath.Join(dir, "aceites.json")
	os.WriteFile(aceites, []byte(`[
	  {"regra":"10098","motivo":"Vercel em arquivo estático","ate":"2027-04-28"},
	  {"regra":"10049","motivo":"conteúdo público","ate":"2026-01-01"}
	]`), 0o600)

	var out, errOut bytes.Buffer
	code := run([]string{"-offline", "-zap", td + "zap.json", "-aceites", aceites, "-falhar-em", "nunca"}, &out, &errOut, offlineDeps())
	if code != exitOK {
		t.Fatalf("com -falhar-em nunca o código deveria ser 0, veio %d: %s", code, errOut.String())
	}
	md := out.String()
	if !strings.Contains(md, "Aceitos com prazo: 1") {
		t.Errorf("o aceite válido não foi contado:\n%s", md)
	}
	if !strings.Contains(md, "`10049` venceu em 2026-01-01") {
		t.Errorf("o aceite vencido não foi apontado:\n%s", md)
	}
}

func TestExpiredAcceptanceBlocks(t *testing.T) {
	dir := t.TempDir()
	aceites := filepath.Join(dir, "aceites.json")
	os.WriteFile(aceites, []byte(`[{"regra":"10049","motivo":"m","ate":"2026-01-01"}]`), 0o600)
	var out, errOut bytes.Buffer
	code := run([]string{"-offline", "-zap", td + "zap.json", "-aceites", aceites, "-falhar-em", "P1"}, &out, &errOut, offlineDeps())
	if code != exitBlocked {
		t.Fatalf("aceite vencido deveria barrar mesmo sem achado P1, veio %d", code)
	}
}

func TestEnrichmentRaisesPriority(t *testing.T) {
	// Servidor falso no lugar da FIRST e da CISA: o CVE do deepmerge entra no
	// KEV e o achado médio sobe para P1.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "kev") {
			fmt.Fprint(w, `{"vulnerabilities":[{"cveID":"CVE-2026-93753"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":[]}`)
	}))
	defer srv.Close()
	c := enrich.NewClient()
	c.EPSSURL = srv.URL + "/epss"
	c.KEVURL = srv.URL + "/kev"

	var out, errOut bytes.Buffer
	code := run([]string{"-osv", td + "osv.json", "-falhar-em", "P1", "-formato", "json"}, &out, &errOut, deps{now: fixed, enrich: c})
	if code != exitBlocked {
		t.Fatalf("achado no KEV deveria barrar em P1, veio %d: %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), `"kev": true`) {
		t.Errorf("KEV não marcado:\n%s", out.String())
	}
}

func TestEnrichmentFailureFallsBackWithWarning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := enrich.NewClient()
	c.EPSSURL, c.KEVURL = srv.URL, srv.URL

	var out, errOut bytes.Buffer
	run([]string{"-osv", td + "osv.json", "-falhar-em", "nunca"}, &out, &errOut, deps{now: fixed, enrich: c})
	if !strings.Contains(errOut.String(), "aviso:") || !strings.Contains(out.String(), "modo offline") {
		t.Fatalf("a falha do enriquecimento tem que aparecer:\nstderr=%s\nout=%s", errOut.String(), out.String())
	}
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{
		{},
		{"-osv", "nao-existe.json"},
		{"-osv", td + "osv.json", "-falhar-em", "P9"},
		{"-osv", td + "osv.json", "-formato", "xml", "-offline"},
	}
	for _, args := range cases {
		var out, errOut bytes.Buffer
		if code := run(args, &out, &errOut, offlineDeps()); code != exitError {
			t.Errorf("%v: código = %d, quero %d", args, code, exitError)
		}
	}
}
