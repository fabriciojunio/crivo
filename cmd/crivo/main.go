// Comando crivo: junta os relatórios de segurança de um projeto, prioriza o
// que está aberto e barra o pipeline quando passa do limite combinado.
//
//	crivo -osv osv.json -sarif codeql.sarif -zap zap.json -aceites aceites.json -falhar-em P2
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fabriciojunio/crivo/internal/accept"
	"github.com/fabriciojunio/crivo/internal/enrich"
	"github.com/fabriciojunio/crivo/internal/finding"
	"github.com/fabriciojunio/crivo/internal/parser"
	"github.com/fabriciojunio/crivo/internal/priority"
	"github.com/fabriciojunio/crivo/internal/report"
	"github.com/fabriciojunio/crivo/internal/summary"
)

// Códigos de saída. O pipeline distingue "achou o que barra" de "não
// conseguiu rodar": o segundo não pode passar como se estivesse tudo certo.
const (
	exitOK      = 0
	exitBlocked = 1
	exitError   = 2
)

type files []string

func (f *files) String() string     { return strings.Join(*f, ",") }
func (f *files) Set(v string) error { *f = append(*f, v); return nil }

// deps é o que o teste troca: relógio e cliente do enriquecimento.
type deps struct {
	now    func() time.Time
	enrich *enrich.Client
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, deps{now: time.Now, enrich: enrich.NewClient()}))
}

func run(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("crivo", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var osv, sarif, zap files
	fs.Var(&osv, "osv", "saída JSON do OSV-Scanner (pode repetir)")
	fs.Var(&sarif, "sarif", "relatório SARIF do CodeQL ou do Semgrep (pode repetir)")
	fs.Var(&zap, "zap", "relatório JSON do OWASP ZAP (pode repetir)")
	acceptFile := fs.String("aceites", "", "arquivo JSON com os riscos aceitos e o prazo de cada um")
	offline := fs.Bool("offline", false, "não consulta EPSS nem KEV")
	failAt := fs.String("falhar-em", "P2", "barra o pipeline com achado deste nível ou mais urgente (P1 a P4, ou nunca)")
	format := fs.String("formato", "md", "md ou json")
	model := fs.String("resumo", "", "modelo do Ollama local para resumir a triagem (opcional)")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	limit, err := parseLimit(*failAt)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	if len(osv)+len(sarif)+len(zap) == 0 {
		fmt.Fprintln(stderr, "nenhum relatório informado: use -osv, -sarif ou -zap")
		return exitError
	}

	var all []finding.Finding
	for _, group := range []struct {
		format parser.Format
		paths  files
	}{{parser.FormatOSV, osv}, {parser.FormatSARIF, sarif}, {parser.FormatZAP, zap}} {
		for _, path := range group.paths {
			found, err := readReport(group.format, path)
			if err != nil {
				fmt.Fprintf(stderr, "%s: %v\n", path, err)
				return exitError
			}
			all = append(all, found...)
		}
	}
	all = finding.Dedupe(all)

	var accepted accept.List
	if *acceptFile != "" {
		// #nosec G304 -- arquivo de aceites indicado por quem roda a ferramenta.
		f, err := os.Open(*acceptFile)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		accepted, err = accept.Load(f)
		f.Close()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	now := d.now()
	res := report.Result{Generated: now, Offline: *offline}

	epss, kev := map[string]float64{}, map[string]bool{}
	if !*offline {
		epss, kev, err = enrichAll(ctx, d.enrich, all)
		if err != nil {
			// Sem enriquecimento a triagem ainda vale, só fica mais pessimista
			// com o que não é explorado. Avisa e segue, em vez de esconder.
			fmt.Fprintf(stderr, "aviso: %v; seguindo só com a severidade\n", err)
			res.Offline = true
		}
	}

	expiredSeen := map[string]bool{}
	for _, f := range all {
		ok, expired := accepted.Match(f, now)
		if ok {
			res.Accepted++
			continue
		}
		if expired != nil && !expiredSeen[expired.Rule+expired.Package] {
			expiredSeen[expired.Rule+expired.Package] = true
			res.Expired = append(res.Expired, *expired)
		}
		res.Open = append(res.Open, priority.Decide(f, epss, kev, now))
	}
	priority.Sort(res.Open)

	if *model != "" && len(res.Open) > 0 {
		text, err := summary.New(*model).Summarize(ctx, res.Open)
		if err != nil {
			fmt.Fprintf(stderr, "aviso: resumo não gerado: %v\n", err)
		} else {
			res.Summary = text
		}
	}

	switch *format {
	case "json":
		err = report.JSON(stdout, res)
	case "md":
		err = report.Markdown(stdout, res)
	default:
		err = fmt.Errorf("formato de saída desconhecido: %q", *format)
	}
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	for _, t := range res.Open {
		if t.Level <= limit {
			return exitBlocked
		}
	}
	if len(res.Expired) > 0 && limit != 0 {
		// Aceite vencido barra igual a achado: é um risco que ninguém revisou.
		return exitBlocked
	}
	return exitOK
}

func readReport(format parser.Format, path string) ([]finding.Finding, error) {
	// #nosec G304 -- abrir o arquivo indicado na linha de comando é o propósito
	// da ferramenta; quem a roda já tem acesso a ele. O conteúdo é limitado e
	// validado pelo leitor.
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parser.Parse(format, f)
}

func enrichAll(ctx context.Context, c *enrich.Client, all []finding.Finding) (map[string]float64, map[string]bool, error) {
	seen := map[string]bool{}
	var cves []string
	for _, f := range all {
		for _, cve := range f.CVEs() {
			if !seen[cve] {
				seen[cve] = true
				cves = append(cves, cve)
			}
		}
	}
	if len(cves) == 0 {
		return map[string]float64{}, map[string]bool{}, nil
	}
	epss, err := c.EPSS(ctx, cves)
	if err != nil {
		return nil, nil, err
	}
	kev, err := c.KEV(ctx)
	if err != nil {
		return nil, nil, err
	}
	return epss, kev, nil
}

// parseLimit traduz o -falhar-em. Zero quer dizer nunca barrar.
func parseLimit(s string) (priority.Level, error) {
	switch strings.ToUpper(s) {
	case "P1":
		return priority.P1, nil
	case "P2":
		return priority.P2, nil
	case "P3":
		return priority.P3, nil
	case "P4":
		return priority.P4, nil
	case "NUNCA":
		return 0, nil
	default:
		return 0, errors.New("-falhar-em aceita P1, P2, P3, P4 ou nunca")
	}
}
