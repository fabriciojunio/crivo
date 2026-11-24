package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"

	"github.com/fabriciojunio/crivo/internal/github"
	"github.com/fabriciojunio/crivo/internal/lifecycle"
	"github.com/fabriciojunio/crivo/internal/priority"
)

// runSync é o "crivo sincronizar": a mesma triagem, mas em vez de barrar o
// pipeline ela vira issue com dono e prazo. Achado novo abre, corrigido fecha,
// o que voltou reabre.
//
//	crivo sincronizar -repo dono/nome -osv osv.json -sarif semgrep.sarif [-simular]
func runSync(args []string, stdout, stderr io.Writer, d deps) int {
	fs := flag.NewFlagSet("crivo sincronizar", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var in inputs
	in.register(fs)
	repo := fs.String("repo", d.getenv("GITHUB_REPOSITORY"), "repositório das issues, dono/nome (padrão: GITHUB_REPOSITORY)")
	simulate := fs.Bool("simular", false, "mostra o plano sem mexer nas issues; com GITHUB_TOKEN lê as que existem")
	if err := fs.Parse(args); err != nil {
		return exitError
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	res, err := triage(ctx, in, stderr, d)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}

	token := d.getenv("GITHUB_TOKEN")
	var client *github.Client
	var issues []lifecycle.Issue
	if !*simulate || token != "" {
		client, err = github.New(*repo, token)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
		if d.githubAPI != "" {
			client.API = d.githubAPI
		}
		issues, err = client.Issues(ctx)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return exitError
		}
	}

	plan := lifecycle.Plan(res.Open, issues)
	for _, a := range plan {
		if a.Kind == lifecycle.Close {
			fmt.Fprintf(stdout, "%-20s #%d\n", a.Kind, a.Issue)
			continue
		}
		alvo := plain(a.Triage)
		if a.Issue != 0 {
			alvo = fmt.Sprintf("#%d %s", a.Issue, alvo)
		}
		fmt.Fprintf(stdout, "%-20s %s\n", a.Kind, alvo)
	}
	if len(plan) == 0 {
		fmt.Fprintln(stdout, "nada a fazer: as issues já refletem a varredura")
	}
	if *simulate {
		return exitOK
	}

	n, err := client.Apply(ctx, plan, d.now())
	fmt.Fprintf(stdout, "%d de %d ações aplicadas\n", n, len(plan))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return exitError
	}
	return exitOK
}

// plain descreve o achado para o terminal. Sem escape de Markdown, que só serve
// na issue, e sem caractere de controle: uma sequência ANSI no nome da regra
// apagaria ou falsificaria linhas do log do CI.
func plain(t priority.Triage) string {
	alvo := t.Package
	if alvo == "" {
		alvo = t.Location
	}
	s := fmt.Sprintf("[%s] %s em %s", t.Level, t.Rule, alvo)
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}
