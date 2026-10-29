# crivo

*[Leia em português](README.md)*

Vulnerability triage for CI pipelines, written in Go with no external dependencies.

crivo merges the reports security tools already produce (CodeQL and Semgrep as SARIF, OSV-Scanner
and OWASP ZAP as JSON), removes duplicates, checks each CVE against what is known about real-world
exploitation and returns a queue with priority and deadline. At the end it fails the pipeline if
anything is left above the agreed threshold.

## Why it exists

Severity alone gets priority wrong both ways. A "critical" flaw nobody exploits can wait for the
next sprint; a "medium" one listed in CISA's active exploitation catalogue cannot. So crivo uses two
free public sources:

- **KEV** (Known Exploited Vulnerabilities), from CISA: flaws confirmed as exploited.
- **EPSS** (Exploit Prediction Scoring System), from FIRST: probability of exploitation in the next
  30 days.

## Priority rules

The first rule that applies wins.

| Priority | When | Deadline |
|---|---|---|
| P1 | in KEV, or critical severity, or EPSS of 50% or more | 7 days |
| P2 | high severity, or EPSS of 10% or more | 30 days |
| P3 | medium severity | 90 days |
| P4 | low or no severity | 180 days |

## Usage

```bash
go build -trimpath -o crivo ./cmd/crivo

crivo -osv osv.json -sarif codeql.sarif -zap zap.json \
      -aceites aceites.json -falhar-em P2
```

| Flag | What it does |
|---|---|
| `-osv`, `-sarif`, `-zap` | input report; each can repeat |
| `-aceites` | accepted risks, with reason and review date |
| `-falhar-em` | `P1` to `P4`, or `nunca` (never); default `P2` |
| `-formato` | `md` (table for the pull request) or `json` |
| `-offline` | skips EPSS and KEV |
| `-resumo` | name of a local Ollama model to summarise the triage |

Exit code `0` when it passes, `1` when it blocks and `2` when it could not run. The difference
matters: a read error must not pass as a green pipeline.

### Acceptances

```json
[
  {"regra": "GHSA-gcqx-w48m-w2h4", "pacote": "npm:deepmerge",
   "motivo": "comes from Jest, tests only", "ate": "2027-01-28"}
]
```

An acceptance without a reason or a date is rejected on load. An expired acceptance counts as open
again, shows up in the report and blocks the pipeline: it is a risk nobody reviewed.

### Optional AI summary

With `-resumo llama3.2`, crivo asks a model running in Ollama on the same machine for a Portuguese
summary aimed at decision makers. Two safeguards:

- **Local addresses only.** The summary carries package names, rules and file paths; the client
  refuses any address outside the machine, so a configuration mistake cannot send the project's
  flaw map to a third-party service.
- **Tool-provided text stays out of the prompt.** A finding's description ultimately comes from
  whoever wrote the analysed code; that is where someone would try to inject instructions into the
  model.

Without the model, the triage is the same.

## crivo's own security

- No dependency beyond Go's standard library: the tool that assesses other projects' supply chain
  brings none of its own.
- Input reports capped at 50 MB and network responses at 20 MB, with a timeout on every call.
- Fuzzing of the three parsers on every push.
- Text written into the Markdown table is neutralised: no HTML or table breaks coming from a
  finding.
- In CI: `govulncheck`, `gosec` triaged by crivo itself, and a guard against AI co-authorship in the
  history.

## Tests

```bash
go test -race ./...
go test -run '^$' -fuzz FuzzParse -fuzztime 60s ./internal/parser
```

Parser tests use real outputs: OSV-Scanner on the ConectAgente app, ZAP baseline against the
published AURORA site and Semgrep on a deliberately vulnerable file (`testdata/`). Enrichment is
tested against a fake server, without touching the network.

## Layout

```
cmd/crivo/          command line
internal/finding/   normalised finding, fingerprint, deduplication
internal/parser/    SARIF, OSV and ZAP readers
internal/enrich/    EPSS and KEV
internal/priority/  priority and deadline rules
internal/accept/    time-boxed accepted risks
internal/report/    Markdown and JSON
internal/summary/   optional summary by a local model
```

## Use of AI

This project was structured with the support of generative AI tools. Modelling, business rules,
code review and conclusions were reviewed and validated by Fabrício Júnio.
