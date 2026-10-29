# crivo

*[Read this in English](README.en.md)*

Triagem de vulnerabilidades para pipeline de CI, escrita em Go e sem nenhuma dependência externa.

O crivo junta os relatórios que as ferramentas de segurança já produzem (CodeQL e Semgrep em SARIF,
OSV-Scanner e OWASP ZAP em JSON), tira as repetições, cruza cada CVE com o que se sabe sobre
exploração real e devolve uma fila com prioridade e prazo. No fim, barra o pipeline se sobrar algo
acima do limite combinado.

## Por que existe

Severidade sozinha prioriza errado nos dois sentidos. Uma falha "crítica" que ninguém explora pode
esperar a próxima sprint; uma "média" que está no catálogo de exploração ativa da CISA não pode. Por
isso o crivo usa duas fontes públicas e gratuitas:

- **KEV** (Known Exploited Vulnerabilities), da CISA: falhas confirmadas como exploradas.
- **EPSS** (Exploit Prediction Scoring System), da FIRST: probabilidade de exploração nos próximos
  30 dias.

## Regras de prioridade

A primeira regra que se aplica decide.

| Prioridade | Quando | Prazo |
|---|---|---|
| P1 | no KEV, ou severidade crítica, ou EPSS de 50% ou mais | 7 dias |
| P2 | severidade alta, ou EPSS de 10% ou mais | 30 dias |
| P3 | severidade média | 90 dias |
| P4 | baixa ou sem severidade | 180 dias |

## Uso

```bash
go build -trimpath -o crivo ./cmd/crivo

crivo -osv osv.json -sarif codeql.sarif -zap zap.json \
      -aceites aceites.json -falhar-em P2
```

| Opção | O que faz |
|---|---|
| `-osv`, `-sarif`, `-zap` | relatório de entrada; cada uma pode repetir |
| `-aceites` | riscos aceitos, com motivo e data de revisão |
| `-falhar-em` | `P1` a `P4`, ou `nunca`; o padrão é `P2` |
| `-formato` | `md` (tabela para o pull request) ou `json` |
| `-offline` | não consulta EPSS nem KEV |
| `-resumo` | nome de um modelo do Ollama local para resumir a triagem |

Saída `0` quando passa, `1` quando barra e `2` quando não conseguiu rodar. A diferença importa: erro
de leitura não pode passar como pipeline verde.

### Aceites

```json
[
  {"regra": "GHSA-gcqx-w48m-w2h4", "pacote": "npm:deepmerge",
   "motivo": "vem do Jest, só nos testes", "ate": "2027-01-28"}
]
```

Aceite sem motivo ou sem data é recusado na leitura. Aceite vencido volta a contar como aberto,
aparece no relatório e barra o pipeline: é um risco que ninguém revisou.

### Resumo por IA, opcional

Com `-resumo llama3.2`, o crivo pede a um modelo rodando no Ollama da própria máquina um resumo em
português para quem decide. Duas proteções:

- **Só endereço local.** O resumo leva nome de pacote, regra e caminho de arquivo; o cliente recusa
  qualquer endereço fora da máquina, para um erro de configuração não mandar o mapa de falhas do
  projeto a um serviço de terceiro.
- **Texto da ferramenta fica de fora do prompt.** A descrição do achado vem, no fim, de quem
  escreveu o código analisado; é por ela que alguém tentaria injetar instrução no modelo.

Sem o modelo, a triagem é a mesma.

## Segurança do próprio crivo

- Nenhuma dependência fora da biblioteca padrão do Go: a ferramenta que avalia a cadeia de
  suprimentos dos outros não traz cadeia nenhuma.
- Relatório de entrada limitado a 50 MB e resposta de rede limitada a 20 MB, com tempo limite em
  toda chamada.
- Fuzzing dos três leitores a cada push.
- Texto que vai para a tabela Markdown é neutralizado: nada de HTML nem quebra de tabela vinda do
  achado.
- No CI: `govulncheck`, `gosec` com a triagem feita pelo próprio crivo, e trava contra coautoria de
  ferramenta de IA no histórico.

## Testes

```bash
go test -race ./...
go test -run '^$' -fuzz FuzzParse -fuzztime 60s ./internal/parser
```

Os testes dos leitores usam saídas reais: o OSV-Scanner sobre o aplicativo do ConectAgente, o ZAP
baseline contra o AURORA publicado e o Semgrep sobre um arquivo vulnerável de propósito
(`testdata/`). O enriquecimento é testado contra um servidor falso, sem tocar na rede.

## Estrutura

```
cmd/crivo/          linha de comando
internal/finding/   achado normalizado, impressão digital, remoção de repetição
internal/parser/    leitores de SARIF, OSV e ZAP
internal/enrich/    EPSS e KEV
internal/priority/  regras de prioridade e prazo
internal/accept/    riscos aceitos com prazo
internal/report/    Markdown e JSON
internal/summary/   resumo opcional por modelo local
```
