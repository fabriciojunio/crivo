// Package parser lê os relatórios das ferramentas e devolve achados no
// formato comum. Cada leitor recebe um io.Reader para o teste não depender de
// arquivo e para o fuzzing alimentar bytes direto.
package parser

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/fabriciojunio/crivo/internal/finding"
)

// MaxInput é o maior relatório aceito. O arquivo vem de outra ferramenta e,
// num pipeline comprometido, de um atacante: ler sem limite seria entregar a
// memória do executor a quem escreveu o arquivo.
const MaxInput = 50 << 20

// ErrTooLarge avisa que o relatório passou do limite.
var ErrTooLarge = errors.New("relatório maior que o limite de 50 MB")

// Format identifica o tipo de relatório.
type Format string

const (
	FormatSARIF Format = "sarif"
	FormatOSV   Format = "osv"
	FormatZAP   Format = "zap"
)

// Parse lê um relatório no formato indicado.
func Parse(format Format, r io.Reader) ([]finding.Finding, error) {
	data, err := io.ReadAll(io.LimitReader(r, MaxInput+1))
	if err != nil {
		return nil, fmt.Errorf("lendo o relatório: %w", err)
	}
	if len(data) > MaxInput {
		return nil, ErrTooLarge
	}
	switch format {
	case FormatSARIF:
		return parseSARIF(data)
	case FormatOSV:
		return parseOSV(data)
	case FormatZAP:
		return parseZAP(data)
	default:
		return nil, fmt.Errorf("formato desconhecido: %q", format)
	}
}

func decode(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("JSON inválido: %w", err)
	}
	return nil
}
