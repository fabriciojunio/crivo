// Package enrich acrescenta ao achado o que se sabe sobre exploração real:
// a probabilidade do EPSS (FIRST) e a presença no catálogo KEV (CISA). As duas
// fontes são públicas e gratuitas.
package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultEPSSURL = "https://api.first.org/data/v1/epss"
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

	// O catálogo KEV inteiro tem poucos megabytes; o limite folgado protege
	// contra uma resposta adulterada no caminho que tente esgotar a memória.
	maxResponse = 20 << 20
	// A API do EPSS aceita vários CVEs por chamada, separados por vírgula.
	// Lotes de 50 mantêm a URL bem abaixo do limite comum de 8 KB.
	epssBatch = 50
)

// Client consulta o EPSS e o KEV.
type Client struct {
	HTTP    *http.Client
	EPSSURL string
	KEVURL  string
}

// NewClient cria um cliente com tempo limite. Sem ele, um servidor lento
// prenderia o pipeline até o job estourar.
func NewClient() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 20 * time.Second},
		EPSSURL: DefaultEPSSURL,
		KEVURL:  DefaultKEVURL,
	}
}

func (c *Client) getJSON(ctx context.Context, rawURL string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "crivo")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s respondeu %d", req.URL.Host, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return fmt.Errorf("resposta de %s maior que o limite", req.URL.Host)
	}
	return json.Unmarshal(data, v)
}

// EPSS devolve a probabilidade de exploração nos próximos 30 dias, de 0 a 1,
// para cada CVE que a FIRST conhece.
func (c *Client) EPSS(ctx context.Context, cves []string) (map[string]float64, error) {
	scores := make(map[string]float64, len(cves))
	for start := 0; start < len(cves); start += epssBatch {
		end := min(start+epssBatch, len(cves))
		u, err := url.Parse(c.EPSSURL)
		if err != nil {
			return nil, err
		}
		q := u.Query()
		q.Set("cve", strings.Join(cves[start:end], ","))
		u.RawQuery = q.Encode()

		var body struct {
			Data []struct {
				CVE  string `json:"cve"`
				EPSS string `json:"epss"`
			} `json:"data"`
		}
		if err := c.getJSON(ctx, u.String(), &body); err != nil {
			return nil, fmt.Errorf("consultando o EPSS: %w", err)
		}
		for _, d := range body.Data {
			if s, err := strconv.ParseFloat(d.EPSS, 64); err == nil {
				scores[d.CVE] = s
			}
		}
	}
	return scores, nil
}

// KEV devolve o conjunto de CVEs que a CISA confirmou como explorados.
func (c *Client) KEV(ctx context.Context) (map[string]bool, error) {
	var body struct {
		Vulnerabilities []struct {
			CVEID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := c.getJSON(ctx, c.KEVURL, &body); err != nil {
		return nil, fmt.Errorf("consultando o KEV: %w", err)
	}
	kev := make(map[string]bool, len(body.Vulnerabilities))
	for _, v := range body.Vulnerabilities {
		kev[v.CVEID] = true
	}
	return kev, nil
}
