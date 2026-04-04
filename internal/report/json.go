package report

import (
	"encoding/json"
	"io"

	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type JSONReporter struct{}

func (r *JSONReporter) Report(w io.Writer, result *types.ScanResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
