package analyzer

import (
	"context"

	"github.com/AlbertoMZCruz/supply-guard/internal/config"
	"github.com/AlbertoMZCruz/supply-guard/internal/types"
)

type Analyzer interface {
	Name() string
	Ecosystem() string
	Detect(dir string) bool
	Analyze(ctx context.Context, dir string, cfg *config.Config) ([]types.Finding, error)
}
