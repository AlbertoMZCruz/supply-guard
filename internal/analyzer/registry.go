package analyzer

import "sync"

var (
	mu       sync.RWMutex
	registry []Analyzer
)

func Register(a Analyzer) {
	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, a)
}

func All() []Analyzer {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Analyzer, len(registry))
	copy(out, registry)
	return out
}

// ResetForTesting clears the registry. Only for use in tests.
func ResetForTesting() {
	mu.Lock()
	defer mu.Unlock()
	registry = nil
}
