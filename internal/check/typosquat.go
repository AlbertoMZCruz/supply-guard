package check

import (
	"encoding/json"
	"strings"
	"sync"

	"github.com/AlbertoMZCruz/supply-guard/data"
)

type PopularPackages struct {
	Npm   []string `json:"npm"`
	Pip   []string `json:"pip"`
	Cargo []string `json:"cargo"`
	Nuget []string `json:"nuget"`
	Maven []string `json:"maven"`
}

var (
	popularPkgs     *PopularPackages
	popularPkgsOnce sync.Once
	popularPkgsErr  error
)

func getPopularPackages() (*PopularPackages, error) {
	popularPkgsOnce.Do(func() {
		popularPkgs = &PopularPackages{}
		popularPkgsErr = json.Unmarshal(data.PopularPackagesJSON, popularPkgs)
	})
	return popularPkgs, popularPkgsErr
}

// CheckTyposquatting checks if a package name is suspiciously similar to a popular package.
// Returns the popular package name and the edit distance if a match is found.
func CheckTyposquatting(ecosystem, name string, maxDistance int) (string, int, error) {
	pkgs, err := getPopularPackages()
	if err != nil {
		return "", 0, err
	}

	var popularList []string
	switch ecosystem {
	case "npm":
		popularList = pkgs.Npm
	case "pip":
		popularList = pkgs.Pip
	case "cargo":
		popularList = pkgs.Cargo
	case "nuget":
		popularList = pkgs.Nuget
	case "maven":
		popularList = pkgs.Maven
	default:
		return "", 0, nil
	}

	lowerName := strings.ToLower(name)

	for _, popular := range popularList {
		lowerPopular := strings.ToLower(popular)

		if lowerName == lowerPopular {
			return "", 0, nil
		}

		dist := levenshtein(lowerName, lowerPopular)
		if dist > 0 && dist <= maxDistance {
			return popular, dist, nil
		}
	}

	return "", 0, nil
}

func levenshtein(a, b string) int {
	la, lb := len(a), len(b)

	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}

	prev := make([]int, lb+1)
	curr := make([]int, lb+1)

	for j := 0; j <= lb; j++ {
		prev[j] = j
	}

	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = min(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}

	return prev[lb]
}
