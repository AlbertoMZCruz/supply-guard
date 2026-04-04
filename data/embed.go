package data

import _ "embed"

//go:embed iocs.json
var IOCsJSON []byte

//go:embed popular_packages.json
var PopularPackagesJSON []byte

//go:embed default_policy.yaml
var DefaultPolicyYAML []byte
