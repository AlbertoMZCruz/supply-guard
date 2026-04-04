package ci

import "os"

type Environment string

const (
	EnvLocal            Environment = "local"
	EnvGitHubActions    Environment = "github-actions"
	EnvGitLabCI         Environment = "gitlab-ci"
	EnvAzureDevOps      Environment = "azure-devops"
	EnvJenkins          Environment = "jenkins"
	EnvBitbucket        Environment = "bitbucket"
	EnvGenericCI        Environment = "generic-ci"
)

func Detect() Environment {
	if os.Getenv("GITHUB_ACTIONS") == "true" {
		return EnvGitHubActions
	}
	if os.Getenv("GITLAB_CI") == "true" {
		return EnvGitLabCI
	}
	if os.Getenv("TF_BUILD") == "True" {
		return EnvAzureDevOps
	}
	if os.Getenv("JENKINS_URL") != "" {
		return EnvJenkins
	}
	if os.Getenv("BITBUCKET_PIPELINE_UUID") != "" {
		return EnvBitbucket
	}
	if os.Getenv("CI") == "true" || os.Getenv("CI") == "1" {
		return EnvGenericCI
	}
	return EnvLocal
}

func IsCI() bool {
	return Detect() != EnvLocal
}
