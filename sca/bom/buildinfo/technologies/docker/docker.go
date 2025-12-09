package docker

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	rtUtils "github.com/jfrog/jfrog-cli-core/v2/artifactory/utils"
	"github.com/jfrog/jfrog-client-go/auth"
	"github.com/jfrog/jfrog-client-go/utils/io/httputils"
	"github.com/jfrog/jfrog-client-go/utils/log"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

const dockerPackagePrefix = "docker://"

// getDockerArch returns the Docker daemon architecture, falls back to runtime.GOARCH
func getDockerArch() string {
	cmd := exec.Command("docker", "version", "--format", "{{.Server.Arch}}")
	output, err := cmd.Output()
	if err != nil {
		return runtime.GOARCH
	}
	arch := strings.TrimSpace(string(output))
	if arch == "" {
		return runtime.GOARCH
	}
	return arch
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if params.DockerImageName == "" {
		return nil, nil, fmt.Errorf("docker image name is required")
	}

	log.Debug(fmt.Sprintf("Using architecture: %s", getDockerArch()))

	repo, pkgName, pkgVersion := extractRepoImageAndTag(params.DockerImageName)
	if repo == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/image:tag'", params.DockerImageName)
	}
	if pkgName == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Image name is missing", params.DockerImageName)
	}

	imageRef := getImageRef(params, repo, pkgName, pkgVersion)

	return []*xrayUtils.GraphNode{{Id: "root", Nodes: []*xrayUtils.GraphNode{{Id: imageRef}}}},
		[]string{imageRef}, nil
}

func getImageRef(params technologies.BuildInfoBomGeneratorParams, repo, pkgName, pkgVersion string) string {
	if params.ServerDetails == nil || (params.ServerDetails.ArtifactoryUrl == "" && params.ServerDetails.Url == "") {
		return dockerPackagePrefix + pkgName + ":" + pkgVersion
	}

	if digest := getArchDigest(params, repo, pkgName, pkgVersion); digest != "" {
		return dockerPackagePrefix + pkgName + ":" + digest
	}

	return dockerPackagePrefix + pkgName + ":" + pkgVersion
}

func getArchDigest(params technologies.BuildInfoBomGeneratorParams, repo, pkgName, pkgVersion string) string {
	rtManager, err := rtUtils.CreateServiceManager(params.ServerDetails, 2, 0, false)
	if err != nil {
		return ""
	}

	rtAuth, err := params.ServerDetails.CreateArtAuthConfig()
	if err != nil {
		return ""
	}

	manifestUrl := buildManifestUrl(params.ServerDetails, repo, pkgName, pkgVersion)
	httpClientDetails := createHttpClientDetails(rtAuth)

	resp, _, err := rtManager.Client().SendHead(manifestUrl, &httpClientDetails)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return ""
	}

	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "manifest.list") && !strings.Contains(contentType, "image.index") {
		return ""
	}

	resp, body, _, err := rtManager.Client().SendGet(manifestUrl, false, &httpClientDetails)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return ""
	}

	var manifestList dockerManifestList
	if err := json.Unmarshal(body, &manifestList); err != nil || len(manifestList.Manifests) == 0 {
		return ""
	}

	currentArch := getDockerArch()
	for _, m := range manifestList.Manifests {
		if m.Platform.OS == "linux" && m.Platform.Architecture == currentArch && m.Digest != "" {
			return m.Digest
		}
	}

	for _, m := range manifestList.Manifests {
		if m.Platform.Architecture == currentArch && m.Digest != "" {
			return m.Digest
		}
	}

	return ""
}

func buildManifestUrl(serverDetails *config.ServerDetails, repo, pkgName, pkgVersion string) string {
	artiUrl := serverDetails.ArtifactoryUrl
	if artiUrl == "" {
		artiUrl = strings.TrimSuffix(serverDetails.Url, "/") + "/artifactory"
	}
	return fmt.Sprintf("%s/api/docker/%s/v2/%s/manifests/%s",
		strings.TrimSuffix(artiUrl, "/"), repo, pkgName, pkgVersion)
}

func createHttpClientDetails(rtAuth auth.ServiceDetails) httputils.HttpClientDetails {
	details := rtAuth.CreateHttpClientDetails()
	details.Headers["Accept"] = "application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/json"
	return details
}

// extractRepoImageAndTag extracts repo, image and tag from format: repo/image:tag
func extractRepoImageAndTag(imagePath string) (repo, image, tag string) {
	tag = "latest"
	if idx := strings.LastIndex(imagePath, ":"); idx > 0 {
		tag = imagePath[idx+1:]
		imagePath = imagePath[:idx]
	}

	parts := strings.Split(imagePath, "/")
	if len(parts) < 2 {
		return "", imagePath, tag
	}

	return parts[0], strings.Join(parts[1:], "/"), tag
}

// GetDockerRepoConfig extracts repository config from image name (format: repo/image:tag)
func GetDockerRepoConfig(serverDetails *config.ServerDetails, imageName, depsRepo string) (*project.RepositoryConfig, error) {
	if imageName == "" {
		return nil, fmt.Errorf("docker image name is required")
	}
	if serverDetails == nil {
		return nil, fmt.Errorf("server details are required")
	}

	repo, _, _ := extractRepoImageAndTag(imageName)
	if repo == "" {
		repo = depsRepo
	}
	if repo == "" {
		return nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/image:tag'", imageName)
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(repo)
	return repoConfig, nil
}

type dockerManifestList struct {
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}
