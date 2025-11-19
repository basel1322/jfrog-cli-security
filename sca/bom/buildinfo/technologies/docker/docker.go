package docker

import (
	"fmt"
	"strings"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

const (
	dockerPackagePrefix = "docker://"
)

type DockerRef struct {
	Ref     string `json:"ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
	node    *xrayUtils.GraphNode
}

func (dr *DockerRef) NodeName() string {
	return dr.Ref
}

func (dr *DockerRef) Node(children ...*xrayUtils.GraphNode) *xrayUtils.GraphNode {
	if dr.node == nil {
		dr.node = &xrayUtils.GraphNode{Id: dr.NodeName()}
	}
	dr.node.Nodes = children
	return dr.node
}

type DockerGraphInput struct {
	Graph DockerGraph `json:"graph"`
}

type DockerGraph struct {
	Nodes map[string]DockerRef `json:"nodes"`
}

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	return calculateDependencies(params.DockerImageName, currentDir, params)
}

func calculateDependencies(imageName, workingDir string, params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if imageName == "" {
		return []*xrayUtils.GraphNode{}, []string{}, fmt.Errorf("Docker image name is required")
	}

	imageName = strings.TrimSpace(imageName)
	if idx := strings.Index(imageName, ","); idx > 0 {
		imageName = strings.TrimSpace(imageName[:idx])
	}
	imageName = strings.TrimSuffix(imageName, "/")

	dockerInput, err := buildDockerDependencyGraph(imageName)
	if err != nil {
		return nil, nil, fmt.Errorf("error building Docker dependency graph: %w", err)
	}

	if dockerInput == nil || len(dockerInput.Graph.Nodes) == 0 {
		return []*xrayUtils.GraphNode{}, []string{}, nil
	}

	var imageRef string
	for ref := range dockerInput.Graph.Nodes {
		imageRef = ref
		break
	}
	if imageRef == "" {
		return []*xrayUtils.GraphNode{}, []string{}, nil
	}

	dockerRef := dockerInput.Graph.Nodes[imageRef]
	imageNode := dockerRef.Node()
	// Create a virtual root node with the image as a child, so fillGraphRelations can process it
	rootNode := &xrayUtils.GraphNode{
		Id:    "root",
		Nodes: []*xrayUtils.GraphNode{imageNode},
	}
	dependencyTrees = []*xrayUtils.GraphNode{rootNode}
	uniqueDeps = []string{imageRef}
	return
}

func buildDockerDependencyGraph(imageName string) (*DockerGraphInput, error) {
	repo := ExtractDockerRepoFromImagePath(imageName)
	pkgName, pkgVersion := extractFromTag(imageName, repo)
	if pkgName == "" {
		pkgName = "unknown"
	}
	if strings.HasPrefix(pkgName, "library/") {
		pkgName = strings.TrimPrefix(pkgName, "library/")
	}
	imageRef := dockerPackagePrefix + pkgName + ":" + pkgVersion
	dockerRefMap := map[string]DockerRef{
		imageRef: {
			Ref:     imageRef,
			Name:    pkgName,
			Version: pkgVersion,
		},
	}
	return &DockerGraphInput{Graph: DockerGraph{Nodes: dockerRefMap}}, nil
}

func extractFromTag(tag, repo string) (name, version string) {
	lastColon := strings.LastIndex(tag, ":")
	if lastColon > 0 {
		beforeColon := tag[:lastColon]
		if strings.Contains(beforeColon, "/") {
			name = extractImageNameWithNamespace(beforeColon, repo)
		} else {
			name = beforeColon
		}
		version = tag[lastColon+1:]
		return
	}
	name = extractImageNameWithNamespace(tag, repo)
	version = "latest"
	return
}

func extractImageNameWithNamespace(imagePath, repo string) string {
	lastColon := strings.LastIndex(imagePath, ":")
	if lastColon > 0 {
		imagePath = imagePath[:lastColon]
	}
	if repo == "" {
		return imagePath
	}
	parts := strings.Split(imagePath, "/")
	if len(parts) == 0 {
		return imagePath
	}
	firstPart := parts[0]
	isRegistry := strings.Contains(firstPart, ".") || firstPart == "docker.io" || strings.Contains(firstPart, ":")
	if isRegistry {
		for i, part := range parts {
			if part == repo && i+1 < len(parts) {
				return strings.Join(parts[i+1:], "/")
			}
		}
		if len(parts) > 1 {
			return strings.Join(parts[1:], "/")
		}
	} else if len(parts) > 0 && parts[0] == repo {
		if len(parts) > 1 {
			return strings.Join(parts[1:], "/")
		}
		return ""
	}
	return strings.Join(parts, "/")
}

func GetDockerArtifactoryUrl(serverUrl, artifactoryUrl string) string {
	var artiUrl string
	if artifactoryUrl != "" {
		artiUrl = artifactoryUrl
	} else if serverUrl != "" {
		artiUrl = strings.TrimSuffix(serverUrl, "/") + "/artifactory"
	}
	if artiUrl != "" && !strings.HasPrefix(artiUrl, "http://") && !strings.HasPrefix(artiUrl, "https://") {
		artiUrl = "https://" + strings.TrimPrefix(artiUrl, "//")
	}
	if artiUrl != "" && !strings.HasSuffix(artiUrl, "/artifactory") && !strings.Contains(artiUrl, "/artifactory/") {
		artiUrl = strings.TrimSuffix(artiUrl, "/") + "/artifactory"
	}
	artiUrl = strings.TrimSuffix(artiUrl, "/")
	return artiUrl
}

func GetDockerUrlAndRepo(rtAuthUrl string, serverDetails *config.ServerDetails, packageManagerConfig *project.RepositoryConfig, imageName string) (artiUrl, repo string) {
	if serverDetails == nil {
		return rtAuthUrl, ""
	}
	artiUrl = GetDockerArtifactoryUrl(serverDetails.Url, serverDetails.ArtifactoryUrl)
	if packageManagerConfig != nil {
		repo = packageManagerConfig.TargetRepo()
	}
	if repo == "" {
		repo = ExtractDockerRepoFromImagePath(imageName)
	}
	return
}

func GetDockerRepositoryConfig(serverDetails *config.ServerDetails, imageName, depsRepo, packageManagerRepo string) *project.RepositoryConfig {
	dockerRepo := packageManagerRepo
	if dockerRepo == "" {
		dockerRepo = ExtractDockerRepoFromImagePath(imageName)
	}
	if dockerRepo == "" {
		dockerRepo = depsRepo
	}
	if dockerRepo == "" {
		return nil
	}
	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(dockerRepo)
	return repoConfig
}

func SetDockerRepo(serverDetails *config.ServerDetails, imageName, depsRepo string, existingRepoConfig *project.RepositoryConfig) *project.RepositoryConfig {
	packageManagerRepo := ""
	if existingRepoConfig != nil {
		packageManagerRepo = existingRepoConfig.TargetRepo()
	}
	return GetDockerRepositoryConfig(serverDetails, imageName, depsRepo, packageManagerRepo)
}

func ExtractDockerRepoFromImagePath(imagePath string) string {
	lastColon := strings.LastIndex(imagePath, ":")
	if lastColon > 0 && strings.Contains(imagePath[:lastColon], "/") {
		imagePath = imagePath[:lastColon]
	}
	parts := strings.Split(imagePath, "/")
	if len(parts) < 2 {
		return ""
	}
	firstPart := parts[0]
	isRegistry := strings.Contains(firstPart, ".") || firstPart == "docker.io" || strings.Contains(firstPart, ":")
	if isRegistry {
		if firstPart == "docker.io" {
			return ""
		}
		if len(parts) >= 3 {
			return parts[1]
		}
		return ""
	}
	return parts[0]
}
