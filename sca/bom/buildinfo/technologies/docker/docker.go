package docker

import (
	"fmt"
	"strings"

	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/common/project"
	"github.com/jfrog/jfrog-cli-core/v2/utils/config"
	"github.com/jfrog/jfrog-cli-security/sca/bom/buildinfo/technologies"
)

const (
	dockerPackagePrefix = "docker://"
)

func BuildDependencyTree(params technologies.BuildInfoBomGeneratorParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	if params.DockerImageName == "" {
		return nil, nil, fmt.Errorf("docker image name is required")
	}

	imageName := strings.TrimSpace(params.DockerImageName)
	if idx := strings.Index(imageName, ","); idx > 0 {
		imageName = strings.TrimSpace(imageName[:idx])
	}
	imageName = strings.TrimSuffix(imageName, "/")

	repo, pkgName, pkgVersion := extractRepoImageAndTag(imageName)
	if repo == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/path/image:tag' or 'repo/image:tag'", imageName)
	}
	if pkgName == "" {
		return nil, nil, fmt.Errorf("invalid docker image format: '%s'. Image name is missing", imageName)
	}

	pkgName = strings.TrimPrefix(pkgName, "library/")

	imageRef := dockerPackagePrefix + pkgName + ":" + pkgVersion
	rootNode := &xrayUtils.GraphNode{
		Id:    "root",
		Nodes: []*xrayUtils.GraphNode{{Id: imageRef}},
	}

	return []*xrayUtils.GraphNode{rootNode}, []string{imageRef}, nil
}

func extractRepoImageAndTag(imagePath string) (repo, image, tag string) {
	tag = "latest"
	if lastColon := strings.LastIndex(imagePath, ":"); lastColon > 0 {
		tag = imagePath[lastColon+1:]
		imagePath = imagePath[:lastColon]
	}

	parts := strings.Split(imagePath, "/")
	if len(parts) < 2 {
		return "", imagePath, tag
	}

	return parts[0], strings.Join(parts[1:], "/"), tag
}

func GetDockerUrlAndRepo(serverDetails *config.ServerDetails, packageManagerConfig *project.RepositoryConfig, imageName string) (artiUrl, repo string) {
	if serverDetails == nil {
		return "", ""
	}

	artiUrl = serverDetails.ArtifactoryUrl
	if artiUrl == "" && serverDetails.Url != "" {
		artiUrl = strings.TrimSuffix(serverDetails.Url, "/") + "/artifactory"
	}

	if packageManagerConfig != nil {
		repo = packageManagerConfig.TargetRepo()
	}
	if repo == "" && imageName != "" {
		repo, _, _ = extractRepoImageAndTag(imageName)
	}

	return
}

func GetDockerRepositoryConfig(serverDetails *config.ServerDetails, imageName, depsRepo, packageManagerRepo string) (*project.RepositoryConfig, error) {
	repo := packageManagerRepo
	if repo == "" && imageName != "" {
		repo, _, _ = extractRepoImageAndTag(imageName)
	}
	if repo == "" {
		repo = depsRepo
	}
	if repo == "" {
		if imageName != "" {
			return nil, fmt.Errorf("invalid docker image format: '%s'. Expected format: 'repo/path/image:tag' or 'repo/image:tag'. Repository name is required", imageName)
		}
		return nil, fmt.Errorf("docker repository name is required")
	}

	repoConfig := &project.RepositoryConfig{}
	repoConfig.SetServerDetails(serverDetails).SetTargetRepo(repo)

	return repoConfig, nil
}

func SetDockerRepo(serverDetails *config.ServerDetails, imageName, depsRepo string, existingRepoConfig *project.RepositoryConfig) (*project.RepositoryConfig, error) {
	packageManagerRepo := ""
	if existingRepoConfig != nil {
		packageManagerRepo = existingRepoConfig.TargetRepo()
	}
	return GetDockerRepositoryConfig(serverDetails, imageName, depsRepo, packageManagerRepo)
}

func GetDockerRepoConfig(serverDetails *config.ServerDetails, imageName, depsRepo string) (*project.RepositoryConfig, error) {
	if imageName == "" {
		return nil, fmt.Errorf("docker image name is required. Use --image flag with format 'repo/path/image:tag'")
	}
	if serverDetails == nil {
		return nil, fmt.Errorf("server details are required")
	}
	return GetDockerRepositoryConfig(serverDetails, imageName, depsRepo, "")
}
