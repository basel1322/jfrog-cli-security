package gem

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp" // Added for regex-based version cleaning
	"strconv"
	"strings"

	"github.com/jfrog/gofrog/io"
	"github.com/jfrog/jfrog-client-go/utils/log"
	xrayUtils "github.com/jfrog/jfrog-client-go/xray/services/utils"

	"github.com/jfrog/jfrog-cli-core/v2/utils/coreutils"
	cliUtils "github.com/jfrog/jfrog-cli-security/utils"
)

const (
	internalPackagePrefix = "rubygems:"
	rubyV2                = "2.6.0"
	jsonGemPrefix         = "rubygems://"
	gemVirtualRootID      = "root"
	stateSearchGEM        = iota
	stateSearchSpecsKeyword
	stateInSpecsSection
)

type GemDep struct {
	Ref    string `json:"ref"`
	Direct bool   `json:"direct"`
}

type GemRef struct {
	Ref          string            `json:"ref"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	Dependencies map[string]GemDep `json:"dependencies"`
	node         *xrayUtils.GraphNode
}

func (gr *GemRef) NodeName() string { return gr.Ref }
func (gr *GemRef) Node(children ...*xrayUtils.GraphNode) *xrayUtils.GraphNode {
	if gr.node == nil {
		gr.node = &xrayUtils.GraphNode{Id: gr.NodeName()}
	}
	gr.node.Nodes = children
	return gr.node
}

type GemGraphInput struct {
	Graph struct {
		Nodes map[string]GemRef `json:"nodes"`
	} `json:"graph"`
}

type internalGemDep struct{ Name, Constraint string }
type internalGemRef struct {
	Ref, Name, Version string
	Dependencies       map[string]internalGemDep
}

func BuildDependencyTree(params cliUtils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	currentDir, err := coreutils.GetWorkingDirectory()
	if err != nil {
		return
	}
	gemExecPath, err := getRubyExecPath()
	if err != nil {
		return
	}
	return calculateDependencies(gemExecPath, currentDir, params)
}

// getRubyExecPath checks for Ruby and Bundle, validates Ruby version, and returns bundle path.
func getRubyExecPath() (bundleExecPath string, err error) {
	rubyPath, err := exec.LookPath("ruby")
	if err != nil {
		return "", fmt.Errorf("could not find 'ruby' executable in PATH: %w", err)
	}

	bundleExecPath, err = exec.LookPath("bundle")
	if err != nil {
		return "", fmt.Errorf("could not find 'bundle' executable in PATH: %w", err)
	}

	output, err := getGemCmd(rubyPath, "", "--version").RunWithOutput()
	if err != nil {
		return "", fmt.Errorf("failed to execute 'ruby --version': %w", err)
	}

	versionStr := string(output)
	fields := strings.Fields(versionStr)
	if len(fields) < 2 {
		return "", fmt.Errorf("unexpected ruby version output: %s", versionStr)
	}
	actualVersion := fields[1]

	// Extract just major.minor from actual version and required version
	actualMajor, actualMinor, err := parseMajorMinor(actualVersion)
	if err != nil {
		return "", err
	}

	requiredMajor, requiredMinor, err := parseMajorMinor(rubyV2)
	if err != nil {
		return "", err
	}

	if actualMajor < requiredMajor || (actualMajor == requiredMajor && actualMinor < requiredMinor) {
		return "", fmt.Errorf(
			"ruby dependency tree building requires ruby %s or higher; current version: %s",
			rubyV2, actualVersion,
		)
	}

	return bundleExecPath, nil
}
func getGemCmd(execPath, workingDir, cmd string, args ...string) *io.Command {
	command := io.NewCommand(execPath, cmd, args)
	command.Dir = workingDir
	return command
}

func calculateDependencies(bundleExecPath, workingDir string, params cliUtils.AuditParams) (dependencyTrees []*xrayUtils.GraphNode, uniqueDeps []string, err error) {
	log.Debug("Ensuring Gemfile.lock is up to date using 'bundle lock'...")
	// The output of 'bundle lock' is not directly used, its purpose is to update/create Gemfile.lock
	if _, err = getGemCmd(bundleExecPath, workingDir, "lock").RunWithOutput(); err != nil {
		err = fmt.Errorf("failed to execute 'bundle lock': %w. Ensure Gemfile is present and bundle can run", err)
		return
	}

	lockFilePath := filepath.Join(workingDir, "Gemfile.lock")
	if _, statErr := os.Stat(lockFilePath); os.IsNotExist(statErr) {
		err = fmt.Errorf("gemfile.lock not found at '%s' after running 'bundle lock'", lockFilePath)
		return
	}

	gemGraphInfoContent, err := parseGemfileLockDeps(lockFilePath)
	if err != nil {
		err = fmt.Errorf("error generating gem graph JSON from Gemfile.lock: %w", err)
		return
	}
	var gemInput GemGraphInput
	if err = json.Unmarshal(gemGraphInfoContent, &gemInput); err != nil {
		err = fmt.Errorf("failed to unmarshal gem graph JSON: %w", err)
		return
	}
	if len(gemInput.Graph.Nodes) == 0 {
		log.Debug("No gem dependencies found in GemGraphInput after parsing Gemfile.lock.")
		return []*xrayUtils.GraphNode{}, []string{}, nil
	}

	projectRootNode, errParser := buildFullGemDependencyGraph(gemInput)
	if errParser != nil {
		err = fmt.Errorf("failed to build full gem dependency graph: %w", errParser)
		return
	}

	if projectRootNode != nil && projectRootNode.Nodes != nil {
		dependencyTrees = projectRootNode.Nodes
	} else {
		dependencyTrees = []*xrayUtils.GraphNode{}
	}
	uniqueDeps = calculateUniqueDependencies(dependencyTrees)

	log.Debug("Calculated dependency trees (children of root): %d trees found.", len(dependencyTrees))

	return
}

func parseLockfileToInternalData(lockFilePath string) (
	orderedGems []*internalGemRef,
	resolvedVersions map[string]string,
	err error,
) {
	file, ioErr := os.Open(lockFilePath)
	if ioErr != nil {
		err = fmt.Errorf("opening lockfile %s: %w", lockFilePath, ioErr)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	orderedGems = []*internalGemRef{}
	resolvedVersions = make(map[string]string)
	var currentGem *internalGemRef
	currentState := stateSearchGEM
	for scanner.Scan() {
		line := scanner.Text()
		trimmedLine := strings.TrimSpace(line)
		switch currentState {
		case stateSearchGEM:
			if trimmedLine == "GEM" {
				currentState = stateSearchSpecsKeyword
			}
		case stateSearchSpecsKeyword:
			if line == "  specs:" || trimmedLine == "specs:" {
				currentState = stateInSpecsSection
			} else if trimmedLine == "REMOTE" || trimmedLine == "SOURCE" {
				continue
			} else if trimmedLine == "GEM" {
			}
		case stateInSpecsSection:
			sectionTerminators := map[string]bool{"DEPENDENCIES": true, "PLATFORMS": true, "RUBY VERSION": true, "BUNDLED WITH": true, "GIT": true, "PATH": true, "PLUGIN SOURCE": true}
			if sectionTerminators[trimmedLine] {
				currentGem = nil
				currentState = stateSearchGEM
				continue
			}
			if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") {
				parts := strings.SplitN(trimmedLine, " ", 2)
				if len(parts) == 2 {
					name, version := parts[0], strings.Trim(parts[1], "()")
					if name == "" || version == "" {
						currentGem = nil
						continue
					}
					ref := internalPackagePrefix + name + ":" + version
					currentGem = &internalGemRef{Ref: ref, Name: name, Version: version, Dependencies: make(map[string]internalGemDep)}
					orderedGems = append(orderedGems, currentGem)
					resolvedVersions[name] = version
				} else {
					currentGem = nil
				}
			} else if strings.HasPrefix(line, "      ") && currentGem != nil {
				depParts := strings.SplitN(strings.TrimSpace(line), " ", 2)
				if len(depParts) > 0 {
					depName := depParts[0]
					depConstraint := ""
					if len(depParts) > 1 {
						depConstraint = depParts[1]
					}
					if depName == "" {
						continue
					}
					currentGem.Dependencies[depName] = internalGemDep{Name: depName, Constraint: depConstraint}
				}
			} else if trimmedLine == "" {
			} else if currentGem != nil && !strings.HasPrefix(line, " ") {
				currentGem = nil
				currentState = stateSearchGEM
			}
		}
	}
	if scanErr := scanner.Err(); scanErr != nil {
		err = fmt.Errorf("scanning lockfile: %w", scanErr)
		return
	}
	return
}

func parseGemfileLockDeps(lockFilePath string) ([]byte, error) {
	orderedInternalGems, resolvedVersions, err := parseLockfileToInternalData(lockFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Gemfile.lock data: %w", err)
	}
	gemRefMap := make(map[string]GemRef, len(orderedInternalGems))
	for _, igem := range orderedInternalGems {
		dependenciesForGemRef := make(map[string]GemDep, len(igem.Dependencies))
		for depNameKey, internalDep := range igem.Dependencies {
			resolvedDepVersion, found := resolvedVersions[internalDep.Name]
			depRefString := ""
			if found {
				depRefString = jsonGemPrefix + internalDep.Name + ":" + resolvedDepVersion
			} else {
				depRefString = jsonGemPrefix + internalDep.Name + ":VERSION_NOT_FOUND_IN_SPECS"
			}
			dependenciesForGemRef[depNameKey] = GemDep{Ref: depRefString, Direct: true}
		}
		publicRef := jsonGemPrefix + igem.Name + ":" + igem.Version
		gemRefMap[publicRef] = GemRef{
			Ref: publicRef, Name: igem.Name, Version: igem.Version, Dependencies: dependenciesForGemRef,
		}
	}
	outputStructure := GemGraphInput{Graph: struct {
		Nodes map[string]GemRef `json:"nodes"`
	}{Nodes: gemRefMap}}
	jsonData, err := json.Marshal(outputStructure)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal: %w", err)
	}
	return jsonData, nil
}

func parseGemDependencyGraphRecursive(id string, graph map[string]GemRef, visitedNodes map[string]*xrayUtils.GraphNode) (*xrayUtils.GraphNode, error) {
	if node, ok := visitedNodes[id]; ok {
		return node, nil
	}
	gemRef, ok := graph[id]
	if !ok {
		log.Debug("Warning: Gem with ID '%s' not found in graph map. Creating as leaf node.", id)
		leafNode := &xrayUtils.GraphNode{Id: id, Nodes: []*xrayUtils.GraphNode{}}
		visitedNodes[id] = leafNode
		return leafNode, nil
	}
	childrenNodes := make([]*xrayUtils.GraphNode, 0)
	for _, dep := range gemRef.Dependencies {
		if !dep.Direct {
			continue
		}
		parsedNode, err := parseGemDependencyGraphRecursive(dep.Ref, graph, visitedNodes)
		if err != nil {
			log.Debug("Error parsing child dependency '%s' for '%s': %v. Skipping.", dep.Ref, id, err)
			continue
		}
		if parsedNode != nil {
			childrenNodes = append(childrenNodes, parsedNode)
		}
	}
	resultNode := gemRef.Node(childrenNodes...)
	visitedNodes[id] = resultNode
	return resultNode, nil
}

func buildFullGemDependencyGraph(graphInput GemGraphInput) (*xrayUtils.GraphNode, error) {
	visitedNodes := make(map[string]*xrayUtils.GraphNode)
	if len(graphInput.Graph.Nodes) == 0 {
		log.Debug("No nodes provided in graphInput to build dependency graph.")
		return &xrayUtils.GraphNode{Id: gemVirtualRootID, Nodes: []*xrayUtils.GraphNode{}}, nil
	}
	var rootChildrenNodes []*xrayUtils.GraphNode
	allDepRefs := make(map[string]bool)
	for _, gemRef := range graphInput.Graph.Nodes {
		for _, depLink := range gemRef.Dependencies {
			allDepRefs[depLink.Ref] = true
		}
	}
	for gemID := range graphInput.Graph.Nodes {
		if !allDepRefs[gemID] {
			parsedNode, err := parseGemDependencyGraphRecursive(gemID, graphInput.Graph.Nodes, visitedNodes)
			if err != nil {
				log.Debug("Error parsing subtree for root candidate '%s': %v. Skipping.", gemID, err)
				continue
			}
			if parsedNode != nil {
				rootChildrenNodes = append(rootChildrenNodes, parsedNode)
			}
		}
	}
	return &xrayUtils.GraphNode{Id: gemVirtualRootID, Nodes: rootChildrenNodes}, nil
}
func parseMajorMinor(version string) (major, minor int, err error) {
	re := regexp.MustCompile(`^(\d+)\.(\d+)`)
	matches := re.FindStringSubmatch(version)
	if len(matches) < 3 {
		return 0, 0, fmt.Errorf("invalid version format: %q", version)
	}
	major, err = strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid major version in %q: %w", version, err)
	}
	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid minor version in %q: %w", version, err)
	}
	return major, minor, nil
}

func calculateUniqueDependencies(trees []*xrayUtils.GraphNode) []string {
	// Using a map as a set to store unique dependency IDs
	uniqueIDsSet := make(map[string]struct{})
	var stack []*xrayUtils.GraphNode
	if len(trees) > 0 {
		for i := len(trees) - 1; i >= 0; i-- {
			if trees[i] != nil {
				stack = append(stack, trees[i])
			}
		}
	}
	visitedInThisTraversal := make(map[*xrayUtils.GraphNode]bool)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		if node == nil || visitedInThisTraversal[node] {
			continue
		}
		visitedInThisTraversal[node] = true
		if node.Id != "" {
			if node.Id == gemVirtualRootID {
				log.Debug("Skipping virtual root ID ('%s') found within dependency trees.", gemVirtualRootID)
			} else {
				uniqueIDsSet[node.Id] = struct{}{}
			}
		} else {
			log.Debug("Encountered a graph node with an empty ID during unique dependency calculation.")
		}
		if node.Nodes != nil {
			for i := len(node.Nodes) - 1; i >= 0; i-- {
				child := node.Nodes[i]
				if child != nil {
					stack = append(stack, child)
				}
			}
		}
	}
	result := make([]string, 0, len(uniqueIDsSet))
	for id := range uniqueIDsSet {
		result = append(result, id)
	}

	return result
}
