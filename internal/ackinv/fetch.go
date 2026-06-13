package ackinv

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultOrg is the GitHub organization hosting all ACK controllers.
const DefaultOrg = "aws-controllers-k8s"

// Client fetches controller metadata and CRDs from GitHub. Authentication is
// taken from GITHUB_TOKEN/GH_TOKEN or, failing that, from `gh auth token`.
type Client struct {
	HTTP  *http.Client
	Token string
	Org   string
}

// NewClient builds a client with sane timeouts and ambient credentials.
func NewClient(org string) *Client {
	return &Client{
		HTTP:  &http.Client{Timeout: 30 * time.Second},
		Token: ambientToken(),
		Org:   org,
	}
}

func ambientToken() string {
	for _, env := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if t := os.Getenv(env); t != "" {
			return t
		}
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func (c *Client) get(rawURL string, accept string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, errNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", rawURL, resp.Status, truncate(string(body), 200))
	}
	return body, nil
}

var errNotFound = fmt.Errorf("not found")

// IsNotFound reports whether err is a 404 from the GitHub API.
func IsNotFound(err error) bool { return err == errNotFound }

func (c *Client) api(path string) ([]byte, error) {
	return c.get("https://api.github.com/"+path, "application/vnd.github+json")
}

func (c *Client) raw(repo, ref, path string) ([]byte, error) {
	u := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		c.Org, repo, url.PathEscape(ref), path)
	return c.get(u, "")
}

// ListControllerRepos enumerates all non-archived <service>-controller repos
// in the org.
func (c *Client) ListControllerRepos() ([]string, error) {
	var repos []string
	for page := 1; ; page++ {
		body, err := c.api(fmt.Sprintf("orgs/%s/repos?per_page=100&page=%d", c.Org, page))
		if err != nil {
			return nil, fmt.Errorf("listing org repos: %w", err)
		}
		var batch []struct {
			Name     string `json:"name"`
			Archived bool   `json:"archived"`
		}
		if err := json.Unmarshal(body, &batch); err != nil {
			return nil, fmt.Errorf("parsing org repos: %w", err)
		}
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			if !r.Archived && strings.HasSuffix(r.Name, "-controller") {
				repos = append(repos, r.Name)
			}
		}
	}
	return repos, nil
}

// LatestRelease returns the latest release tag of a repo, or "" when the
// repo has no releases yet (pre-release controllers).
func (c *Client) LatestRelease(repo string) (string, error) {
	body, err := c.api(fmt.Sprintf("repos/%s/%s/releases/latest", c.Org, repo))
	if IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var rel struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &rel); err != nil {
		return "", err
	}
	return rel.TagName, nil
}

// crdBasesPath is where every ACK controller keeps its CRD manifests.
const crdBasesPath = "config/crd/bases"

// ListCRDFiles lists CRD YAML filenames under config/crd/bases at a ref.
func (c *Client) ListCRDFiles(repo, ref string) ([]string, error) {
	body, err := c.api(fmt.Sprintf("repos/%s/%s/contents/%s?ref=%s", c.Org, repo, crdBasesPath, url.QueryEscape(ref)))
	if IsNotFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var entries []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		// Common CRDs (adoptedresources, fieldexports) are shared runtime
		// plumbing, not service resources; skip them for coverage purposes.
		if e.Type != "file" || !strings.HasSuffix(e.Name, ".yaml") {
			continue
		}
		if strings.Contains(e.Name, "services.k8s.aws_adoptedresources") ||
			strings.Contains(e.Name, "services.k8s.aws_fieldexports") {
			continue
		}
		files = append(files, e.Name)
	}
	return files, nil
}

// FetchCRD downloads one CRD file at a ref.
func (c *Client) FetchCRD(repo, ref, name string) ([]byte, error) {
	return c.raw(repo, ref, crdBasesPath+"/"+name)
}

// ServiceFullName fetches the human-readable service name from metadata.yaml,
// returning "" when absent.
func (c *Client) ServiceFullName(repo, ref string) string {
	body, err := c.raw(repo, ref, "metadata.yaml")
	if err != nil {
		return ""
	}
	var meta struct {
		Service struct {
			FullName string `yaml:"full_name"`
		} `yaml:"service"`
	}
	if yaml.Unmarshal(body, &meta) != nil {
		return ""
	}
	return meta.Service.FullName
}

// BuildService assembles the inventory entry for one controller repo. A repo
// without releases or without CRDs yields a Service with empty Release/Kinds
// so new controllers still appear in the inventory (and in drift reports).
func (c *Client) BuildService(repo string) (*Service, error) {
	name := strings.TrimSuffix(repo, "-controller")
	svc := &Service{Name: name, Repo: fmt.Sprintf("%s/%s", c.Org, repo)}

	release, err := c.LatestRelease(repo)
	if err != nil {
		return nil, fmt.Errorf("%s: resolving latest release: %w", repo, err)
	}
	svc.Release = release
	ref := release
	if ref == "" {
		ref = "main"
	}
	svc.FullName = c.ServiceFullName(repo, ref)

	files, err := c.ListCRDFiles(repo, ref)
	if err != nil {
		return nil, fmt.Errorf("%s: listing CRDs at %s: %w", repo, ref, err)
	}
	for _, f := range files {
		data, err := c.FetchCRD(repo, ref, f)
		if err != nil {
			return nil, fmt.Errorf("%s: fetching %s at %s: %w", repo, f, ref, err)
		}
		kind, err := ParseCRD(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %s: %w", repo, f, err)
		}
		svc.Kinds = append(svc.Kinds, *kind)
	}
	return svc, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
