package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/zricethezav/gitleaks/v8/logging"
	"golang.org/x/sync/semaphore"
)

type RClient interface {
	Platform() string
	FetchRepo(ctx context.Context, username, repo string) (Repository, error)
	GetRepos(ctx context.Context, username string, opts ReposListOpts) ([]Repository, error)
}

type Repository interface {
	GetURL() string
	GetName() string
}
type Repo struct {
	URL  string
	Name string
}

func (g *Repo) GetName() string {
	return g.Name
}
func (g *Repo) GetURL() string {
	return g.URL
}

type RawClient struct {
	Urls []string
}

func (r *RawClient) Platform() string {
	return "raw"
}

func (r *RawClient) FetchRepo(ctx context.Context, username, repo string) (Repository, error) {
	return &Repo{
		Name: repo,
		URL:  repo,
	}, nil
}

func (r *RawClient) GetRepos(ctx context.Context, username string, opts ReposListOpts) ([]Repository, error) {
	var repos []Repository
	for _, url := range r.Urls {
		parsed := strings.TrimSuffix(filepath.Base(url), ".git")
		repos = append(repos, &Repo{
			Name: parsed,
			URL:  url,
		})
	}
	return repos, nil
}

type ReposListOpts interface {
	GetLimit() int
	GetType() string
	GetDirection() string
	GetToolFlagsConfig() *ReposListOptsToolFlags
}

type ReposListOptsToolFlags struct {
	IncludeARchived *bool `json:"include_archived,omitempty"`
	IncludeForks    *bool `json:"include_forks,omitempty"`
}

type ReposListOptsGithub struct {
	Limit     int    `url:"limit,omitempty" json:"limit"`
	Type      string `url:"type,omitempty"`
	Sort      string `url:"sort,omitempty"`
	Direction string `url:"direction,omitempty"`
}

func (r *ReposListOptsGithub) GetDirection() string {
	return r.Direction
}

func (r *ReposListOptsGithub) GetLimit() int {
	if r.Limit == 0 {
		r.Limit = limit
	}
	return r.Limit
}

func (r *ReposListOptsGithub) GetToolFlagsConfig() *ReposListOptsToolFlags {
	return &ReposListOptsToolFlags{
		IncludeARchived: &includeArchived,
		IncludeForks:    &includeForks,
	}
}

func (r *ReposListOptsGithub) GetType() string {
	return r.Type
}

var (
	remoteCmd = &cobra.Command{
		Use:   "remote [flags]",
		Short: "scan remote repositories",
		Run:   runRepos,
		Example: `- gitleaks remote -u userName 					# scans the 5 most recently updated repos for userName
- gitleaks remote -u userName --repo repoName 			# scans a specific repo for userName
- gitleaks remote -u userName --platform gitlab --include-forks --limit 10 --threads 10
- gitleaks remote -u orgName -t org --include-forks --include-archived --limit 10 --threads 10
- gitleaks remote -u orgName -t org --limit 0 --threads 20 --output-dir my-reports --cleanup-repos
`,
	}
	platform        string
	accountType     string
	username        string
	repo            string
	limit           int
	threads         int
	includeForks    bool
	includeArchived bool
	outputDir       string
	cloneDepth      int
	cloneTimeout    time.Duration
	scanTimeout     time.Duration
	cleanupRepos    bool
	scanAllBranches bool
	rawUrls         string
	rawUrlsFile     string
)

func init() {
	rootCmd.AddCommand(remoteCmd)
	remoteCmd.Flags().StringVarP(&platform, "platform", "", "github", "Platform name (e.g., github, gitlab, etc..)")
	remoteCmd.Flags().StringVarP(&accountType, "type", "t", "user", "The type of account to scan (user, org)")
	remoteCmd.Flags().StringVarP(&username, "username", "u", "", "The username of the user or org account to scan")
	remoteCmd.Flags().StringVarP(&repo, "repo", "", "", "The specific repository to scan (overrides username and type)")
	remoteCmd.Flags().IntVarP(&limit, "limit", "", 5, "number of repositories to scan (default 5; 0 means clone all repositories)")
	remoteCmd.Flags().IntVarP(&threads, "threads", "", 5, "number of threads to use for the scan (default 5)")
	remoteCmd.Flags().BoolVar(&includeForks, "include-forks", false, "Include forked repositories in the scan")
	remoteCmd.Flags().BoolVar(&includeArchived, "include-archived", false, "Include archived repositories in the scan")
	remoteCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "gitleaks-reports", "The directory to store the scan results")
	remoteCmd.Flags().DurationVar(&cloneTimeout, "clone-timeout", 30*time.Second, "Timeout for cloning each repository (e.g., 30s, 1m)")
	remoteCmd.Flags().DurationVar(&scanTimeout, "scan-timeout", 10*time.Minute, "Timeout for scanning each repository (e.g., 10m, 1h)")
	remoteCmd.Flags().IntVar(&cloneDepth, "clone-depth", 1, "Depth for git clone (default 1 for shallow clone)")
	remoteCmd.Flags().BoolVar(&cleanupRepos, "cleanup-repos", false, "Remove cloned repositories after scanning")
	remoteCmd.Flags().BoolVar(&scanAllBranches, "scan-all-branches", false, "Scan all repository branches")
	remoteCmd.Flags().StringVar(&rawUrls, "urls", "", "Comma-separated list of raw Git URLs to scan (bypasses platform logic)")
	remoteCmd.Flags().StringVar(&rawUrlsFile, "urls-file", "", "Path to file containing one Git URL per line")
}

func runRepos(cmd *cobra.Command, args []string) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if username == "" && rawUrls == "" && rawUrlsFile == "" {
		logging.Fatal().Msg("username for account required")
	}
	if threads <= 0 {
		threads = 5
	}
	if rawUrlsFile != "" {
		file, err := os.ReadFile(rawUrlsFile)
		if err != nil {
			logging.Fatal().Msgf("failed to read urls file: %v", err)
		}
		urlList := strings.FieldsFunc(strings.TrimSpace(string(file)), func(r rune) bool {
			return r == '\n' || r == '\r' || r == ','
		})
		rawUrls = strings.Join(urlList, ",")
	}

	var client RClient
	if rawUrls != "" {
		urlList := strings.Split(rawUrls, ",")
		client = &RawClient{Urls: urlList}
		username = "raw"
	} else {
		switch strings.ToLower(platform) {
		case "github":
			client = createGitHubClient()
		case "gitlab":
			client = createGitlabClient()
		default:
			client = createGitHubClient()
		}
	}
	repos, err := fetchRepos(ctx, client)
	if err != nil {
		logging.Fatal().Msgf("Failed to fetch repositories: %v", err)
	}
	if len(repos) == 0 {
		logging.Warn().Msg("Found no repositories")
		return
	}
	logging.Info().Msgf("Found %d repositories", len(repos))
	if err := setupDirectories(); err != nil {
		logging.Fatal().Msgf("Failed to setup directories: %v", err)
	}
	if err := cloneAndScanRepos(ctx, repos); err != nil {
		logging.Fatal().Msgf("Scan failed: %v", err)
	}
	logging.Info().Msgf("All scans complete. Check %s/%s/", outputDir, username)
}

func fetchRepos(ctx context.Context, client RClient) ([]Repository, error) {
	logging.Info().Msgf("Fetching %v repositories...", client.Platform())
	if repo != "" {
		r, err := client.FetchRepo(ctx, username, repo)
		if err != nil {
			return nil, fmt.Errorf("error fetching repository %s/%s: %w", username, repo, err)
		}
		return []Repository{r}, nil
	}
	opts := &ReposListOptsGithub{
		Type:      "all",
		Sort:      "updated",
		Direction: "desc",
		Limit:     limit,
	}
	rs, err := client.GetRepos(ctx, username, opts)
	if err != nil {
		return nil, fmt.Errorf("error fetching repositories: %w", err)
	}
	return rs, nil
}

func setupDirectories() error {
	userResultDir := filepath.Join(outputDir, username)
	dirs := []string{userResultDir, filepath.Join(userResultDir, "repos"), filepath.Join(userResultDir, "results")}
	for _, dir := range dirs {
		if err := os.MkdirAll(dir, os.ModePerm); err != nil {
			return fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}
	return nil
}

func cloneAndScanRepos(ctx context.Context, repos []Repository) error {
	var wg sync.WaitGroup
	sem := semaphore.NewWeighted(int64(threads))
	reposDir := filepath.Join(filepath.Join(outputDir, username), "repos")
	resultsDir := filepath.Join(filepath.Join(outputDir, username), "results")
	for _, repo := range repos {
		wg.Add(1)
		go func(repo Repository) {
			defer wg.Done()
			if err := sem.Acquire(ctx, 1); err != nil {
				logging.Error().Msgf("Failed to acquire semaphore: %v", err)
				return
			}
			defer sem.Release(1)

			url := repo.GetURL()
			name := strings.ReplaceAll(strings.ReplaceAll(repo.GetName(), "/", "_"), " ", "_")
			repoDir := filepath.Join(reposDir, name)
			reportDir, err := filepath.Abs(resultsDir)
			if err != nil {
				logging.Error().Msgf("Failed to get absolute path for results directory: %v", err)
				return
			}
			reportPath := fmt.Sprintf("%s/%s.json", reportDir, name)
			logging.Info().Msgf("Processing repo: %s\n", name)

			cloneCtx, cancel := context.WithTimeout(ctx, cloneTimeout)
			args := []string{
				"clone",
				"--depth", fmt.Sprintf("%d", cloneDepth),
				"--no-tags",
				"--single-branch",
				"--recurse-submodules=no",
			}
			if scanAllBranches {
				args = args[:len(args)-1]
				args = append(args, "--no-single-branch")
			}
			args = append(args, url, repoDir)
			cloneCmd := exec.CommandContext(cloneCtx, "git", args...)
			cloneCmd.Stdout = nil
			cloneCmd.Stderr = nil
			if err := cloneCmd.Run(); err != nil {
				cancel()
				if cloneCtx.Err() == context.DeadlineExceeded {
					logging.Warn().Msgf("Cloning %s timed out after %s. Skipping this repository.", url, cloneTimeout)
					return
				}
				if err.Error() != "exit status 128" {
					logging.Error().Msgf("Failed to clone repository %s: %v", url, err)
				}
				return
			}
			cancel()

			scanCtx, cancel := context.WithTimeout(ctx, scanTimeout)
			gitleaksCmd := exec.CommandContext(scanCtx, "gitleaks", "git", "-r", reportPath, "--no-banner")
			gitleaksCmd.Dir = repoDir
			gitleaksCmd.Stdout = os.Stdout
			gitleaksCmd.Stderr = nil
			if err := gitleaksCmd.Run(); err != nil {
				cancel()
				if scanCtx.Err() == context.DeadlineExceeded {
					logging.Warn().Msgf("Scanning %s timed out after %s. Skipping this repository.", name, scanTimeout)
					return
				}
				return
			}
			cancel()

			if cleanupRepos {
				defer func() {
					if err := os.RemoveAll(repoDir); err != nil {
						fmt.Printf("Warning: failed to cleanup %s: %v\n", repoDir, err)
					}
				}()
			}
		}(repo)
	}
	wg.Wait()
	return nil
}

const githubAPIBase = "https://api.github.com"

func createGitHubClient() RClient {
	return &GithubClient{}
}

type GithubClient struct{}

func (g *GithubClient) Platform() string {
	return "github"
}

func (g *GithubClient) FetchRepo(ctx context.Context, username string, repo string) (Repository, error) {
	url := fmt.Sprintf("%s/repos/%s/%s", githubAPIBase, username, repo)
	token := os.Getenv("GITHUB_TOKEN")
	resp, err := makeGitHubApiRequest(ctx, "GET", url, token)
	if err != nil {
		return nil, fmt.Errorf("failed request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error (%d): %s", resp.StatusCode, string(body))
	}

	var data struct {
		Name     string `json:"name"`
		CloneURL string `json:"clone_url"`
		Fork     bool   `json:"fork"`
		Archived bool   `json:"archived"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}
	return &Repo{
		Name: data.Name,
		URL:  data.CloneURL,
	}, nil
}

func (g *GithubClient) GetRepos(ctx context.Context, username string, opts ReposListOpts) ([]Repository, error) {
	token := os.Getenv("GITHUB_TOKEN")
	perPage := 100
	limit := opts.GetLimit()
	isOrg := strings.ToLower(accountType) == "org"
	base := fmt.Sprintf("%s/users/%s/repos", githubAPIBase, username)
	if isOrg {
		base = fmt.Sprintf("%s/orgs/%s/repos", githubAPIBase, username)
	}
	page := 1
	repos := make([]Repository, 0)
	for {
		url := fmt.Sprintf("%s?per_page=%d&page=%d&sort=updated", base, perPage, page)
		resp, err := makeGitHubApiRequest(ctx, "GET", url, token)
		if err != nil {
			return nil, fmt.Errorf("request failed: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitHub API error (%d): %s", resp.StatusCode, string(body))
		}
		var response []struct {
			Name     string `json:"name"`
			CloneURL string `json:"clone_url"`
			Fork     bool   `json:"fork"`
			Archived bool   `json:"archived"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
			return nil, fmt.Errorf("failed to decode response: %w", err)
		}
		toolFlags := opts.GetToolFlagsConfig()
		for _, r := range response {
			if toolFlags != nil {
				if !*toolFlags.IncludeForks && r.Fork {
					continue
				}
				if !*toolFlags.IncludeARchived && r.Archived {
					continue
				}
			}
			repos = append(repos, &Repo{
				Name: r.Name,
				URL:  r.CloneURL,
			})
			if limit > 0 && len(repos) >= limit {
				return repos, nil
			}
		}
		if len(response) < perPage {
			break
		}
		page++
	}
	return repos, nil
}

func makeGitHubApiRequest(ctx context.Context, method, url, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "gitleaks-cli")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return http.DefaultClient.Do(req)
}

const gitlabAPIBase = "https://gitlab.com/api/v4"

func makeGitLabRequest(ctx context.Context, method, url, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "gitleaks-cli")
	if token != "" {
		req.Header.Set("PRIVATE-TOKEN", token)
	}
	return http.DefaultClient.Do(req)
}

func createGitlabClient() RClient {
	return &GitlabClient{}
}

type GitlabClient struct{}

func (g *GitlabClient) Platform() string {
	return "gitlab"
}

func (g *GitlabClient) FetchRepo(ctx context.Context, username, repo string) (Repository, error) {
	token := os.Getenv("GITLAB_TOKEN")
	projectID := url.PathEscape(fmt.Sprintf("%s/%s", username, repo))
	url := fmt.Sprintf("%s/projects/%s", gitlabAPIBase, projectID)
	resp, err := makeGitLabRequest(ctx, "GET", url, token)
	if err != nil {
		return nil, fmt.Errorf("gitlab GET request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitLab API error (%d): %s", resp.StatusCode, string(body))
	}
	var result struct {
		Name     string `json:"name"`
		HTTPURL  string `json:"http_url_to_repo"`
		Archived bool   `json:"archived"`
		Forked   bool   `json:"forked_from_project"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode error: %w", err)
	}
	return &Repo{
		Name: result.Name,
		URL:  result.HTTPURL,
	}, nil
}

func (g *GitlabClient) GetRepos(ctx context.Context, username string, opts ReposListOpts) ([]Repository, error) {
	token := os.Getenv("GITLAB_TOKEN")
	isOrg := strings.ToLower(accountType) == "org"
	perPage := 100
	limit := opts.GetLimit()
	toolFlags := opts.GetToolFlagsConfig()
	base := fmt.Sprintf("%s/users/%s/projects", gitlabAPIBase, username)
	if isOrg {
		base = fmt.Sprintf("%s/groups/%s/projects", gitlabAPIBase, username)
	}
	page := 1
	var repos []Repository
	for {
		url := fmt.Sprintf("%s?per_page=%d&page=%d&order_by=last_activity_at&sort=desc", base, perPage, page)
		resp, err := makeGitLabRequest(ctx, "GET", url, token)
		if err != nil {
			return nil, fmt.Errorf("gitlab list request failed: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			return nil, fmt.Errorf("GitLab API error (%d): %s", resp.StatusCode, string(body))
		}

		var data []struct {
			Name     string `json:"name"`
			HTTPURL  string `json:"http_url_to_repo"`
			Archived bool   `json:"archived"`
			Forked   bool   `json:"forked_from_project"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
			return nil, fmt.Errorf("decode error: %w", err)
		}

		for _, proj := range data {
			if toolFlags != nil {
				if !*toolFlags.IncludeForks && proj.Forked {
					continue
				}
				if !*toolFlags.IncludeARchived && proj.Archived {
					continue
				}
			}
			repos = append(repos, &Repo{
				Name: proj.Name,
				URL:  proj.HTTPURL,
			})
			if limit > 0 && len(repos) >= limit {
				return repos, nil
			}
		}

		if len(data) < perPage {
			break
		}
		page++
	}

	return repos, nil
}
