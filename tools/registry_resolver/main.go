package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/git-pkgs/purl"
	"github.com/git-pkgs/registries"
	_ "github.com/git-pkgs/registries/all"
	"github.com/git-pkgs/registries/fetch"
)

const (
	providerVersion = "github.com/git-pkgs/registries v0.14.0"
	defaultTimeout  = 15 * time.Second
	defaultMaxBytes = 256 * 1024
)

type artifact struct {
	URL       string `json:"url,omitempty"`
	Filename  string `json:"filename,omitempty"`
	Integrity string `json:"integrity,omitempty"`
	Size      int64  `json:"size,omitempty"`
	MediaType string `json:"media_type,omitempty"`
	Evidence  string `json:"evidence"`
}

type result struct {
	Provider         string          `json:"provider"`
	PURL             string          `json:"purl,omitempty"`
	Ecosystem        string          `json:"ecosystem,omitempty"`
	Package          string          `json:"package,omitempty"`
	RequestedVersion string          `json:"requested_version,omitempty"`
	ResolvedVersion  string          `json:"resolved_version,omitempty"`
	Description      string          `json:"description,omitempty"`
	RepositoryURL    string          `json:"repository_url,omitempty"`
	DocumentationURL string          `json:"documentation_url,omitempty"`
	License          string          `json:"license,omitempty"`
	PublishedAt      string          `json:"published_at,omitempty"`
	VersionStatus    string          `json:"version_status,omitempty"`
	Artifacts        []artifact      `json:"artifacts"`
	Status           string          `json:"status"`
	Errors           []providerError `json:"errors"`
}

type providerError struct {
	Operation string `json:"operation"`
	Kind      string `json:"kind"`
	Message   string `json:"message"`
}

func main() {
	maxBytes := envInt("REGISTRY_RESOLVER_MAX_OUTPUT_BYTES", defaultMaxBytes)
	timeout := time.Duration(envInt("REGISTRY_RESOLVER_TIMEOUT_SECONDS", int(defaultTimeout/time.Second))) * time.Second
	res := resolve(timeout, os.Args[1:])
	if err := writeBoundedJSON(res, maxBytes); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if res.Status != "FOUND" {
		os.Exit(1)
	}
}

func resolve(timeout time.Duration, args []string) result {
	res := result{Provider: providerVersion, Artifacts: []artifact{}, Errors: []providerError{}, Status: "PROVIDER_ERROR"}
	if len(args) != 1 {
		res.Errors = append(res.Errors, providerError{"input", "MALFORMED", "exactly one normalized PURL is required"})
		return res
	}
	parsed, err := purl.Parse(args[0])
	if err != nil || parsed.Version == "" || parsed.String() != args[0] {
		res.Errors = append(res.Errors, providerError{"input", "MALFORMED", "a normalized, versioned PURL is required"})
		return res
	}
	res.PURL = parsed.String()
	res.Ecosystem = parsed.Type
	res.Package = parsed.FullName()
	res.RequestedVersion = parsed.Version

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	pkg, pkgErr := registries.FetchPackageFromPURL(ctx, res.PURL, nil)
	if pkgErr != nil {
		res.Errors = append(res.Errors, classifyError("package", pkgErr))
	} else if pkg != nil {
		res.Description = pkg.Description
		res.RepositoryURL = pkg.Repository
		res.DocumentationURL = pkg.Homepage
		res.License = pkg.Licenses
	}
	version, versionErr := registries.FetchVersionFromPURL(ctx, res.PURL, nil)
	if versionErr != nil {
		res.Errors = append(res.Errors, classifyError("version", versionErr))
		if isNotFound(versionErr) {
			res.Status = "NOT_FOUND"
		} else if strings.Contains(strings.ToLower(versionErr.Error()), "unsupported") {
			res.Status = "UNSUPPORTED"
		}
		return res
	}
	res.ResolvedVersion = version.Number
	if version.Number != parsed.Version {
		res.Errors = append(res.Errors, providerError{"version", "MISMATCH", "provider did not return the requested version"})
		return res
	}
	if !version.PublishedAt.IsZero() {
		res.PublishedAt = version.PublishedAt.UTC().Format(time.RFC3339)
	}
	res.VersionStatus = string(version.Status)
	if res.License == "" {
		res.License = version.Licenses
	}
	for _, item := range version.Artifacts {
		res.Artifacts = append(res.Artifacts, artifact{
			URL: item.URL, Filename: item.Filename, Integrity: firstNonempty(item.Integrity, version.Integrity),
			Size: item.Size, MediaType: item.MediaType, Evidence: "REGISTRY_METADATA",
		})
	}
	if !hasArtifactURL(res.Artifacts) {
		info, resolveErr := fetch.NewResolver().Resolve(ctx, parsed.Type, parsed.FullName(), parsed.Version)
		if resolveErr != nil {
			res.Errors = append(res.Errors, classifyError("download", resolveErr))
		} else if info.URL != "" {
			res.Artifacts = append(res.Artifacts, artifact{
				URL: info.URL, Filename: info.Filename, Integrity: info.Integrity,
				Size: info.Size, Evidence: "COMPUTED_UNVERIFIED",
			})
		}
	}
	res.Status = "FOUND"
	return res
}

func hasArtifactURL(artifacts []artifact) bool {
	for _, item := range artifacts {
		if item.URL != "" {
			return true
		}
	}
	return false
}

func classifyError(operation string, err error) providerError {
	kind := "PROVIDER_ERROR"
	if errors.Is(err, context.DeadlineExceeded) {
		kind = "TIMEOUT"
	} else if isNotFound(err) {
		kind = "NOT_FOUND"
	} else if strings.Contains(strings.ToLower(err.Error()), "unsupported") {
		kind = "UNSUPPORTED"
	}
	return providerError{operation, kind, err.Error()}
}

func isNotFound(err error) bool {
	return errors.Is(err, registries.ErrNotFound) || strings.Contains(strings.ToLower(err.Error()), "not found")
}

func writeBoundedJSON(res result, maxBytes int) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(res); err != nil {
		return fmt.Errorf("encode result: %w", err)
	}
	if buffer.Len() > maxBytes {
		fallback := result{Provider: providerVersion, Artifacts: []artifact{}, Status: "PROVIDER_ERROR", Errors: []providerError{{"output", "TOO_LARGE", "structured output exceeded configured limit"}}}
		buffer.Reset()
		if err := json.NewEncoder(&buffer).Encode(fallback); err != nil || buffer.Len() > maxBytes {
			return errors.New("structured output exceeds configured limit")
		}
	}
	_, err := os.Stdout.Write(buffer.Bytes())
	return err
}

func envInt(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func firstNonempty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
