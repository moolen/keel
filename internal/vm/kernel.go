package vm

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
)

const defaultKernelBucketURL = "https://s3.amazonaws.com/spec.ccfc.min"

var firecrackerVersionPattern = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

type KernelManager struct {
	HTTPClient         *http.Client
	BucketBaseURL      string
	Arch               string
	FirecrackerVersion func(context.Context) (string, error)
	Progress           func(KernelProgress)
}

type KernelProgress struct {
	Phase   string
	Current int64
	Total   int64
}

type listBucketResult struct {
	Contents []struct {
		Key string `xml:"Key"`
	} `xml:"Contents"`
}

func DefaultKernelPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".cache", "keel", "kernel", "vmlinux")
}

func (m KernelManager) Ensure(ctx context.Context, destPath string) (string, error) {
	if destPath == "" {
		destPath = DefaultKernelPath()
	}
	if _, err := os.Stat(destPath); err == nil {
		return destPath, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}

	ciVersion, err := m.resolveCIVersion(ctx)
	if err != nil {
		return "", err
	}
	arch := m.resolveArch()
	key, err := m.findLatestKernelKey(ctx, ciVersion, arch)
	if err != nil {
		return "", err
	}
	url := strings.TrimRight(m.bucketBaseURL(), "/") + "/" + key

	if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
		return "", err
	}
	tempFile := destPath + ".tmp"
	if err := m.download(ctx, url, tempFile); err != nil {
		return "", err
	}
	if err := os.Rename(tempFile, destPath); err != nil {
		_ = os.Remove(tempFile)
		return "", err
	}
	return destPath, nil
}

func (m KernelManager) resolveCIVersion(ctx context.Context) (string, error) {
	versionFn := m.FirecrackerVersion
	if versionFn == nil {
		versionFn = installedFirecrackerVersion
	}
	version, err := versionFn(ctx)
	if err != nil {
		return "", err
	}
	matches := firecrackerVersionPattern.FindStringSubmatch(version)
	if len(matches) != 4 {
		return "", fmt.Errorf("unrecognized firecracker version %q", version)
	}
	return fmt.Sprintf("v%s.%s", matches[1], matches[2]), nil
}

func (m KernelManager) resolveArch() string {
	if m.Arch != "" {
		return m.Arch
	}
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return runtime.GOARCH
	}
}

func (m KernelManager) bucketBaseURL() string {
	if m.BucketBaseURL != "" {
		return m.BucketBaseURL
	}
	return defaultKernelBucketURL
}

func (m KernelManager) findLatestKernelKey(ctx context.Context, ciVersion, arch string) (string, error) {
	listURL := fmt.Sprintf("%s/?prefix=firecracker-ci/%s/%s/vmlinux-&list-type=2", strings.TrimRight(m.bucketBaseURL(), "/"), ciVersion, arch)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, listURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return "", err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("list kernels: unexpected status %s", resp.Status)
	}
	var result listBucketResult
	if err := xml.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	type candidate struct {
		key     string
		version string
	}
	var candidates []candidate
	for _, entry := range result.Contents {
		base := filepath.Base(entry.Key)
		if strings.HasSuffix(base, ".config") || strings.Contains(base, "debug") || strings.Contains(base, "no-acpi") {
			continue
		}
		if version := strings.TrimPrefix(base, "vmlinux-"); version != base {
			candidates = append(candidates, candidate{key: entry.Key, version: version})
		}
	}
	if len(candidates) == 0 {
		return "", fmt.Errorf("no kernel artifacts found for %s/%s", ciVersion, arch)
	}
	slices.SortFunc(candidates, func(a, b candidate) int {
		return compareDottedVersions(a.version, b.version)
	})
	return candidates[len(candidates)-1].key, nil
}

func (m KernelManager) download(ctx context.Context, url, destPath string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := m.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download kernel: unexpected status %s", resp.Status)
	}
	m.reportProgress(KernelProgress{
		Phase:   "downloading kernel",
		Current: 0,
		Total:   max(resp.ContentLength, 0),
	})
	file, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
	if err != nil {
		return err
	}
	defer func() {
		_ = file.Close()
	}()
	if _, err := copyWithProgress(file, resp.Body, func(written int64) {
		m.reportProgress(KernelProgress{
			Phase:   "downloading kernel",
			Current: written,
			Total:   max(resp.ContentLength, 0),
		})
	}); err != nil {
		return err
	}
	return nil
}

func (m KernelManager) httpClient() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return http.DefaultClient
}

func installedFirecrackerVersion(_ context.Context) (string, error) {
	output, err := exec.Command("firecracker", "--version").CombinedOutput()
	if err != nil {
		if isExecNotFound(err) {
			return "", fmt.Errorf("firecracker is not installed or not in PATH; install Firecracker and ensure the `firecracker` binary is available")
		}
		return "", fmt.Errorf("detect firecracker version: %w: %s", err, output)
	}
	return strings.TrimSpace(string(output)), nil
}

func isExecNotFound(err error) bool {
	var execErr *exec.Error
	return errors.As(err, &execErr) && execErr.Err == exec.ErrNotFound
}

func compareDottedVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	for i := 0; i < max(len(aParts), len(bParts)); i++ {
		ai := dottedPart(aParts, i)
		bi := dottedPart(bParts, i)
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
	}
	return 0
}

func (m KernelManager) reportProgress(update KernelProgress) {
	if m.Progress != nil {
		m.Progress(update)
	}
}

func copyWithProgress(dst io.Writer, src io.Reader, report func(int64)) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			written += int64(nw)
			if report != nil {
				report(written)
			}
			if writeErr != nil {
				return written, writeErr
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if readErr == io.EOF {
				return written, nil
			}
			return written, readErr
		}
	}
}

func dottedPart(parts []string, index int) int {
	if index >= len(parts) {
		return 0
	}
	value, err := strconv.Atoi(parts[index])
	if err != nil {
		return 0
	}
	return value
}
