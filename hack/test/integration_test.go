package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/moolen/keel/internal/image"
)

func TestKeelE2ESuite(t *testing.T) {
	if !e2eEnabled(t) {
		t.Skip("set KEEL_E2E=1 to run Firecracker e2e coverage")
	}

	suite := newE2ESuite(t)

	t.Run("T1 Image Management", suite.testImageManagement)
	t.Run("T2 VM Lifecycle And Execution", suite.testVMLifecycleAndExecution)
	t.Run("T3 Package Installation And Filesystem", suite.testFilesystemOperations)
	t.Run("T4 DNS Policy", suite.testDNSPolicy)
	t.Run("T5 TCP TLS And SNI", suite.testTCPTLSPolicy)
	t.Run("T6 Security And Evasion", suite.testSecurityAndEvasion)
	t.Run("T7 MITM And HTTP Policy", suite.testMITMHTTPPolicy)
	t.Run("T8 Audit Mode", suite.testAuditMode)
	t.Run("T9 Docker In VM", suite.testDockerInVM)
	t.Run("T10 Workspace Sync Back", suite.testWorkspaceSync)
	t.Run("T11 Simulated Agent Workflow", suite.testAgentWorkflow)
	t.Run("T12 Shutdown Summary", suite.testShutdownSummary)
	t.Run("T13 Resource Cleanup", suite.testResourceCleanup)
	if os.Getenv("KEEL_E2E_STRESS") == "1" {
		t.Run("T14 Parallel Network Stress", suite.testParallelNetworkStress)
	}
}

func (s *e2eSuite) testImageManagement(t *testing.T) {
	project := s.newProject(t)
	const imageRef = "ghcr.io/moolen/keel-devtools:main"
	project.writeConfig(t, imageRef, "")

	pullImage := project.run(t, "", "image", "pull", imageRef)
	pullImage.requireSuccess(t)

	listImage := project.run(t, "", "image", "list")
	listImage.requireSuccess(t)
	requireContainsAll(t, listImage.Stdout, imageRef, "B")

	layout, err := image.ResolveCacheLayout(project.cacheDir, imageRef)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(layout.RootfsPath)
	if err != nil {
		t.Fatal(err)
	}
	secondPull := project.run(t, "", "image", "pull", imageRef)
	secondPull.requireSuccess(t)
	after, err := os.Stat(layout.RootfsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("duplicate pull rewrote cached rootfs: before=%s after=%s", before.ModTime(), after.ModTime())
	}

	rmImage := project.run(t, "", "image", "rm", imageRef)
	rmImage.requireSuccess(t)
	requireFileMissing(t, layout.RootfsPath)

	listAfterRemove := project.run(t, "", "image", "list")
	listAfterRemove.requireSuccess(t)
	requireNotContains(t, listAfterRemove.Stdout, imageRef)

	repullImage := project.run(t, "", "image", "pull", imageRef)
	repullImage.requireSuccess(t)

	missing := project.run(t, "", "image", "pull", "nonexistent/image:fake")
	missing.requireFailure(t)
	requireContainsAll(t, missing.Combined, "nonexistent/image:fake")

	listAfterRepull := project.run(t, "", "image", "list")
	listAfterRepull.requireSuccess(t)
	requireContainsAll(t, listAfterRepull.Stdout, imageRef)
}

func (s *e2eSuite) testVMLifecycleAndExecution(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "ubuntu:24.04", yamlBlock(
		"resources:",
		"  vcpu: 1",
		"  memory_mb: 512",
		"env:",
		"  static:",
		"    MY_VAR: hello123",
		"    TERM: xterm-256color",
	))

	echoResult := project.run(t, "", sh(`echo "hello from keel"`)...)
	echoResult.requireSuccess(t)
	requireContainsAll(t, echoResult.Stdout, "hello from keel")

	exitResult := project.run(t, "", sh("exit 42")...)
	exitResult.requireFailure(t)
	if exitResult.ExitCode != 42 {
		t.Fatalf("exit code = %d, want 42\n%s", exitResult.ExitCode, exitResult.Combined)
	}

	stderrResult := project.run(t, "", sh("echo error >&2")...)
	stderrResult.requireSuccess(t)
	requireContainsAll(t, stderrResult.Stdout, "error")

	interactive := project.runPTY(t, "whoami\npwd\nls /workspace\nexit\n", "--", "bash")
	interactive.requireSuccess(t)
	requireContainsAll(t, interactive.Stdout, "/workspace", "hello.txt")

	interrupted := project.runWithSignal(t, 5*time.Second, os.Interrupt, "--", "sleep", "3600")
	interrupted.requireFailure(t)
	if interrupted.ExitCode == 0 {
		t.Fatalf("interrupt exit code = 0\n%s", interrupted.Combined)
	}

	envResult := project.run(t, "", sh(`echo "$MY_VAR $TERM"`)...)
	envResult.requireSuccess(t)
	requireContainsAll(t, envResult.Stdout, "hello123 xterm-256color")

	dryRun := project.run(t, "", "--dry-run", "--", "echo", "hello")
	dryRun.requireSuccess(t)
	requireContainsAll(t, dryRun.Stdout, "dry-run: image=ubuntu:24.04", `command=["echo" "hello"]`)

	workspaceResult := project.run(t, "", sh("cat /workspace/hello.txt")...)
	workspaceResult.requireSuccess(t)
	requireContainsAll(t, workspaceResult.Stdout, "hello from host")

	limitsResult := project.run(t, "", sh(`printf 'CPUS=%s\nMEMKB=%s\n' "$(nproc)" "$(awk '/MemTotal:/ {print $2}' /proc/meminfo)"`)...)
	limitsResult.requireSuccess(t)
	requireContainsAll(t, limitsResult.Stdout, "CPUS=1", "MEMKB=")
}

func (s *e2eSuite) testFilesystemOperations(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "ubuntu:24.04", yamlBlock(
		"network:",
		"  endpoints:",
		"    - host: archive.ubuntu.com",
		"      port: 80",
		"    - host: security.ubuntu.com",
		"      port: 80",
		"    - host: '*.ubuntu.com'",
		"      port: 80",
	))

	result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y curl jq >/dev/null
which curl
which jq
echo "bin-test" > /usr/local/bin/test-script
chmod +x /usr/local/bin/test-script
echo "lib-test" > /usr/local/lib/test.conf
echo "tmp-test" > /tmp/test.tmp
cat /usr/local/bin/test-script
cat /usr/local/lib/test.conf
cat /tmp/test.tmp
echo "new file" > /workspace/created-in-vm.txt
mkdir -p /workspace/subdir
echo "nested" > /workspace/subdir/nested.txt
dd if=/dev/urandom of=/workspace/large.bin bs=1M count=100 status=none
touch /workspace/perm-test
chmod 755 /workspace/perm-test
ls -lh /workspace/large.bin
stat -c '%a %n' /workspace/perm-test
`)...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout,
		"/usr/bin/curl",
		"/usr/bin/jq",
		"bin-test",
		"lib-test",
		"tmp-test",
		"100M",
		"755 /workspace/perm-test",
	)
	requireFileMissing(t, filepath.Join(project.dir, "created-in-vm.txt"))
}

func (s *e2eSuite) testDNSPolicy(t *testing.T) {
	t.Run("Allow Deny Wildcard", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: example.com",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: api.github.com",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: '*.ubuntu.com'",
			"      port: 80",
			"    - host: archive.ubuntu.com",
			"      port: 80",
			"    - host: security.ubuntu.com",
			"      port: 80",
		))

		result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y dnsutils >/dev/null
echo EXAMPLE
dig +short example.com
echo GIST
dig +short gist.github.com
echo RANDOM
dig +short randomsite123456.example
echo UBUNTU
dig +short archive.ubuntu.com
dig +short security.ubuntu.com
`)...)
		result.requireSuccess(t)
		requireContainsAll(t, result.Stdout, "EXAMPLE", "UBUNTU")
		requireContainsAll(t, result.Stderr,
			"dns  example.com:53 policy=allowed",
			"dns  gist.github.com:53 policy=denied",
			"dns  randomsite123456.example:53 policy=denied",
			"dns  archive.ubuntu.com:53 policy=allowed",
			"dns  security.ubuntu.com:53 policy=allowed",
		)
	})

	t.Run("Denied Takes Precedence", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: api.github.com",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: archive.ubuntu.com",
			"      port: 80",
			"    - host: security.ubuntu.com",
			"      port: 80",
			"    - host: '*.ubuntu.com'",
			"      port: 80",
		))
		result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y dnsutils >/dev/null
dig +short api.github.com
dig +short gist.github.com
`)...)
		result.requireSuccess(t)
		requireContainsAll(t, result.Stderr,
			"dns  api.github.com:53 policy=allowed",
			"dns  gist.github.com:53 policy=denied",
		)
	})
}

func (s *e2eSuite) testTCPTLSPolicy(t *testing.T) {
	t.Run("HTTPS HTTP CIDR And SNI", func(t *testing.T) {
		project := s.newProject(t)
		serverPort := startLocalHTTPServer(t, "NeverSSL from host\n")
		project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: neverssl.com",
			"      port: 80",
			"  ip_rules:",
			"    - cidr: 172.22.0.0/16",
			fmt.Sprintf("      port: %d", serverPort),
		))

		allowedHTTPS := project.run(t, "", sh("curl -fsS https://httpbin.org/get")...)
		allowedHTTPS.requireSuccess(t)
		requireContainsAll(t, allowedHTTPS.Stdout, `"url": "https://httpbin.org/get"`)
		requireContainsAll(t, allowedHTTPS.Stderr, "tcp  httpbin.org:443 policy=allowed")

		deniedSNI := project.run(t, "", sh("curl -fsS https://example.com")...)
		deniedSNI.requireFailure(t)
		requireContainsAll(t, deniedSNI.Stderr, "dns  example.com:53 policy=denied")

		allowedHTTP := project.run(t, "", sh(fmt.Sprintf(`
gw=$(ip route | awk '/default/ {print $3; exit}')
curl -fsS "http://$gw:%d"
`, serverPort))...)
		allowedHTTP.requireSuccess(t)
		requireContainsAll(t, allowedHTTP.Stdout, "NeverSSL from host")
		requireContainsAll(t, allowedHTTP.Stderr, "tcp  172.22.", "policy=allowed")

		deniedCIDR := project.run(t, "", sh("curl --connect-timeout 3 http://10.0.0.1:80")...)
		deniedCIDR.requireFailure(t)
		requireContainsAll(t, deniedCIDR.Stderr, "tcp  10.0.0.1:80 policy=denied")
	})

	t.Run("No SNI Enforcement", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: httpbin.org",
			"      port: 8443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: archive.ubuntu.com",
			"      port: 80",
			"    - host: security.ubuntu.com",
			"      port: 80",
			"    - host: '*.ubuntu.com'",
			"      port: 80",
		))
		denied := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y openssl >/dev/null
echo | openssl s_client -connect httpbin.org:443 -noservername >/tmp/out 2>&1
cat /tmp/out
`)...)
		denied.requireFailure(t)
		requireContainsAll(t, denied.Stderr, "tcp  httpbin.org:443 policy=denied")

		// Verify required SNI matching is enforced on non-standard TLS ports too.
		deniedNonStd := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y openssl >/dev/null
echo | openssl s_client -connect httpbin.org:8443 -noservername >/tmp/out_8443 2>&1
cat /tmp/out_8443
`)...)
		deniedNonStd.requireFailure(t)
		requireContainsAll(t, deniedNonStd.Stderr, "tcp  httpbin.org:8443 policy=denied")

		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: false",
			"    - host: archive.ubuntu.com",
			"      port: 80",
			"    - host: security.ubuntu.com",
			"      port: 80",
			"    - host: '*.ubuntu.com'",
			"      port: 80",
		))
		allowed := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y openssl >/dev/null
echo | openssl s_client -connect httpbin.org:443 -noservername >/tmp/out 2>&1
grep -q CONNECTED /tmp/out
cat /tmp/out
`)...)
		allowed.requireSuccess(t)
		requireContainsAll(t, allowed.Stderr, "tcp  httpbin.org:443 policy=allowed")
	})

	t.Run("Non-Standard Port TLS SNI", func(t *testing.T) {
		// Verify that endpoint TLS SNI matching is enforced on non-standard
		// TLS ports, not only port 443.
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: httpbin.org",
			"      port: 8443",
			"      tls:",
			"        require_sni_match: true",
			"    - host: archive.ubuntu.com",
			"      port: 80",
			"    - host: security.ubuntu.com",
			"      port: 80",
			"    - host: '*.ubuntu.com'",
			"      port: 80",
		))

		// Port 443: denied by SNI (baseline).
		denied443 := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y openssl >/dev/null
real_ip=$(getent ahostsv4 httpbin.org | awk '{print $1; exit}')
echo | openssl s_client -connect "${real_ip}:443" -servername other.httpbin.org >/tmp/out_443 2>&1 || echo SNI_DENIED_443
`)...)
		denied443.requireSuccess(t)
		requireContainsAll(t, denied443.Stdout, "SNI_DENIED_443")
		requireContainsAll(t, denied443.Stderr, "tcp  httpbin.org:443 policy=denied")

		// Port 8443: must also be denied by endpoint policy, not allowed via DNS correlation.
		// Before the fix, non-standard ports bypassed SNI checks and would show
		// "policy=allowed" (allowed via dns correlation) instead of "policy=denied".
		denied8443 := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y openssl >/dev/null
real_ip=$(getent ahostsv4 httpbin.org | awk '{print $1; exit}')
echo | openssl s_client -connect "${real_ip}:8443" -servername other.httpbin.org >/tmp/out_8443 2>&1 || echo SNI_DENIED_8443
`)...)
		denied8443.requireSuccess(t)
		requireContainsAll(t, denied8443.Stdout, "SNI_DENIED_8443")
		requireContainsAll(t, denied8443.Stderr,
			"dns  httpbin.org:53 policy=allowed",
			"tcp  httpbin.org:8443 policy=denied",
		)
		requireNotContains(t, denied8443.Stderr, "tcp  httpbin.org:8443 policy=allowed")
	})
}

func startLocalHTTPServer(t *testing.T, body string) int {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
	})

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = fmt.Fprint(w, body)
		}),
	}
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
	})
	return listener.Addr().(*net.TCPAddr).Port
}

func (s *e2eSuite) testSecurityAndEvasion(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "ubuntu:24.04", yamlBlock(
		"network:",
		"  endpoints:",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: archive.ubuntu.com",
		"      port: 80",
		"    - host: security.ubuntu.com",
		"      port: 80",
		"    - host: '*.ubuntu.com'",
		"      port: 80",
	))

	result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y iputils-ping dnsutils openssl netcat-openbsd iptables iproute2 curl >/dev/null
ping -c 1 -W 3 8.8.8.8 || echo ICMP_BLOCKED
timeout 3 sh -c 'printf keel | nc -w 2 1.1.1.1 443 | grep -q .' || echo TCP_BLOCKED
REAL_IP=$(dig +short httpbin.org | head -1)
echo | openssl s_client -connect "${REAL_IP}:443" -servername example.com >/tmp/fronting 2>&1 || true
grep -qE 'CONNECTED|alert|handshake' /tmp/fronting || true
curl -fsS --resolve "example.com:443:${REAL_IP}" https://example.com/get || echo REBIND_BLOCKED
dig +short google.com || true
dig TXT long-record.example.com || true
printf 'nameserver 8.8.8.8\n' > /etc/resolv.conf
dig +short google.com || echo DNS_OVERRIDE_BLOCKED
iptables -t nat -F || true
curl --connect-timeout 3 https://google.com || echo IPTABLES_FLUSH_BLOCKED
dig TXT long-record.example.com || echo TXT_BLOCKED
ping6 -c 1 -W 3 2606:4700:4700::1111 || echo IPV6_BLOCKED
ip link add dummy0 type dummy || true
timeout 3 sh -c 'printf keel | nc -w 2 1.1.1.1 443 | grep -q .' || echo DUMMY_IF_BLOCKED
`)...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout,
		"ICMP_BLOCKED",
		"TCP_BLOCKED",
		"REBIND_BLOCKED",
		"DNS_OVERRIDE_BLOCKED",
		"IPTABLES_FLUSH_BLOCKED",
		"TXT_BLOCKED",
		"IPV6_BLOCKED",
		"DUMMY_IF_BLOCKED",
	)
	requireContainsAll(t, result.Stderr,
		"tcp  1.1.1.1:443 policy=denied",
		"dns  google.com:53 policy=denied",
		"dns  long-record.example.com:53 policy=denied",
	)
}

func (s *e2eSuite) testMITMHTTPPolicy(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
		"network:",
		"  endpoints:",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"      mitm:",
		"        required: true",
		"      http:",
		"        default: deny",
		"        rules:",
		"          - action: allow",
		"            methods: ['GET']",
		"            paths: ['/get', '/status/*']",
		"          - action: deny",
		"            methods: ['POST', 'PUT', 'DELETE']",
		"            paths: ['/*']",
		"  mitm:",
		"    ca:",
		"      name: keel-test-ca",
		"      install_system: true",
		"      install_docker: false",
	))

	allowedGet := project.run(t, "", sh("curl -fsS https://httpbin.org/get")...)
	allowedGet.requireSuccess(t)
	requireContainsAll(t, allowedGet.Stdout, `"url": "https://httpbin.org/get"`)
	requireContainsAll(t, allowedGet.Stderr, "http httpbin.org GET /get policy=allowed")

	allowedStatus := project.run(t, "", sh("curl -fsS https://httpbin.org/status/200 >/dev/null && echo status-ok")...)
	allowedStatus.requireSuccess(t)
	requireContainsAll(t, allowedStatus.Stdout, "status-ok")
	requireContainsAll(t, allowedStatus.Stderr, "http httpbin.org GET /status/200 policy=allowed")

	deniedPath := project.run(t, "", sh("curl -fsS https://httpbin.org/anything")...)
	deniedPath.requireFailure(t)
	requireContainsAll(t, deniedPath.Stderr, "http httpbin.org GET /anything policy=denied")

	deniedMethod := project.run(t, "", sh(`curl -fsS -X POST https://httpbin.org/post -d "test=123"`)...)
	deniedMethod.requireFailure(t)
	requireContainsAll(t, deniedMethod.Stderr, "http httpbin.org POST /post policy=denied")

	caPath := filepath.Join(project.home, ".local", "share", "keel", "ca", "ca.crt")
	requireFileContains(t, caPath, "BEGIN CERTIFICATE")

	project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
		"network:",
		"  endpoints:",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"  mitm:",
		"    ca:",
		"      name: keel-test-ca",
		"      install_system: true",
	))
	bypass := project.run(t, "", sh(`curl -fsS -X POST https://httpbin.org/post -d "test=123"`)...)
	bypass.requireSuccess(t)
	requireContainsAll(t, bypass.Stdout, `"url": "https://httpbin.org/post"`)
}

func (s *e2eSuite) testAuditMode(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
		"network:",
		"  audit: true",
		"  endpoints:",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
	))

	result := project.run(t, "", sh("curl -fsS https://api.github.com/repos/moolen/keel >/dev/null && echo audit-ok")...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout, "audit-ok")
	requireContainsAll(t, result.Stderr,
		"policy=would_deny",
		"dns  api.github.com:53 policy=would_deny",
		"tcp  api.github.com:443 policy=would_deny",
	)
}

func (s *e2eSuite) testDockerInVM(t *testing.T) {
	requireFreeDiskSpace(t, "/var/tmp", 10*1024*1024*1024)

	project := s.newProject(t)
	dockerProbeDir := filepath.Join(project.dir, "docker-probe")
	writeTextFile(t, filepath.Join(dockerProbeDir, "Dockerfile"), `FROM quay.io/libpod/alpine:latest
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG NO_PROXY
ARG http_proxy
ARG https_proxy
ARG no_proxy
RUN env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
    sh -eux -c 'apk update >/dev/null && apk add --no-cache curl >/dev/null && curl --noproxy "*" -fsS https://httpbin.org/get >/dev/null && echo build-transparent-ok'
RUN sh -eux -c 'test -n "${HTTP_PROXY:-}${http_proxy:-}" && apk update >/dev/null && apk add --no-cache curl >/dev/null && curl -fsS https://httpbin.org/get >/dev/null && echo build-proxy-ok'
`)
	project.writeConfig(t, "docker:28-dind", yamlBlock(
		"workspace:",
		"  mount: .",
		"  target: /workspace",
		"resources:",
		"  root_disk_mb: 8192",
		"network:",
		"  endpoints:",
		"    - host: auth.docker.io",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: registry-1.docker.io",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: production.cloudflare.docker.com",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.r2.cloudflarestorage.com'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.docker.io'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.docker.com'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: quay.io",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.quay.io'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: ghcr.io",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: pkg-containers.githubusercontent.com",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.githubusercontent.com'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: '*.cloudfront.net'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: dl-cdn.alpinelinux.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: dl-cdn.alpinelinux.org",
		"      port: 80",
		"    - host: '*.alpinelinux.org'",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: registry.npmjs.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"features:",
		"  - name: docker",
		"    config:",
		"      storage_driver: vfs",
	))

	result := project.run(t, "", sh(`
set -eu
apk add --no-cache curl >/dev/null
docker version >/dev/null
echo docker-version-ok
docker pull quay.io/libpod/alpine:latest >/dev/null
docker run --rm quay.io/libpod/alpine:latest echo "hello from docker"
docker run --rm -i \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e NO_PROXY= \
  -e http_proxy= -e https_proxy= -e no_proxy= \
  quay.io/libpod/alpine:latest sh -eux -c '
    apk update >/dev/null
    apk add --no-cache curl >/dev/null
    curl --noproxy "*" -fsS https://httpbin.org/get >/dev/null
    echo docker-transparent-ok
  '
docker run --rm -i quay.io/libpod/alpine:latest sh -eux -c '
  env | grep -Eq "^(HTTP_PROXY|http_proxy)=http://172.17.0.1:3128$"
  apk update >/dev/null
  apk add --no-cache curl >/dev/null
  curl -fsS https://httpbin.org/get >/dev/null
  echo docker-proxy-ok
'
cd /workspace/docker-node
docker build -t keel-node-test .
docker run --rm -d -p 3000:3000 --name node-test keel-node-test >/dev/null
sleep 2
curl -fsS http://localhost:3000
docker stop node-test >/dev/null
cd /workspace/docker-python
docker build -t keel-python-test .
docker run --rm -d -p 5000:5000 --name python-test keel-python-test >/dev/null
sleep 2
curl -fsS http://localhost:5000
docker stop python-test >/dev/null
cd /workspace/docker-probe
docker build --no-cache -t keel-alpine-probe .
echo docker-build-ok
`)...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout,
		"docker-version-ok",
		"hello from docker",
		"docker-transparent-ok",
		"docker-proxy-ok",
		"hello from node",
		"hello from python",
		"docker-build-ok",
	)
	requireContainsAll(t, result.Combined,
		"build-transparent-ok",
		"build-proxy-ok",
		"Network summary:",
	)
}

func (s *e2eSuite) testWorkspaceSync(t *testing.T) {
	t.Run("Disabled By Default", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"workspace:",
			"  mount: .",
			"  sync_back: false",
		))
		result := project.run(t, "", bash(`
set -eu
echo "vm-created" > /workspace/vm-file.txt
echo "modified" > /workspace/existing.txt
`)...)
		result.requireSuccess(t)
		requireFileMissing(t, filepath.Join(project.dir, "vm-file.txt"))
		requireFileContains(t, project.fixtures.Existing, "original content")
	})

	t.Run("Enabled Without Deletes", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"workspace:",
			"  mount: .",
			"  sync_back: true",
			"  sync_confirm: false",
			"  sync_deletes: false",
		))
		result := project.run(t, "", bash(`
set -eu
echo "created in vm" > /workspace/new-from-vm.txt
mkdir -p /workspace/new-subdir
echo "nested" > /workspace/new-subdir/nested.txt
echo "updated content" > /workspace/existing.txt
rm /workspace/do-not-delete.txt
`)...)
		result.requireSuccess(t)
		requireFileContains(t, filepath.Join(project.dir, "new-from-vm.txt"), "created in vm")
		requireFileContains(t, filepath.Join(project.dir, "new-subdir", "nested.txt"), "nested")
		requireFileContains(t, project.fixtures.Existing, "updated content")
		requireFileContains(t, project.fixtures.DoNotDelete, "keep me")
	})

	t.Run("Deletes And Prompt", func(t *testing.T) {
		project := s.newProject(t)
		writeTextFile(t, filepath.Join(project.dir, "deletable.txt"), "delete me\n")

		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"workspace:",
			"  mount: .",
			"  sync_back: true",
			"  sync_confirm: false",
			"  sync_deletes: true",
		))
		deleteResult := project.run(t, "", bash(`rm /workspace/deletable.txt`)...)
		deleteResult.requireSuccess(t)
		requireFileMissing(t, filepath.Join(project.dir, "deletable.txt"))

		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"workspace:",
			"  mount: .",
			"  sync_back: true",
			"  sync_confirm: true",
			"  sync_deletes: false",
		))
		yesResult := project.run(t, "y\n", bash(`echo "confirm-test" > /workspace/confirm-file.txt`)...)
		yesResult.requireSuccess(t)
		requireContainsAll(t, yesResult.Stderr, "Apply workspace changes?")
		requireFileContains(t, filepath.Join(project.dir, "confirm-file.txt"), "confirm-test")

		noResult := project.run(t, "n\n", bash(`echo "skip-sync" > /workspace/no-sync.txt`)...)
		noResult.requireSuccess(t)
		requireContainsAll(t, noResult.Stderr, "Apply workspace changes?")
		requireFileMissing(t, filepath.Join(project.dir, "no-sync.txt"))
	})
}

func (s *e2eSuite) testAgentWorkflow(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "ubuntu:24.04", yamlBlock(
		"workspace:",
		"  mount: .",
		"  sync_back: true",
		"  sync_confirm: false",
		"  sync_deletes: false",
		"network:",
		"  endpoints:",
		"    - host: archive.ubuntu.com",
		"      port: 80",
		"    - host: security.ubuntu.com",
		"      port: 80",
		"    - host: '*.ubuntu.com'",
		"      port: 80",
	))

	result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y golang-go git >/dev/null
cat /workspace/hello.txt
cat /workspace/src/main.go
cat > /workspace/src/handler.go <<'GOFILE'
package main

import "fmt"

func handler() string {
    return fmt.Sprintf("handled at %s", "test")
}
GOFILE
sed -i "s/original content/modified by agent/" /workspace/existing.txt
for i in $(seq 1 10); do
  echo "file $i content" > /workspace/batch-$i.txt
done
cat > /workspace/main_test.go <<'GOFILE'
package main

import "testing"

func TestHello(t *testing.T) {
	if "hello" != "hello" {
		t.Fatal("mismatch")
	}
}
GOFILE
cd /workspace
export HOME=/tmp
export GOCACHE=/tmp/go-build
go mod init keel-e2e-agent >/dev/null
go test ./...
git init >/dev/null
git add -A
git -c color.status=false status --short
`)...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout, "hello from host", "A  src/handler.go", "A  main_test.go")
	requireFileContains(t, filepath.Join(project.fixtures.SourceDir, "handler.go"), "func handler() string")
	requireFileContains(t, project.fixtures.Existing, "modified by agent")
	for i := 1; i <= 10; i++ {
		requireFileContains(t, filepath.Join(project.dir, "batch-"+strconv.Itoa(i)+".txt"), "file")
	}
}

func (s *e2eSuite) testParallelNetworkStress(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
		"network:",
		"  endpoints:",
		"    - host: api.github.com",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
		"    - host: httpbin.org",
		"      port: 443",
		"      tls:",
		"        require_sni_match: true",
	))

	result := project.run(t, "", sh(`
set -eu
seq 1 24 | xargs -P 8 -I{} sh -c '
  env -u HTTP_PROXY -u HTTPS_PROXY -u NO_PROXY -u http_proxy -u https_proxy -u no_proxy \
    curl --noproxy "*" -fsS "https://httpbin.org/get?direct={}" >/dev/null
  curl -fsS "https://api.github.com/rate_limit?proxy={}" >/dev/null
'
echo stress-ok
`)...)
	result.requireSuccess(t)
	requireContainsAll(t, result.Stdout, "stress-ok")
	requireContainsAll(t, result.Stderr, "Network summary:")
}

func (s *e2eSuite) testShutdownSummary(t *testing.T) {
	t.Run("Printed And Aggregated", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
		))
		result := project.run(t, "", sh(`
curl -fsS https://httpbin.org/get >/dev/null
curl -fsS https://httpbin.org/status/200 >/dev/null
curl -fsS https://httpbin.org/status/201 >/dev/null
echo no-network-check
`)...)
		result.requireSuccess(t)
		requireContainsAll(t, result.Stderr,
			"Network summary:",
			"dns  httpbin.org:53 policy=allowed",
			"tcp  httpbin.org:443 policy=allowed count=3",
		)
	})

	t.Run("HTTP Details And Empty Summary", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
			"network:",
			"  endpoints:",
			"    - host: httpbin.org",
			"      port: 443",
			"      tls:",
			"        require_sni_match: true",
			"      mitm:",
			"        required: true",
			"      http:",
			"        default: deny",
			"        rules:",
			"          - action: allow",
			"            methods: ['GET']",
			"            paths: ['/get']",
			"  mitm:",
			"    ca:",
			"      name: keel-summary-ca",
			"      install_system: true",
		))
		httpResult := project.run(t, "", sh("curl -fsS https://httpbin.org/get >/dev/null")...)
		httpResult.requireSuccess(t)
		requireContainsAll(t, httpResult.Stderr, "http httpbin.org GET /get policy=allowed")

		emptyProject := s.newProject(t)
		emptyProject.writeConfig(t, "ubuntu:24.04", "")
		noNetwork := emptyProject.run(t, "", sh(`echo "no network"`)...)
		noNetwork.requireSuccess(t)
		requireNotContains(t, noNetwork.Stderr, "Network summary:")
	})
}

func (s *e2eSuite) testResourceCleanup(t *testing.T) {
	baseline := captureHostResources(t)

	t.Run("Successful Command", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ghcr.io/moolen/keel-devtools:main", "")

		result := project.run(t, "", sh(`echo cleanup-ok`)...)
		result.requireSuccess(t)
		requireContainsAll(t, result.Stdout, "cleanup-ok")
		requireNoNewHostResources(t, baseline)
	})

	t.Run("Nonzero Exit", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ghcr.io/moolen/keel-devtools:main", "")

		result := project.run(t, "", sh(`exit 42`)...)
		result.requireFailure(t)
		if result.ExitCode != 42 {
			t.Fatalf("exit code = %d, want 42\n%s", result.ExitCode, result.Combined)
		}
		requireNoNewHostResources(t, baseline)
	})

	t.Run("Interrupted Command", func(t *testing.T) {
		project := s.newProject(t)
		project.writeConfig(t, "ghcr.io/moolen/keel-devtools:main", "")

		result := project.runWithSignal(t, 3*time.Second, os.Interrupt, "--", "sleep", "3600")
		result.requireFailure(t)
		requireNoNewHostResources(t, baseline)
	})

	t.Run("Concurrent Commands", func(t *testing.T) {
		projects := make([]*e2eProject, 2)
		for i := range projects {
			projects[i] = s.newProject(t)
			projects[i].writeConfig(t, "ghcr.io/moolen/keel-devtools:main", "")
		}

		errCh := make(chan error, 2)
		for i := range 2 {
			i := i
			go func() {
				if i > 0 {
					time.Sleep(5 * time.Second)
				}
				result := projects[i].run(t, "", sh(fmt.Sprintf("echo concurrent-%d\nsleep 10", i))...)
				if result.Err != nil {
					errCh <- fmt.Errorf("run %d failed with exit=%d\nstdout:\n%s\nstderr:\n%s", i, result.ExitCode, result.Stdout, result.Stderr)
					return
				}
				if !strings.Contains(result.Stdout, fmt.Sprintf("concurrent-%d", i)) {
					errCh <- fmt.Errorf("run %d stdout = %q, want marker", i, result.Stdout)
					return
				}
				errCh <- nil
			}()
		}
		for range 2 {
			if err := <-errCh; err != nil {
				t.Fatal(err)
			}
		}
		requireNoNewHostResources(t, baseline)
	})
}

type hostResourceSnapshot struct {
	firecracker map[string]struct{}
	taps        map[string]struct{}
	iptables    map[string]struct{}
	runtimeDirs map[string]struct{}
	controlDirs map[string]struct{}
}

func captureHostResources(t *testing.T) hostResourceSnapshot {
	t.Helper()
	return hostResourceSnapshot{
		firecracker: captureFirecrackerProcesses(t),
		taps:        captureKeelTapDevices(t),
		iptables:    captureKeelIPTablesRules(t),
		runtimeDirs: captureGlobSet(t, "/var/lib/keel/runtime/vm-*", "/var/tmp/keel/runtime/vm-*"),
		controlDirs: captureGlobSet(t, "/var/run/keel/vm-*", filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "keel", "vm-*"), "/tmp/keel-run/vm-*"),
	}
}

func requireNoNewHostResources(t *testing.T, baseline hostResourceSnapshot) {
	t.Helper()

	var diff string
	deadline := time.Now().Add(10 * time.Second)
	for {
		current := captureHostResources(t)
		diff = hostResourceDiff(baseline, current)
		if diff == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("host resources leaked after run:\n%s", diff)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func hostResourceDiff(before, after hostResourceSnapshot) string {
	var out strings.Builder
	appendSetDiff(&out, "firecracker processes", before.firecracker, after.firecracker)
	appendSetDiff(&out, "tap devices", before.taps, after.taps)
	appendSetDiff(&out, "iptables rules", before.iptables, after.iptables)
	appendSetDiff(&out, "runtime dirs", before.runtimeDirs, after.runtimeDirs)
	appendSetDiff(&out, "control dirs", before.controlDirs, after.controlDirs)
	return out.String()
}

func appendSetDiff(out *strings.Builder, label string, before, after map[string]struct{}) {
	for item := range after {
		if _, ok := before[item]; ok {
			continue
		}
		fmt.Fprintf(out, "%s: %s\n", label, item)
	}
}

func captureFirecrackerProcesses(t *testing.T) map[string]struct{} {
	t.Helper()
	output := commandOutput(t, "ps", "-eo", "pid=,args=")
	out := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.Contains(line, "firecracker") {
			continue
		}
		out[line] = struct{}{}
	}
	return out
}

func captureKeelTapDevices(t *testing.T) map[string]struct{} {
	t.Helper()
	output := commandOutput(t, "ip", "-o", "link", "show")
	out := map[string]struct{}{}
	for _, line := range strings.Split(output, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) < 2 {
			continue
		}
		name := strings.TrimSpace(strings.Split(fields[1], "@")[0])
		if strings.HasPrefix(name, "keel") {
			out[name] = struct{}{}
		}
	}
	return out
}

func captureKeelIPTablesRules(t *testing.T) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, args := range [][]string{
		{"iptables", "-S"},
		{"iptables", "-t", "nat", "-S"},
		{"ip6tables", "-S"},
		{"ip6tables", "-t", "nat", "-S"},
	} {
		output := commandOutput(t, "sudo", append([]string{"-n"}, args...)...)
		for _, line := range strings.Split(output, "\n") {
			line = strings.TrimSpace(line)
			if strings.Contains(line, "keel") {
				out[strings.Join(args, " ")+" "+line] = struct{}{}
			}
		}
	}
	return out
}

func captureGlobSet(t *testing.T, patterns ...string) map[string]struct{} {
	t.Helper()
	out := map[string]struct{}{}
	for _, pattern := range patterns {
		if strings.Contains(pattern, string(filepath.Separator)+".") || strings.Contains(pattern, "\x00") {
			continue
		}
		if strings.HasPrefix(pattern, "keel") {
			continue
		}
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range matches {
			out[match] = struct{}{}
		}
	}
	return out
}

func commandOutput(t *testing.T, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s failed: %v\n%s", name, strings.Join(args, " "), err, output)
	}
	return string(output)
}
