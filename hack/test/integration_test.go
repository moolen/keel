package test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
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
	if os.Getenv("KEEL_E2E_STRESS") == "1" {
		t.Run("T13 Parallel Network Stress", suite.testParallelNetworkStress)
	}
}

func (s *e2eSuite) testImageManagement(t *testing.T) {
	project := s.newProject(t)
	project.writeConfig(t, "ubuntu:24.04", "")

	pull24 := project.run(t, "", "image", "pull", "ubuntu:24.04")
	pull24.requireSuccess(t)

	list24 := project.run(t, "", "image", "list")
	list24.requireSuccess(t)
	requireContainsAll(t, list24.Stdout, "index.docker.io/library/ubuntu:24.04", "B")

	layout24, err := image.ResolveCacheLayout(project.cacheDir, "ubuntu:24.04")
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(layout24.RootfsPath)
	if err != nil {
		t.Fatal(err)
	}
	secondPull := project.run(t, "", "image", "pull", "ubuntu:24.04")
	secondPull.requireSuccess(t)
	after, err := os.Stat(layout24.RootfsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatalf("duplicate pull rewrote cached rootfs: before=%s after=%s", before.ModTime(), after.ModTime())
	}

	rm24 := project.run(t, "", "image", "rm", "ubuntu:24.04")
	rm24.requireSuccess(t)
	requireFileMissing(t, layout24.RootfsPath)

	listAfterRemove := project.run(t, "", "image", "list")
	listAfterRemove.requireSuccess(t)
	requireNotContains(t, listAfterRemove.Stdout, "index.docker.io/library/ubuntu:24.04")

	repull24 := project.run(t, "", "image", "pull", "ubuntu:24.04")
	repull24.requireSuccess(t)

	missing := project.run(t, "", "image", "pull", "nonexistent/image:fake")
	missing.requireFailure(t)
	requireContainsAll(t, missing.Combined, "nonexistent/image:fake")

	pull22 := project.run(t, "", "image", "pull", "ubuntu:22.04")
	pull22.requireSuccess(t)
	listBoth := project.run(t, "", "image", "list")
	listBoth.requireSuccess(t)
	requireContainsAll(t, listBoth.Stdout,
		"index.docker.io/library/ubuntu:22.04",
		"index.docker.io/library/ubuntu:24.04",
	)
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
		"  dns:",
		"    allowed:",
		"      - archive.ubuntu.com",
		"      - security.ubuntu.com",
		"      - '*.ubuntu.com'",
		"  tls:",
		"    allowed_sni:",
		"      - archive.ubuntu.com",
		"      - security.ubuntu.com",
		"      - '*.ubuntu.com'",
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
			"  dns:",
			"    allowed:",
			"      - example.com",
			"      - '*.github.com'",
			"      - '*.ubuntu.com'",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
			"    denied:",
			"      - gist.github.com",
			"  tls:",
			"    allowed_sni:",
			"      - '*.ubuntu.com'",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
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
			"  dns:",
			"    allowed:",
			"      - '*.github.com'",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
			"      - '*.ubuntu.com'",
			"    denied:",
			"      - gist.github.com",
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
		project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
			"network:",
			"  deny_if_no_sni: true",
			"  dns:",
			"    allowed:",
			"      - httpbin.org",
			"      - neverssl.com",
			"      - example.com",
			"  tls:",
			"    allowed_sni:",
			"      - httpbin.org",
			"      - neverssl.com",
			"    denied_sni:",
			"      - example.com",
			"  tcp:",
			"    allowed_cidrs:",
			"      - 172.22.0.0/16",
			"    denied_cidrs:",
			"      - 10.0.0.0/8",
		))

		allowedHTTPS := project.run(t, "", sh("curl -fsS https://httpbin.org/get")...)
		allowedHTTPS.requireSuccess(t)
		requireContainsAll(t, allowedHTTPS.Stdout, `"url": "https://httpbin.org/get"`)
		requireContainsAll(t, allowedHTTPS.Stderr, "tcp  httpbin.org:443 policy=allowed")

		deniedSNI := project.run(t, "", sh("curl -fsS https://example.com")...)
		deniedSNI.requireFailure(t)
		requireContainsAll(t, deniedSNI.Stderr, "tcp  example.com:443 policy=denied")

		serverPort := startLocalHTTPServer(t, "NeverSSL from host\n")
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
			"  deny_if_no_sni: true",
			"  dns:",
			"    allowed:",
			"      - httpbin.org",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
			"      - '*.ubuntu.com'",
			"  tls:",
			"    allowed_sni:",
			"      - httpbin.org",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
			"      - '*.ubuntu.com'",
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

		project.writeConfig(t, "ubuntu:24.04", yamlBlock(
			"network:",
			"  deny_if_no_sni: false",
			"  dns:",
			"    allowed:",
			"      - httpbin.org",
			"      - archive.ubuntu.com",
			"      - security.ubuntu.com",
			"      - '*.ubuntu.com'",
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
		"  deny_if_no_sni: true",
		"  dns:",
		"    allowed:",
		"      - httpbin.org",
		"      - archive.ubuntu.com",
		"      - security.ubuntu.com",
		"      - '*.ubuntu.com'",
		"  tls:",
		"    allowed_sni:",
		"      - httpbin.org",
	))

	result := project.run(t, "", bash(`
set -eu
apt-get update >/dev/null
apt-get install -y iputils-ping dnsutils openssl netcat-openbsd iptables curl >/dev/null
ping -c 1 -W 3 8.8.8.8 || echo ICMP_BLOCKED
nc -z -w 3 1.1.1.1 443 || echo TCP_BLOCKED
REAL_IP=$(dig +short httpbin.org | head -1)
echo | openssl s_client -connect "${REAL_IP}:443" -servername example.com >/tmp/fronting 2>&1 || true
grep -qE 'CONNECTED|alert|handshake' /tmp/fronting || true
curl -fsS --resolve "example.com:443:${REAL_IP}" https://example.com/get || echo REBIND_BLOCKED
printf 'nameserver 8.8.8.8\n' > /etc/resolv.conf
dig +short google.com || echo DNS_OVERRIDE_BLOCKED
iptables -t nat -F || true
curl --connect-timeout 3 https://google.com || echo IPTABLES_FLUSH_BLOCKED
dig TXT long-record.example.com || echo TXT_BLOCKED
ping6 -c 1 -W 3 2606:4700:4700::1111 || echo IPV6_BLOCKED
ip link add dummy0 type dummy || true
nc -z -w 3 1.1.1.1 443 || echo DUMMY_IF_BLOCKED
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
		"  mitm:",
		"    enabled: true",
		"    mode: optional",
		"    on_untrusted_cert: deny",
		"    log_requests: true",
		"    ca:",
		"      name: keel-test-ca",
		"      install_system: true",
		"      install_docker: false",
		"    bypass:",
		"      hosts: []",
		"      sni: []",
		"  dns:",
		"    allowed:",
		"      - httpbin.org",
		"  tls:",
		"    allowed_sni:",
		"      - httpbin.org",
		"  http:",
		"    default: deny",
		"    rules:",
		"      - action: allow",
		"        host: httpbin.org",
		"        methods: ['GET']",
		"        paths: ['/get', '/status/*']",
		"      - action: deny",
		"        host: httpbin.org",
		"        methods: ['POST', 'PUT', 'DELETE']",
		"        paths: ['/*']",
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

	caPath := filepath.Join(project.home, ".local", "share", "keel", "ca", "keel-test-ca.crt")
	requireFileContains(t, caPath, "BEGIN CERTIFICATE")

	project.writeConfig(t, "curlimages/curl:latest", yamlBlock(
		"network:",
		"  mitm:",
		"    enabled: true",
		"    mode: optional",
		"    on_untrusted_cert: deny",
		"    ca:",
		"      name: keel-test-ca",
		"      install_system: true",
		"    bypass:",
		"      hosts:",
		"        - httpbin.org",
		"  dns:",
		"    allowed:",
		"      - httpbin.org",
		"  tls:",
		"    allowed_sni:",
		"      - httpbin.org",
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
		"  dns:",
		"    denied:",
		"      - api.github.com",
		"  tls:",
		"    denied_sni:",
		"      - api.github.com",
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
	requireFreeDiskSpace(t, "/var/tmp", 5*1024*1024*1024)

	project := s.newProject(t)
	dockerProbeDir := filepath.Join(project.dir, "docker-probe")
	writeTextFile(t, filepath.Join(dockerProbeDir, "Dockerfile"), `FROM alpine:3.20
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
		"  root_disk_mb: 4096",
		"network:",
		"  dns:",
		"    allowed:",
		"      - auth.docker.io",
		"      - registry-1.docker.io",
		"      - production.cloudflare.docker.com",
		"      - '*.r2.cloudflarestorage.com'",
		"      - '*.docker.io'",
		"      - '*.docker.com'",
		"      - '*.cloudfront.net'",
		"      - dl-cdn.alpinelinux.org",
		"      - '*.alpinelinux.org'",
		"      - httpbin.org",
		"      - registry.npmjs.org",
		"  tls:",
		"    allowed_sni:",
		"      - auth.docker.io",
		"      - registry-1.docker.io",
		"      - production.cloudflare.docker.com",
		"      - '*.r2.cloudflarestorage.com'",
		"      - '*.docker.io'",
		"      - '*.docker.com'",
		"      - '*.cloudfront.net'",
		"      - dl-cdn.alpinelinux.org",
		"      - '*.alpinelinux.org'",
		"      - httpbin.org",
		"      - registry.npmjs.org",
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
docker pull alpine:3.20 >/dev/null
docker run --rm alpine:3.20 echo "hello from docker"
docker run --rm -i \
  -e HTTP_PROXY= -e HTTPS_PROXY= -e NO_PROXY= \
  -e http_proxy= -e https_proxy= -e no_proxy= \
  alpine:3.20 sh -eux -c '
    apk update >/dev/null
    apk add --no-cache curl >/dev/null
    curl --noproxy "*" -fsS https://httpbin.org/get >/dev/null
    echo docker-transparent-ok
  '
docker run --rm -i alpine:3.20 sh -eux -c '
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
cd /workspace/docker-node
docker build --no-cache -t keel-node-nocache . >/dev/null
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
		"  dns:",
		"    allowed:",
		"      - archive.ubuntu.com",
		"      - security.ubuntu.com",
		"      - '*.ubuntu.com'",
		"  tls:",
		"    allowed_sni:",
		"      - archive.ubuntu.com",
		"      - security.ubuntu.com",
		"      - '*.ubuntu.com'",
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
go test ./...
git init >/dev/null
git add -A
git status --short
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
		"  dns:",
		"    allowed:",
		"      - api.github.com",
		"      - httpbin.org",
		"  tls:",
		"    allowed_sni:",
		"      - api.github.com",
		"      - httpbin.org",
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
			"  dns:",
			"    allowed:",
			"      - httpbin.org",
			"  tls:",
			"    allowed_sni:",
			"      - httpbin.org",
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
			"  mitm:",
			"    enabled: true",
			"    ca:",
			"      name: keel-summary-ca",
			"      install_system: true",
			"  dns:",
			"    allowed:",
			"      - httpbin.org",
			"  tls:",
			"    allowed_sni:",
			"      - httpbin.org",
			"  http:",
			"    default: deny",
			"    rules:",
			"      - action: allow",
			"        host: httpbin.org",
			"        methods: ['GET']",
			"        paths: ['/get']",
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
