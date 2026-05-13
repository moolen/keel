# Keel — E2E Test Plan

Manual and scriptable QA test suite for validating keel's core functionality before production use. Tests run locally on a Linux host with KVM, Firecracker, and real network access.

---

## 1. Test Environment

### 1.1 Host Prerequisites

- Linux host with `/dev/kvm` accessible
- `firecracker` in `$PATH`
- `sudo` access
- `mkfs.ext4`, `debugfs`, `iptables`, `ip6tables` available
- `keel` binary built with `dist/keel-agent` in place
- Internet access for real endpoint tests
- Docker installed on host (for building test fixture images if needed)

### 1.2 Base Image

All tests use `ubuntu:24.04` pulled via `keel image pull`. No custom pre-built image — installing tools at runtime is itself test coverage.

### 1.3 Test Project Directory

Create a disposable test project directory for each test run:

```bash
TEST_DIR=$(mktemp -d /tmp/keel-e2e-XXXXXX)
cd "$TEST_DIR"
```

Populate it with known fixture files that tests reference:

```
$TEST_DIR/
├── keel.yaml             # test-specific config (swapped per test)
├── hello.txt             # "hello from host"
├── existing.txt          # "original content"
├── do-not-delete.txt     # verify sync_deletes: false
├── src/
│   └── main.go           # simple Go program
├── docker-node/
│   ├── Dockerfile
│   ├── package.json
│   └── server.js          # Node.js hello-world HTTP server
└── docker-python/
    ├── Dockerfile
    ├── requirements.txt
    └── server.py           # Python hello-world HTTP server
```

### 1.4 Docker Test Fixtures

**Node.js app (`docker-node/`):**

```dockerfile
FROM node:20-slim
WORKDIR /app
COPY package.json .
RUN npm install
COPY server.js .
EXPOSE 3000
CMD ["node", "server.js"]
```

```javascript
// server.js
const http = require('http');
const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'text/plain'});
  res.end('hello from node\n');
});
server.listen(3000, () => console.log('listening on 3000'));
```

```json
{
  "name": "keel-test",
  "version": "1.0.0",
  "dependencies": {}
}
```

**Python app (`docker-python/`):**

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY server.py .
EXPOSE 5000
CMD ["python", "server.py"]
```

```python
# server.py
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'hello from python\n')

HTTPServer(('0.0.0.0', 5000), Handler).serve_forever()
```

```
# requirements.txt
# empty, stdlib only
```

---

## 2. Test Categories

```
T1  — Image management
T2  — VM lifecycle and basic execution
T3  — Package installation and filesystem operations
T4  — Network policy: DNS
T5  — Network policy: TCP and TLS/SNI
T6  — Network policy: security and evasion
T7  — Network policy: MITM and HTTP policy
T8  — Network policy: audit mode
T9  — Docker-in-VM
T10 — Workspace sync-back
T11 — Simulated agent workflow
T12 — Shutdown summary validation
```

---

## 3. Test Cases

### T1 — Image Management

#### T1.1 Pull image

```bash
keel image pull ubuntu:24.04
```

**Expect:** exits 0, image cached locally.

#### T1.2 List images

```bash
keel image list
```

**Expect:** shows `ubuntu:24.04` with size.

#### T1.3 Pull duplicate is idempotent

```bash
keel image pull ubuntu:24.04
```

**Expect:** exits 0, no re-download (or fast cache hit).

#### T1.4 Remove image

```bash
keel image rm ubuntu:24.04
```

**Expect:** exits 0, image removed.

```bash
keel image list
```

**Expect:** `ubuntu:24.04` no longer listed.

#### T1.5 Re-pull after remove

```bash
keel image pull ubuntu:24.04
```

**Expect:** downloads again, exits 0.

#### T1.6 Pull nonexistent image

```bash
keel image pull nonexistent/image:fake
```

**Expect:** non-zero exit, clear error message about image not found.

#### T1.7 Pull with tag and digest

```bash
keel image pull ubuntu:22.04
```

**Expect:** exits 0, listed separately from `ubuntu:24.04`.

---

### T2 — VM Lifecycle and Basic Execution

#### T2.1 Run a simple command

```bash
keel -- echo "hello from keel"
```

**Expect:** stdout contains `hello from keel`, exit code 0.

#### T2.2 Exit code propagation

```bash
keel -- sh -c "exit 42"
echo $?
```

**Expect:** host exit code is 42.

#### T2.3 Stderr forwarding

```bash
keel -- sh -c "echo error >&2"
```

**Expect:** `error` appears on host stderr.

#### T2.4 Interactive shell

```bash
keel -- bash
```

Inside the shell, run:

```bash
whoami
hostname
uname -a
pwd
ls /workspace
exit
```

**Expect:** commands work, `/workspace` contains test fixtures, PTY is functional (colors, line editing work).

#### T2.5 Long-running command with interrupt

```bash
keel -- sleep 3600
# Press Ctrl+C after a few seconds
```

**Expect:** VM shuts down cleanly, exit code reflects signal.

#### T2.6 Environment variables

Using config:

```yaml
env:
  static:
    MY_VAR: hello123
    TERM: xterm-256color
```

```bash
keel -- sh -c 'echo $MY_VAR $TERM'
```

**Expect:** `hello123 xterm-256color`.

#### T2.7 Dry run

```bash
keel --dry-run -- echo hello
```

**Expect:** prints what would happen, no VM booted.

#### T2.8 Workspace present and contains host files

```bash
keel -- sh -c 'cat /workspace/hello.txt'
```

**Expect:** `hello from host`.

#### T2.9 Resource limits

Using config with `resources.vcpu: 1` and `resources.memory_mb: 512`:

```bash
keel -- sh -c 'nproc && free -m'
```

**Expect:** 1 CPU, ~512 MB memory visible.

---

### T3 — Package Installation and Filesystem Operations

#### T3.1 apt update and install

Config with DNS/TCP allowing Ubuntu repos:

```yaml
network:
  dns:
    allowed:
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
  tls:
    allowed_sni:
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
```

```bash
keel -- bash -lc '
  apt-get update &&
  apt-get install -y curl jq &&
  which curl &&
  which jq
'
```

**Expect:** packages install successfully, binaries available.

#### T3.2 Write to standard directories

```bash
keel -- bash -lc '
  echo "bin-test" > /usr/local/bin/test-script &&
  chmod +x /usr/local/bin/test-script &&
  echo "lib-test" > /usr/local/lib/test.conf &&
  echo "tmp-test" > /tmp/test.tmp &&
  cat /usr/local/bin/test-script &&
  cat /usr/local/lib/test.conf &&
  cat /tmp/test.tmp
'
```

**Expect:** all writes succeed, reads return correct content.

#### T3.3 Create files in workspace

```bash
keel -- bash -lc '
  echo "new file" > /workspace/created-in-vm.txt &&
  mkdir -p /workspace/subdir &&
  echo "nested" > /workspace/subdir/nested.txt
'
```

**Expect:** exits 0 (sync-back validation is T10).

#### T3.4 Large file handling

```bash
keel -- bash -lc '
  dd if=/dev/urandom of=/workspace/large.bin bs=1M count=100 &&
  ls -lh /workspace/large.bin
'
```

**Expect:** 100 MB file created successfully.

#### T3.5 Permission and ownership

```bash
keel -- bash -lc '
  touch /workspace/perm-test &&
  chmod 755 /workspace/perm-test &&
  ls -la /workspace/perm-test
'
```

**Expect:** permissions set correctly.

---

### T4 — Network Policy: DNS

Config for DNS tests:

```yaml
network:
  dns:
    allowed:
      - "example.com"
      - "api.github.com"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
    denied:
      - "evil.example.com"
```

Ensure `curl` is installed (either pre-installed in image or install via T3.1 first with broader policy, then run DNS tests with this restricted config).

**Practical approach:** run DNS tests inside a single `keel -- bash` session where you first install tools, then test policy. Alternatively, use a two-phase approach: first run installs tools, second run with restricted policy tests DNS.

#### T4.1 Allowed domain resolves

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y dnsutils &&
  dig +short example.com
'
```

**Expect:** returns IP address(es).

#### T4.2 Denied domain returns NXDOMAIN or failure

```bash
keel -- bash -lc '
  dig +short evil.example.com
'
```

**Expect:** no answer / NXDOMAIN / REFUSED.

#### T4.3 Unlisted domain is denied

```bash
keel -- bash -lc '
  dig +short randomsite123456.com
'
```

**Expect:** no answer / NXDOMAIN / REFUSED (default deny for unlisted domains).

#### T4.4 Wildcard matching works

```bash
keel -- bash -lc '
  dig +short archive.ubuntu.com &&
  dig +short security.ubuntu.com
'
```

**Expect:** both resolve successfully (matched by `*.ubuntu.com`).

#### T4.5 Denied takes precedence over allowed

If `evil.example.com` is denied but `*.example.com` would be covered by a hypothetical allow:

Config:

```yaml
network:
  dns:
    allowed:
      - "*.example.com"
    denied:
      - "evil.example.com"
```

```bash
keel -- bash -lc '
  dig +short good.example.com &&
  dig +short evil.example.com
'
```

**Expect:** `good.example.com` resolves, `evil.example.com` does not.

---

### T5 — Network Policy: TCP and TLS/SNI

Config:

```yaml
network:
  deny_if_no_sni: true
  dns:
    allowed:
      - "httpbin.org"
      - "api.github.com"
      - "example.com"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
  tls:
    allowed_sni:
      - "httpbin.org"
      - "api.github.com"
    denied_sni:
      - "evil.httpbin.org"
```

#### T5.1 Allowed HTTPS succeeds

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://httpbin.org/get
'
```

**Expect:** HTTP 200 with JSON response.

#### T5.2 DNS-allowed but SNI-denied fails

```bash
keel -- bash -lc '
  curl -fsS https://evil.httpbin.org/get
'
```

**Expect:** connection refused/reset, non-zero exit.

#### T5.3 DNS-allowed but SNI-unlisted fails (deny_if_no_sni context)

```bash
keel -- bash -lc '
  curl -fsS https://example.com
'
```

**Expect:** if `example.com` is not in `tls.allowed_sni`, connection should be evaluated based on policy. With `deny_if_no_sni: true`, verify behavior matches expectations.

#### T5.4 HTTP (non-TLS) to allowed domain

```bash
keel -- bash -lc '
  curl -fsS http://httpbin.org/get
'
```

**Expect:** succeeds (no SNI involved, TCP correlation from DNS allows it).

#### T5.5 TCP to denied CIDR

Config addition:

```yaml
network:
  tcp:
    denied_cidrs:
      - "10.0.0.0/8"
```

```bash
keel -- bash -lc '
  curl --connect-timeout 3 http://10.0.0.1:80
'
```

**Expect:** connection refused/timeout, non-zero exit.

#### T5.6 deny_if_no_sni enforcement

With `deny_if_no_sni: true`, attempt a TLS connection that omits SNI:

```bash
keel -- bash -lc '
  # Use openssl s_client without SNI
  apt-get update && apt-get install -y openssl &&
  echo | openssl s_client -connect httpbin.org:443 -noservername 2>&1
'
```

**Expect:** connection denied/reset.

#### T5.7 deny_if_no_sni disabled allows no-SNI

Same test with `deny_if_no_sni: false`:

**Expect:** connection proceeds (TLS handshake completes).

---

### T6 — Network Policy: Security and Evasion

These tests validate that the network boundary is tight and resistant to bypass attempts.

Config for security tests:

```yaml
network:
  deny_if_no_sni: true
  dns:
    allowed:
      - "httpbin.org"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
  tls:
    allowed_sni:
      - "httpbin.org"
  tcp:
    allowed_cidrs: []
    denied_cidrs: []
```

#### T6.1 ICMP is blocked

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y iputils-ping &&
  ping -c 1 -W 3 8.8.8.8
'
```

**Expect:** ping fails (ICMP blocked at TAP default-deny).

#### T6.2 UDP to non-DNS port is blocked

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y netcat-openbsd &&
  echo "test" | nc -u -w 3 8.8.8.8 12345
'
```

**Expect:** no response, times out or connection refused.

#### T6.3 Direct TCP bypassing proxy is blocked

Attempt a raw TCP connection bypassing the guest proxy:

```bash
keel -- bash -lc '
  # Attempt direct connection to an IP (not through proxy)
  # If transparent redirect is active, it gets captured.
  # If not, TAP default-deny blocks it.
  apt-get update && apt-get install -y netcat-openbsd &&
  nc -z -w 3 1.1.1.1 443
'
```

**Expect:** connection fails (either captured by transparent redirect and denied by policy because IP has no DNS correlation, or blocked by TAP default-deny).

#### T6.4 Domain fronting attempt

Resolve an allowed domain, then connect to that IP but send a different SNI:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl dnsutils openssl &&
  # Resolve httpbin.org
  REAL_IP=$(dig +short httpbin.org | head -1) &&
  # Try to connect with a different SNI
  echo | openssl s_client -connect $REAL_IP:443 -servername evil.example.com 2>&1
'
```

**Expect:** connection denied — SNI `evil.example.com` does not match allowed SNI list, and/or SNI cross-check against DNS correlation fails.

#### T6.5 DNS rebinding / correlation mismatch

Attempt to use a resolved IP from one allowed domain to reach a different service:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  # httpbin.org is allowed. Try to curl a different service on the same IP.
  # This tests whether the policy engine only allows traffic when
  # the destination IP correlates to the domain that was actually allowed.
  curl -fsS --resolve "notallowed.com:443:$(dig +short httpbin.org | head -1)" \
    https://notallowed.com/get
'
```

**Expect:** denied — `notallowed.com` was never resolved via the DNS policy proxy, and/or SNI `notallowed.com` is not in the allowed list.

#### T6.6 Attempt to change /etc/resolv.conf

```bash
keel -- bash -lc '
  cat /etc/resolv.conf &&
  echo "nameserver 8.8.8.8" > /etc/resolv.conf &&
  dig +short google.com
'
```

**Expect:** even if resolv.conf is overwritten, DNS still goes through the policy path (transparent iptables redirect captures it) or the direct UDP to 8.8.8.8:53 is blocked at the TAP.

#### T6.7 Attempt to flush iptables rules in guest

```bash
keel -- bash -lc '
  iptables -t nat -F 2>&1 || echo "iptables flush failed" &&
  # Even if rules are flushed, TAP default-deny on host still blocks direct egress
  curl --connect-timeout 3 https://google.com 2>&1 || echo "blocked"
'
```

**Expect:** even if iptables rules are flushed inside the guest, direct egress is still blocked because the host TAP interface has default-deny rules. `curl` should fail.

#### T6.8 Attempt DNS tunneling (large TXT queries)

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y dnsutils &&
  dig TXT long-record.example.com
'
```

**Expect:** query is handled by the DNS policy proxy — `example.com` is not in the allowlist, so it's denied. The DNS proxy doesn't blindly forward arbitrary query types.

#### T6.9 IPv6 is blocked

```bash
keel -- bash -lc '
  ping6 -c 1 -W 3 ::1 2>&1 || echo "ipv6 blocked"
'
```

**Expect:** IPv6 blocked (ip6tables default-deny on TAP).

#### T6.10 Attempt to create additional network interfaces

```bash
keel -- bash -lc '
  ip link add dummy0 type dummy 2>&1 || echo "cannot create interface" &&
  ip link show
'
```

**Expect:** even if interface creation succeeds inside the VM, there's no route out — the only egress is through vsock.

---

### T7 — Network Policy: MITM and HTTP Policy

Config:

```yaml
network:
  dns:
    allowed:
      - "api.github.com"
      - "httpbin.org"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
  tls:
    allowed_sni:
      - "api.github.com"
      - "httpbin.org"
  mitm:
    enabled: true
    mode: optional
    on_untrusted_cert: deny
    log_requests: true
    ca:
      name: keel-test-ca
      install_system: true
      install_docker: false
    bypass:
      hosts: []
      sni: []
  http:
    default: deny
    rules:
      - action: allow
        host: api.github.com
        methods: ["GET"]
        paths:
          - /repos/*
          - /users/*
      - action: allow
        host: httpbin.org
        methods: ["GET"]
        paths:
          - /get
          - /status/*
      - action: deny
        host: httpbin.org
        methods: ["POST", "PUT", "DELETE"]
        paths:
          - /*
```

#### T7.1 Allowed GET request succeeds

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://api.github.com/repos/moolen/keel
'
```

**Expect:** HTTP 200 with JSON response. MITM inspects the request, matches `GET /repos/*` on `api.github.com`, allows.

#### T7.2 Allowed GET with different path

```bash
keel -- bash -lc '
  curl -fsS https://api.github.com/users/moolen
'
```

**Expect:** HTTP 200. Matches `GET /users/*`.

#### T7.3 Denied method (POST to httpbin)

```bash
keel -- bash -lc '
  curl -fsS -X POST https://httpbin.org/post -d "test=123"
'
```

**Expect:** request denied by HTTP policy (POST to httpbin.org is explicitly denied).

#### T7.4 Denied path (unlisted path)

```bash
keel -- bash -lc '
  curl -fsS https://api.github.com/gists
'
```

**Expect:** denied — `/gists` is not covered by `/repos/*` or `/users/*`, and `http.default` is `deny`.

#### T7.5 PUT method denied

```bash
keel -- bash -lc '
  curl -fsS -X PUT https://httpbin.org/put -d "test=123"
'
```

**Expect:** denied by explicit deny rule for PUT on httpbin.org.

#### T7.6 Allowed status endpoint

```bash
keel -- bash -lc '
  curl -fsS https://httpbin.org/status/200
'
```

**Expect:** HTTP 200. Matches `GET /status/*`.

#### T7.7 MITM CA is installed in guest trust store

```bash
keel -- bash -lc '
  ls /usr/local/share/ca-certificates/ &&
  cat /etc/ssl/certs/ca-certificates.crt | grep -c "keel"
'
```

**Expect:** keel CA certificate is present in guest trust store.

#### T7.8 MITM bypass for specified hosts

Add to config:

```yaml
  mitm:
    bypass:
      hosts:
        - "httpbin.org"
```

```bash
keel -- bash -lc '
  # httpbin.org bypasses MITM, so HTTP policy rules do not apply
  # only DNS + TCP/TLS policy applies
  curl -fsS -X POST https://httpbin.org/post -d "test=123"
'
```

**Expect:** POST succeeds because MITM is bypassed for httpbin.org, so HTTP-level policy is not evaluated. TCP/TLS policy still allows it.

---

### T8 — Network Policy: Audit Mode

Config:

```yaml
network:
  audit: true
  dns:
    allowed:
      - "httpbin.org"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
    denied:
      - "evil.example.com"
  tls:
    allowed_sni:
      - "httpbin.org"
```

#### T8.1 Denied domain is allowed in audit mode

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl dnsutils &&
  dig +short evil.example.com &&
  curl --connect-timeout 5 https://evil.example.com 2>&1 || true
'
```

**Expect:** DNS query goes through (audit mode allows it), but the shutdown summary reports `policy=would_deny` for the DNS query.

#### T8.2 Shutdown summary shows would_deny

Capture stderr:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://httpbin.org/get &&
  dig +short evil.example.com
' 2>summary.txt
```

Inspect `summary.txt`:

**Expect:** summary contains lines like:

```
dns  httpbin.org:53 policy=allowed count=...
dns  evil.example.com:53 policy=would_deny count=...
tcp  httpbin.org:443 policy=allowed count=...
```

#### T8.3 Audit mode does not block real traffic

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://httpbin.org/get
'
```

**Expect:** request succeeds normally. Audit mode does not interfere with allowed traffic.

---

### T9 — Docker-in-VM

Config:

```yaml
image: ubuntu:24.04

network:
  dns:
    allowed:
      - "*.docker.io"
      - "*.docker.com"
      - "auth.docker.io"
      - "registry-1.docker.io"
      - "production.cloudflare.docker.com"
      - "*.cloudfront.net"
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
      - "*.debian.org"
      - "deb.nodesource.com"
      - "registry.npmjs.org"
      - "*.npmjs.org"
      - "*.pythonhosted.org"
      - "pypi.org"
      - "files.pythonhosted.org"
  tls:
    allowed_sni:
      - "*.docker.io"
      - "*.docker.com"
      - "auth.docker.io"
      - "registry-1.docker.io"
      - "production.cloudflare.docker.com"
      - "*.cloudfront.net"
      - "*.ubuntu.com"
      - "*.debian.org"
      - "deb.nodesource.com"
      - "registry.npmjs.org"
      - "*.npmjs.org"
      - "*.pythonhosted.org"
      - "pypi.org"
      - "files.pythonhosted.org"

features:
  - name: docker
    config:
      storage_driver: vfs
```

**Note:** the DNS/TLS allowlist for Docker tests needs to be broad enough to cover all registry and CDN hosts involved in pulls. The list above is a starting point — actual required domains may vary. Run with `-v` or audit mode first to discover missing domains.

#### T9.1 Docker is available

```bash
keel -- bash -lc 'docker version'
```

**Expect:** docker client and daemon version printed, daemon is running.

#### T9.2 Docker pull

```bash
keel -- bash -lc 'docker pull alpine:latest && docker images'
```

**Expect:** alpine image pulled successfully, listed in `docker images`.

#### T9.3 Docker run

```bash
keel -- bash -lc 'docker run --rm alpine echo "hello from docker"'
```

**Expect:** `hello from docker` printed.

#### T9.4 Build and run Node.js app

```bash
keel -- bash -lc '
  cd /workspace/docker-node &&
  docker build -t keel-node-test . &&
  docker run --rm -d -p 3000:3000 --name node-test keel-node-test &&
  sleep 2 &&
  curl -fsS http://localhost:3000 &&
  docker stop node-test
'
```

**Expect:** `hello from node` returned by curl.

#### T9.5 Build and run Python app

```bash
keel -- bash -lc '
  cd /workspace/docker-python &&
  docker build -t keel-python-test . &&
  docker run --rm -d -p 5000:5000 --name python-test keel-python-test &&
  sleep 2 &&
  curl -fsS http://localhost:5000 &&
  docker stop python-test
'
```

**Expect:** `hello from python` returned by curl.

#### T9.6 Docker build with network access

Verify that Docker builds can pull base images and run `npm install` / `pip install` through the policy-enforced proxy:

```bash
keel -- bash -lc '
  cd /workspace/docker-node &&
  docker build --no-cache -t keel-node-nocache . 2>&1 | tail -5
'
```

**Expect:** build succeeds, pulls `node:20-slim` through the proxy path.

---

### T10 — Workspace Sync-Back

#### T10.1 Default: no sync-back (host untouched)

Config:

```yaml
workspace:
  mount: .
  sync_back: false
```

```bash
keel -- bash -lc '
  echo "vm-created" > /workspace/vm-file.txt &&
  echo "modified" > /workspace/existing.txt
'
```

After VM exits, check on host:

```bash
test ! -f "$TEST_DIR/vm-file.txt" && echo "PASS: no new file"
grep -q "original content" "$TEST_DIR/existing.txt" && echo "PASS: not modified"
```

**Expect:** host directory unchanged.

#### T10.2 sync_back enabled: new files synced

Config:

```yaml
workspace:
  mount: .
  sync_back: true
  sync_confirm: false   # <-- INVESTIGATE: does this flag exist and work?
  sync_deletes: false
```

**Open question:** does `sync_confirm: false` exist and work for non-interactive sync? If not, we need to either:
- Add it as a feature
- Use stdin redirection (`echo y | keel ...`)
- Add a `--yes` / `--sync-auto` CLI flag

Test once the mechanism is determined:

```bash
keel -- bash -lc '
  echo "created in vm" > /workspace/new-from-vm.txt &&
  mkdir -p /workspace/new-subdir &&
  echo "nested" > /workspace/new-subdir/nested.txt
'
```

After VM exits:

```bash
test -f "$TEST_DIR/new-from-vm.txt" && echo "PASS: new file synced"
grep -q "created in vm" "$TEST_DIR/new-from-vm.txt" && echo "PASS: content correct"
test -f "$TEST_DIR/new-subdir/nested.txt" && echo "PASS: nested file synced"
```

**Expect:** new files appear on host.

#### T10.3 sync_back enabled: modifications synced

```bash
keel -- bash -lc '
  echo "updated content" > /workspace/existing.txt
'
```

After VM exits:

```bash
grep -q "updated content" "$TEST_DIR/existing.txt" && echo "PASS: modification synced"
```

**Expect:** host file updated.

#### T10.4 sync_deletes: false (default) — deletions not applied

```bash
keel -- bash -lc '
  rm /workspace/do-not-delete.txt
'
```

After VM exits:

```bash
test -f "$TEST_DIR/do-not-delete.txt" && echo "PASS: file not deleted on host"
```

**Expect:** file still exists on host.

#### T10.5 sync_deletes: true — deletions applied

Config:

```yaml
workspace:
  sync_back: true
  sync_confirm: false
  sync_deletes: true
```

Create a deletable fixture:

```bash
echo "delete me" > "$TEST_DIR/deletable.txt"
```

```bash
keel -- bash -lc 'rm /workspace/deletable.txt'
```

After VM exits:

```bash
test ! -f "$TEST_DIR/deletable.txt" && echo "PASS: file deleted on host"
```

**Expect:** file removed from host.

#### T10.6 Sync confirmation prompt (if sync_confirm: true)

This test is manual or requires a mechanism to feed `y` to the prompt:

```bash
echo "y" | keel -- bash -lc 'echo "confirm-test" > /workspace/confirm-file.txt'
```

**Expect:** prompt shown (visible in stderr), file synced after confirmation. If `echo "n"` is sent, file should NOT be synced.

**INVESTIGATE:** verify how the confirmation prompt interacts with piped stdin when a PTY is in use. This may need a dedicated `--yes` flag or environment variable.

---

### T11 — Simulated Agent Workflow

Simulate what a coding agent does: read files, create new files, modify existing files, run commands, use git.

Config:

```yaml
image: ubuntu:24.04

workspace:
  mount: .
  sync_back: true
  sync_confirm: false  # or whatever mechanism works
  sync_deletes: false

network:
  dns:
    allowed:
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
  tls:
    allowed_sni:
      - "*.ubuntu.com"
      - "*.archive.ubuntu.com"
```

#### T11.1 Read existing project files

```bash
keel -- bash -lc '
  cat /workspace/hello.txt &&
  cat /workspace/src/main.go &&
  ls -la /workspace/
'
```

**Expect:** all fixture files readable with correct content.

#### T11.2 Agent creates new source file

```bash
keel -- bash -lc '
  cat > /workspace/src/handler.go << '\''GOFILE'\''
package main

import "fmt"

func handler() string {
    return fmt.Sprintf("handled at %s", "test")
}
GOFILE
'
```

After VM exits:

```bash
test -f "$TEST_DIR/src/handler.go" && echo "PASS: new source file synced"
grep -q "func handler" "$TEST_DIR/src/handler.go" && echo "PASS: content correct"
```

#### T11.3 Agent modifies existing file

```bash
keel -- bash -lc '
  sed -i "s/original content/modified by agent/" /workspace/existing.txt
'
```

After VM exits:

```bash
grep -q "modified by agent" "$TEST_DIR/existing.txt" && echo "PASS: modification synced"
```

#### T11.4 Agent creates multiple files in a batch

```bash
keel -- bash -lc '
  for i in $(seq 1 10); do
    echo "file $i content" > /workspace/batch-$i.txt
  done
'
```

After VM exits:

```bash
for i in $(seq 1 10); do
  test -f "$TEST_DIR/batch-$i.txt" && grep -q "file $i content" "$TEST_DIR/batch-$i.txt"
done && echo "PASS: all batch files synced"
```

#### T11.5 Agent installs tooling and runs tests

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y golang-go &&
  cd /workspace &&
  go version &&
  echo "package main
import \"testing\"
func TestHello(t *testing.T) {
    if \"hello\" != \"hello\" {
        t.Fatal(\"mismatch\")
    }
}" > /workspace/main_test.go &&
  go test ./...
'
```

**Expect:** Go installs, test passes.

#### T11.6 Agent uses git

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y git &&
  cd /workspace &&
  git init &&
  git add -A &&
  git status
'
```

**Expect:** git operations work inside the VM workspace.

---

### T12 — Shutdown Summary Validation

Capture and validate the shutdown summary across various scenarios.

#### T12.1 Summary printed on stderr

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://httpbin.org/get
' 2>summary.txt

cat summary.txt
```

**Expect:** `summary.txt` contains a `Network summary:` section with at least:
- DNS entries for resolved domains
- TCP entries for connections made

#### T12.2 Summary includes correct policy decisions

Using the audit mode config from T8:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl dnsutils &&
  curl -fsS https://httpbin.org/get &&
  dig +short evil.example.com
' 2>summary.txt
```

**Expect:** summary contains:
- `dns  httpbin.org... policy=allowed`
- `dns  evil.example.com... policy=would_deny`
- `tcp  httpbin.org:443 policy=allowed`

#### T12.3 Summary includes counts

Make multiple requests to the same host:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://httpbin.org/get &&
  curl -fsS https://httpbin.org/status/200 &&
  curl -fsS https://httpbin.org/status/201
' 2>summary.txt
```

**Expect:** summary shows aggregated count for httpbin.org (e.g., `count=3` or similar aggregation).

#### T12.4 Summary with MITM/HTTP details

With MITM enabled and HTTP rules:

```bash
keel -- bash -lc '
  apt-get update && apt-get install -y curl &&
  curl -fsS https://api.github.com/repos/moolen/keel &&
  curl -fsS -X POST https://httpbin.org/post -d "test" 2>&1 || true
' 2>summary.txt
```

**Expect:** summary includes HTTP-level entries showing method, path, and policy decision.

#### T12.5 No summary when no network activity

```bash
keel -- echo "no network" 2>summary.txt
```

**Expect:** no `Network summary:` section in stderr (or an empty/omitted summary).

---

## 4. Open Questions to Investigate

### 4.1 Non-interactive sync confirmation

**Question:** Does `sync_confirm: false` exist in the current implementation? If not, how can automated tests confirm sync prompts?

**Options to evaluate:**
- `sync_confirm` config flag (may already exist per the README schema)
- `--yes` CLI flag
- `KEEL_SYNC_AUTO=true` environment variable
- `echo y | keel ...` via stdin (may conflict with PTY mode)

**Action:** check the implementation, add the mechanism if missing, document it.

### 4.2 Transparent redirect availability

**Question:** the README mentions that transparent TCP redirect depends on guest kernel netfilter support and that keel prints a warning when it's unavailable. Some security tests (T6.3, T6.6) depend on this.

**Action:** verify whether the default kernel has transparent redirect support. If not, the security tests need to account for proxy-only mode behavior (where direct TAP egress is still blocked by host iptables, but non-proxy-aware tools in the guest won't work at all rather than being transparently captured).

### 4.3 Docker DNS/TLS allowlist completeness

**Question:** the Docker pull path involves multiple registries and CDNs that may change. The allowlist in T9 is a best guess.

**Action:** run Docker tests first in audit mode (`network.audit: true`) to discover all required domains from the shutdown summary, then update the allowlist.

### 4.4 MITM test CA trust

**Question:** does `ca.install_system: true` work reliably with the default `ubuntu:24.04` image, or does it need `update-ca-certificates` run explicitly?

**Action:** verify during T7 tests. If manual steps are needed, document them.

---

## 5. Test Execution Order

Recommended order to minimize repeated package installation and build on previous results:

```
1. T1  — Image management (get the base image ready)
2. T2  — VM lifecycle (verify basic execution works)
3. T3  — Filesystem operations (verify writes work)
4. T4  — DNS policy (verify network policy foundation)
5. T5  — TCP/TLS policy (build on DNS tests)
6. T6  — Security and evasion (stress test the boundary)
7. T7  — MITM and HTTP policy
8. T8  — Audit mode
9. T9  — Docker-in-VM (requires broad network access)
10. T10 — Workspace sync-back
11. T11 — Simulated agent workflow
12. T12 — Shutdown summary validation
```

Each category should be runnable independently (with its own `keel.yaml`), but the order above provides a natural progression from simple to complex.

---

## 6. Pass/Fail Criteria

A test passes when:
- the exit code matches expectations
- stdout/stderr contain expected output (or absence of output)
- host filesystem state matches expectations (for sync tests)
- network summary contains expected entries (for audit/summary tests)

A test fails when:
- unexpected exit code
- missing or incorrect output
- host files modified when they shouldn't be (or vice versa)
- network traffic reaches destinations it shouldn't
- policy decisions in the summary don't match configured policy

Any T6 (security) test failure is a **blocking issue** — the network boundary must be tight before production use.

