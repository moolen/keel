# keel

Firecracker-based VM sandbox for AI coding agents.

Keel boots agent workloads inside a Firecracker VM, syncs a workspace disk in and out, and applies host-enforced egress policy through DNS, TCP/TLS, and optional HTTP MITM inspection.

## MITM HTTP policy

Example:

```yaml
network:
  mitm:
    enabled: true
    ca:
      install_system: true
      install_docker: true
  dns:
    allowed:
      - api.github.com
  tls:
    allowed_sni:
      - api.github.com
  http:
    default: deny
    rules:
      - action: allow
        host: api.github.com
        methods: ["GET"]
        paths:
          - /repos/*
```

MITM support installs Keel's local CA into the guest system trust store and Docker daemon/client trust where supported. Arbitrary build-stage container trust varies by base image and is best-effort in the current release.
