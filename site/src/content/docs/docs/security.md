---
title: "Security"
description: "TLS, mutual TLS, and provider-upstream SSRF controls; how Busbar protects credentials and operator-controlled upstreams."
---

Busbar has two main security surfaces: the client-facing listener (TLS / mTLS) and the provider-facing outbound connections (SSRF / metadata-endpoint protection). Both are on by default with sensible defaults; both have escape hatches for unusual deployments.

Cross-references: [Configuration](/docs/configuration/) (full field reference) · [Reliability & Failover](/docs/reliability/) (breaker, failover, governance).

---

## Table of contents

- [TLS & mTLS](#tls--mtls)
  - [Native TLS termination](#native-tls-termination)
  - [Configuration](#configuration)
  - [Certificate and key formats](#certificate-and-key-formats)
  - [Enabling mTLS](#enabling-mtls)
  - [Where mTLS sits in the request path](#where-mtls-sits-in-the-request-path)
  - [Certificate rotation](#certificate-rotation)
  - [Reverse proxy as an alternative](#reverse-proxy-as-an-alternative)
  - [Startup behavior and failure modes](#startup-behavior-and-failure-modes)
- [Provider upstreams & SSRF](#provider-upstreams--ssrf)
  - [Local models just work](#local-models-just-work)
  - [What is blocked and why](#what-is-blocked-and-why)
  - [The control matrix](#the-control-matrix)
  - [Inspecting the effective denylist](#inspecting-the-effective-denylist)

---

## TLS & mTLS

Native TLS and optional mTLS ship in **1.0**.

Busbar terminates TLS for the client ↔ Busbar hop itself. Point cert and key at it in config and the listener serves HTTPS directly; no reverse proxy in front. Turn on mutual TLS (mTLS) by adding a client CA, and a connecting client must present a certificate signed by that CA before any HTTP request is read.

The honest framing:

> **TLS** = encrypted and server-verified out of the box. **mTLS** = only your cert-holding clients can connect at all; clients without a valid cert are rejected at the TLS handshake, before any HTTP or bearer-token check. Zero-trust without a service mesh.

---

## Native TLS termination

By default Busbar listens for plain HTTP; the listener you configure under `listen` binds and serves directly. Adding a `tls:` block turns that same listener into an HTTPS endpoint: Busbar performs the TLS handshake itself, decrypts the connection, and serves your routes over the encrypted channel.

This removes the "it's actually HTTP; bring your own proxy" caveat. You do not need Nginx, Caddy, or a cloud load balancer in front of Busbar to get encrypted client traffic. A reverse proxy still works if you already run one (see [below](#reverse-proxy-as-an-alternative)); it is now an option, not a requirement.

The `tls:` block is fully optional and zero-cost when absent: with no `tls:` configured, Busbar runs the exact plain-HTTP path it always has.

---

## Configuration

The `tls:` block lives next to `listen` in `config.yaml`:

```yaml
listen: "0.0.0.0:8443"
tls:
  cert_file: /etc/busbar/tls/fullchain.pem   # PEM cert chain (leaf first)
  key_file:  /etc/busbar/tls/privkey.pem     # PEM private key
  client_ca_file: /etc/busbar/tls/ca.pem     # OPTIONAL; present ⇒ enables mTLS
```

| Field | Type | Required | Notes |
|---|---|---|---|
| `cert_file` | string | **yes** (when `tls:` present) | Path to the PEM-encoded certificate chain, leaf certificate first. |
| `key_file` | string | **yes** (when `tls:` present) | Path to the PEM-encoded private key for the leaf certificate. |
| `client_ca_file` | string | no | Path to a PEM CA bundle. When set, **mTLS is enabled**: clients must present a certificate signed by this CA. When absent, no client certificate is requested. |

When `tls:` is present, set `listen` to a TLS port (8443 is conventional). The block is additive; absent means today's plain-HTTP path, byte for byte.

---

## Certificate and key formats

- **`cert_file`**: PEM-encoded certificate chain with the leaf (server) certificate first, followed by any intermediate certificates. A `fullchain.pem` from Let's Encrypt or your CA is exactly this format.
- **`key_file`**: PEM-encoded private key matching the leaf certificate. PKCS#8, PKCS#1, and SEC1 key encodings are accepted.
- **`client_ca_file`**: a PEM bundle of one or more CA certificates. A client certificate is accepted only if it chains to one of these CAs.

Busbar never logs key bytes. A cert, key, or CA file that is missing or fails to parse is a fatal startup error naming the offending file (see [Startup behavior](#startup-behavior-and-failure-modes)).

---

## Enabling mTLS

Mutual TLS is enabled by a single addition: set `client_ca_file` to a CA bundle.

```yaml
listen: "0.0.0.0:8443"
tls:
  cert_file: /etc/busbar/tls/fullchain.pem
  key_file:  /etc/busbar/tls/privkey.pem
  client_ca_file: /etc/busbar/tls/ca.pem    # enables mTLS
```

With `client_ca_file` set, every connecting client **must** present a certificate signed by that CA. A client with no certificate, or one signed by a different CA, is rejected during the TLS handshake; the connection never becomes an HTTP request. Issue client certificates from your own CA, distribute them to the services allowed to reach Busbar, and only those services can open a connection at all.

This is a network-level admission control that sits *underneath* Busbar's existing bearer-token / virtual-key auth. mTLS decides **who can connect**; tokens and governance keys decide **what a connection is allowed to do**. The two compose; you can require both a valid client certificate and a valid Busbar token.

---

## Where mTLS sits in the request path

The order of checks on an mTLS-enabled listener:

1. **TLS handshake.** The client presents its certificate. If it is missing or not signed by `client_ca_file`'s CA, the handshake fails and the connection is dropped. No HTTP request is parsed; no header, path, or token is ever read.
2. **HTTP request parsed.** Only a client that cleared step 1 reaches this point.
3. **Bearer-token / virtual-key auth.** The usual `auth` (or [governance](/docs/guides/governance/)) check runs on the now-decrypted request.

The practical consequence: a client without a valid certificate cannot probe your routes, cannot trigger token comparisons, and cannot reach any application code. It is rejected at the lowest layer. This is what "zero-trust without a service mesh" means in practice; you get cert-based mutual authentication between your services and Busbar without deploying or operating a mesh.

A handshake failure on one connection is logged at debug level and drops that connection only; it never crashes the server, and the next valid client is served normally.

---

## Certificate rotation

**Rotation is a restart.** Certificates, the key, and the client CA bundle are loaded once at startup. To rotate any of them, write the new PEM files to their configured paths and restart Busbar. There is no live reload of TLS material.

In practice this is a routine operation: write the renewed `fullchain.pem` / `privkey.pem` (or updated `ca.pem`), then restart the process. A graceful restart on a single-binary deployment is fast, and Busbar resumes serving on the same `listen` address.

---

## Reverse proxy as an alternative

If you already operate a TLS-terminating reverse proxy (Nginx, Caddy, an ingress controller, a cloud load balancer), you can keep using it: leave the `tls:` block out, let Busbar serve plain HTTP on a private network, and terminate TLS at the proxy. Native termination does not replace this pattern; it removes the *requirement* for it.

Choose native termination when you want one binary with no extra moving parts, or when you need mTLS that Busbar itself enforces. Choose a reverse proxy when it is already part of your edge and you prefer to centralize certificate management there.

---

## Startup behavior and failure modes

- **`tls:` absent**: plain HTTP, exactly as before. No TLS code path is exercised.
- **`tls:` present, files valid**: the listener serves HTTPS; with `client_ca_file` set, it requires client certificates.
- **Cert / key / CA file missing or unparseable**: fatal startup error. Busbar refuses to boot and names the offending file. It never starts in a degraded "TLS misconfigured" state.
- **Per-connection handshake failure** (bad or missing client cert under mTLS, protocol mismatch); logged at debug, that connection is dropped, the server stays up and continues serving valid clients.

Busbar never logs private-key bytes at any level.

---

## Provider upstreams & SSRF

Busbar makes outbound HTTP requests to provider `base_url` endpoints on behalf of callers. Because callers only pick a **model name** (which resolves to an operator-configured URL), they cannot steer Busbar toward an arbitrary destination; there is no classic client-driven SSRF here. The real risk is different: a misconfigured or malicious `base_url` that points at a cloud-provider metadata service (IMDS / WireServer / GCE metadata) and exfiltrates the host machine's credentials. Busbar's SSRF guard addresses exactly that.

### Local models just work

By default, a provider `base_url` may point at **loopback or any private address**: `127.0.0.1`, `::1`, RFC 1918 (`10/8`, `172.16/12`, `192.168/16`), CGNAT (`100.64/10`, which includes Tailscale addresses), and link-local; with no configuration flag required. HTTP is allowed for these private/loopback hosts because there is no off-box wiretap risk; an API key in cleartext on a loopback socket never leaves the machine. HTTPS is required for all public (non-private) hosts.

In practice this means Ollama (`http://127.0.0.1:11434`), vLLM, LM Studio, and any sidecar reachable over Tailscale all work out of the box:

```yaml
providers:
  local-ollama:
    protocol: openai
    base_url: http://127.0.0.1:11434   # loopback; http:// allowed, no flag needed
    api_key_env: UNUSED_KEY

models:
  llama3:
    provider: local-ollama
    max_concurrent: 4
```

### What is blocked and why

The hardcoded denylist targets **cloud-instance metadata endpoints**: the addresses that cloud providers expose on well-known IPs to hand credentials and configuration to running VMs. A `base_url` resolving to any of these is rejected at startup (not at request time):

| Entry | What it covers |
|---|---|
| `169.254.0.0/16` | Entire link-local range: AWS IMDS (`169.254.169.254`), AWS ECS credentials (`169.254.170.2`), Tencent Cloud metadata (`169.254.0.23`), and any future link-local IMDS |
| `100.100.100.200` | Alibaba Cloud metadata |
| `168.63.129.16` | Azure WireServer |
| `192.0.0.192` | Oracle Cloud (OCI) metadata |
| `fd00:ec2::254` | AWS IMDSv6 |
| `metadata.google.internal` | GCE metadata hostname |
| `metadata.internal` | Generic cloud metadata hostname |
| `metadata.tencentyun.com` | Tencent Cloud metadata hostname |
| `metadata.platformequinix.com` | Equinix Metal metadata hostname |
| `instance-data`, `instance-data.ec2.internal` | EC2 instance data hostnames |

The guard also defends against obfuscated forms of every denylisted IP: IPv4-mapped IPv6, decimal-integer encoding, percent-encoding, and trailing-dot variants are all detected and blocked.

**The hardcoded list is compiled into the binary**: it cannot be accidentally deleted by editing `config.yaml`. Config can only extend or carve exceptions from it (see below).

### The control matrix

Four knobs cover every scenario:

| Need | Config field | Scope |
|---|---|---|
| Block an extra host not in the built-in list | `security.blocked_metadata_hosts: [host, ...]` | Global; adds to the denylist for all providers |
| Unblock one host for every provider | `security.allow_metadata_hosts: [host, ...]` | Global; removes from the effective denylist everywhere |
| Unblock one host for a single provider only | Per-provider `allow_metadata_hosts: [host, ...]` | Scoped; removes from the effective denylist for that provider only |
| Disable the guard entirely | `security.allow_all_metadata: true` | Global; every metadata endpoint becomes reachable; **logs a startup WARNING** |

**Precedence (one sentence):** a host is blocked if and only if it is on the denylist (hardcoded union `blocked_metadata_hosts`) and is not in any allow-override (`security.allow_metadata_hosts` union that provider's `allow_metadata_hosts`) and `allow_all_metadata` is not set. Allow always wins over block.

**Entries must be exact IPs or hostnames.** CIDR notation (e.g. `169.254.0.0/16`) is **not** supported in `blocked_metadata_hosts` or `allow_metadata_hosts` and is rejected at startup with a clear error; list specific addresses instead. (The built-in `169.254.0.0/16` link-local range is enforced internally; config cannot add new CIDR ranges.)

**Example; extend the denylist and carve a surgical per-provider exception:**

```yaml
security:
  # Block an additional internal metadata service not in the built-in list.
  blocked_metadata_hosts:
    - "169.254.100.1"          # custom internal metadata IP

  # Unblock GCE metadata globally (every provider may reach it).
  # Use this only if you are proxying GCE metadata intentionally.
  # allow_metadata_hosts:
  #   - "metadata.google.internal"

providers:
  local-ollama:
    protocol: openai
    base_url: http://127.0.0.1:11434   # loopback; no entry needed
    api_key_env: UNUSED_KEY

  gce-metadata-proxy:
    protocol: openai
    base_url: http://metadata.google.internal/computeMetadata/v1/...
    api_key_env: UNUSED_KEY
    # Per-provider surgical exception: only THIS provider may reach GCE metadata.
    # Every other provider (and every other metadata endpoint) stays blocked.
    allow_metadata_hosts:
      - "metadata.google.internal"

models:
  llama3:
    provider: local-ollama
    max_concurrent: 4
```

`security.allow_all_metadata: true` is a nuclear option intended for development environments only. When set, Busbar logs a startup warning: `metadata protection DISABLED; all cloud-metadata endpoints reachable`.

### Inspecting the effective denylist

Two ways to see exactly what Busbar is blocking:

1. **CLI flag:** `busbar --print-metadata-blocklist` dumps the denylist; the hardcoded entries plus any `blocked_metadata_hosts` additions (allow-overrides and `allow_all_metadata` are not subtracted from this list). This is the ground truth for what the compiled binary and config consider metadata hosts.

2. **Startup log:** at `info` level Busbar logs `metadata protection: N hosts blocked (--print-metadata-blocklist to view)`. When `allow_all_metadata` is set the log line is instead a `WARN`: `metadata protection DISABLED; all cloud-metadata endpoints reachable`.
