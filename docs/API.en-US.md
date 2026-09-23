# Go-nftables-portbridge API Reference — v2.5.0

**Applies to: v2.5.0**

**Language:** **English** | [简体中文](API.zh-CN.md)  

> [!IMPORTANT]
> Every management API requires an administrator Bearer token. Write operations also require `X-PortBridge-CSRF`. Normal installations should use HTTPS. Do not treat an HTTP success status by itself as proof that the data plane is active or that an old forwarding path has been fully retired.

This document describes the Web management HTTP API. It does not describe internal Go package APIs or the TCP/UDP protocol carried by forwarded application traffic. Field names, enum values, and error semantics follow the v2.5.0 implementation.

Examples contain documentation placeholders, not live credentials or deployment details.

## Table of Contents

- [1. API Scope and Quick Reference](#1-api-scope-and-quick-reference)
- [2. Addressing, TLS, Authentication, and CSRF](#2-addressing-tls-authentication-and-csrf)
- [3. Common HTTP and JSON Conventions](#3-common-http-and-json-conventions)
- [4. Obtain CSRF: GET /api/bootstrap](#4-obtain-csrf-get-apibootstrap)
- [5. Read Configuration: GET /api/config](#5-read-configuration-get-apiconfig)
- [6. Read Runtime Status: GET /api/status](#6-read-runtime-status-get-apistatus)
- [7. Save Management Settings: PUT /api/settings](#7-save-management-settings-put-apisettings)
- [8. Rotate Token: POST /api/token/rotate](#8-rotate-token-post-apitokenrotate)
- [9. Create, Replace, and Delete Rules](#9-create-replace-and-delete-rules)
- [10. Complete Rule Schema and Validation](#10-complete-rule-schema-and-validation)
- [11. Runtime, Stats, and Kernel State](#11-runtime-stats-and-kernel-state)
- [12. Error Responses and Handling](#12-error-responses-and-handling)
- [13. Complete curl Integration Flow](#13-complete-curl-integration-flow)
- [14. Python Standard-Library Client Example](#14-python-standard-library-client-example)
- [15. Concurrency, Retries, and Operational Boundaries](#15-concurrency-retries-and-operational-boundaries)
- [16. Capabilities Not Exposed by the Current API](#16-capabilities-not-exposed-by-the-current-api)
- [17. Prometheus metrics](#17-prometheus-metrics)
- [Implementation References and Source Links](#implementation-references-and-source-links)

---

## 1. API Scope and Quick Reference

The current release explicitly registers **8 JSON management API routes** under `/api/`, plus the protected Prometheus `GET /metrics` endpoint, with no `/api/v1/` version prefix. The management API and WebGUI share the same listeners, port, TLS configuration, and IP ACL.[^routes]

| Method | Path | Purpose | Success | CSRF | Request JSON |
|---|---|---|---:|---|---|
| `GET` | `/api/bootstrap` | Obtain the process-level CSRF value and project name | `200` | No | None |
| `GET` | `/api/config` | Obtain the administrator-visible configuration projection | `200` | No | None |
| `GET` | `/api/status` | Obtain runtime state, counters, and effective management ACLs | `200` | No | None |
| `PUT` | `/api/settings` | Save management-plane settings | `200` | Required | `settingsRequest` |
| `POST` | `/api/token/rotate` | Generate and immediately activate a new administrator token | `200` | Required | None |
| `POST` | `/api/rules` | Create a rule | `201` | Required | `Rule` |
| `PUT` | `/api/rules/{id}` | Fully replace an existing rule | `200` | Required | `Rule` |
| `DELETE` | `/api/rules/{id}` | Remove a rule from persistent configuration and request retirement | `204` | Required | None |

**All of the APIs above require the administrator Bearer token.** `/api/bootstrap` is not an anonymous login endpoint. There are currently no user accounts, roles, read-only tokens, or per-rule authorization scopes. A valid administrator token authorizes these management operations.[^auth]

To read the rule list, use `rules` from `/api/config`, or `rules[].rule` from `/api/status`. There is currently **no** `GET /api/rules` or `GET /api/rules/{id}`. Unregistered read paths return `404`; do not infer a read endpoint merely because a POST route exists.[^routes]

### 1.1 Four concepts that must remain distinct

| Concept | Location | Meaning |
|---|---|---|
| Management access authorization | `web.whitelist`, `/api/status.acl` | Who may access the WebGUI/API; this is not a source ACL for forwarded service ports |
| Desired rule configuration | `/api/config.rules[]` | Persisted rules; `enabled` is the administrator's desired state |
| Runtime state | `/api/status.rules[]` | Runtime/risk state observed by the manager; may include cleanup records that exist only at runtime |
| Actual application reachability | External TCP/UDP payload checks | The API does not expose automatic end-to-end probes; HTTP success does not replace workload validation |

Rule writes persist configuration first and then invoke data-plane application logic. Failures from that logic are recorded in runtime status, but rule create/update handlers do not convert those data-plane failures into create/update HTTP failure codes. Therefore `201`, `200`, and `204` **do not by themselves prove that the data plane is active as intended or that old flows have been fully retired**.[^rule-handlers][^manager]

## 2. Addressing, TLS, Authentication, and CSRF

### 2.1 Base URL and default deployment

Typical local management origins are:

```text
https://127.0.0.1:9080
https://[::1]:9080
```

The actual addresses are controlled by `web.listen_ipv4`, `web.listen_ipv6`, and `web.port`. The source default management port is `9080`, listening on `127.0.0.1` and `::1`. Adding management allowlist entries does not automatically move the listener to a public address.[^config-defaults]

**Distinguish source defaults from the installed service:** an unprepared development configuration may retain loopback HTTP before HTTPS setup. The packaged installation flow prepares certificates, sets `web.require_https=true`, and the supplied systemd unit also passes `--require-https`. A normal installed service should therefore use native HTTPS, and the settings API cannot disable that deployment-enforced policy.[^deployment]

The server's default minimum TLS version is `1.2`; setting `tls_min_version:"1.3"` raises the minimum to TLS 1.3 after restart. HTTPS responses include `Strict-Transport-Security: max-age=31536000`.[^tls][^headers]

For self-signed certificates, verify the certificate fingerprint through a trusted channel first, then establish client trust. Examples in this document use `--cacert` or a Python trusted-CA file instead of bypassing certificate verification. The certificate SAN/name must also cover the address used by the client. `self_signed:false` alone does not prove that client-side trust validation succeeded.[^tls][^deployment]

### 2.2 Management IP ACL: evaluated before the token

The ACL evaluates the direct TCP peer address. It does not use `X-Forwarded-For`, `X-Real-IP`, or `Forwarded` as the client identity. New connections can be closed before TLS handshake/HTTP parsing, while later requests on an already-established connection are checked again by the HTTP ACL. An unauthorized client may therefore observe a connection close rather than a JSON error. An HTTP-layer ACL rejection is plain-text `403 Forbidden`.[^acl][^listener]

In non-strict mode, the effective allow set is the union of loopback addresses, optional auto-detected LAN prefixes, the persistent allowlist, and bootstrap ACL entries supplied at startup. Strict mode preserves the local loopback recovery path, accepts only the persistent allowlist beyond that, disables automatic LAN entries, and ignores the bootstrap ACL.[^acl]

`auto_lan_acl=true` discovers directly connected private/link-local prefixes on local interfaces that are up; it does not unconditionally permit every private address. The management allowlist supports at most **1024 normalized, de-duplicated entries**. Strict mode rejects `/0`; normal mode rejects `/0` by default as well, and the local risk override is not exposed through the API.[^acl][^config-validation]

### 2.3 Administrator token

Every request uses one Authorization header:

```http
Authorization: Bearer <64-character-admin-token>
```

Tokens generated by the program use 32 random bytes encoded as 64 hexadecimal characters. The server persists and compares the SHA-256 hash of the token string; do not send the `admin_token_sha256` hash value as the token.[^token-storage]

| Item | Current behavior |
|---|---|
| Authentication source | Extracted only from the `Authorization` request header |
| Scheme | `Bearer`; scheme comparison is case-insensitive |
| Token value | The extracted token must be exactly 64 bytes and match the stored hash; case matters. The header parser splits surrounding/separating whitespace with `strings.Fields`; token-internal whitespace is invalid |
| Duplicate Authorization | Rejected; do not send multiple Authorization headers |
| Cookie / URL query / Basic | Not supported as authentication mechanisms |
| Default local token path | `/etc/portbridge/admin.token`; may be changed with `--token-file` |
| Anonymous login/registration | Not provided |
| Server-side logout | Not provided; GUI logout only clears browser-side token state |
| Revoke current token | Rotate the administrator token; the old token then stops authenticating |

Reading the initial token requires authorized local access to the token file. The API does not expose an endpoint that returns the current plaintext token. A successful rotation response returns the new token and updates the configured local token file.[^auth][^token-storage][^cli][^gui]

### 2.4 Obtaining and retaining CSRF

First call:

```http
GET /api/bootstrap
Authorization: Bearer <admin-token>
```

Then place the returned `csrf` value on every write request:

```http
X-PortBridge-CSRF: <csrf-from-bootstrap>
```

The CSRF value is generated in `Server.New` from 24 random bytes and encoded as **48 hexadecimal characters**. It belongs to the server object/process, not to an individual browser session. A normal process restart generates a new value; rotating the administrator token does not regenerate it.[^auth][^web-constructor]

CLI tools, scripts, and backend programs must also send CSRF on writes. It is required even for `DELETE /api/rules/{id}` and the bodyless `/api/token/rotate` endpoint.

### 2.5 Browser same-origin validation

Write requests pass through these checks in order:

```text
management ACL → Bearer authentication → browser same-origin check → CSRF → request parsing/business logic
```

The current same-origin rules are:[^auth]

| Request header | Accepted condition |
|---|---|
| `Sec-Fetch-Site` | Missing, empty, `same-origin`, or `none` |
| `Sec-Fetch-Site: same-site` | Rejected; same-site is not the same as same-origin |
| `Sec-Fetch-Site: cross-site` | Rejected |
| `Origin` | May be omitted; when present and non-empty, scheme must match the server's actual TLS/HTTP scheme and host:port must match the request `Host` (host comparison is case-insensitive) |
| Other Origin components | Must not contain userinfo, a path (including a trailing `/`), a query, or a fragment; `Origin: null` is rejected |
| Duplicate Origin / Sec-Fetch-Site | Rejected |

For example, if the request URL is `https://pb.example:9080/api/rules`, the valid Origin is `https://pb.example:9080`, not `https://pb.example:9080/`.

A normal command-line client does not need to fabricate browser headers; omit `Origin` and `Sec-Fetch-Site`, while still sending both Token and CSRF. No cross-origin CORS authorization/preflight handler exists in the current routes; do not assume a cross-site web page can call the management API.[^routes][^auth]

### 2.6 Failed-authentication rate limiting

Failed authentication uses token buckets rather than a fixed time window.[^auth-limiter]

| Dimension | Burst capacity | Refill rate |
|---|---:|---:|
| Per direct source IP | 10 failures | 1 token every 6 seconds |
| Global | 100 failures | 5 tokens per second |

Failed requests normally return `401`; requests exceeding the failure budget return `429`. A valid token is verified before the failure-rate check and therefore **cannot be locked out by these failed requests**. Successful authentication clears that source IP's failure bucket but does not reset the global bucket. This is failed-authentication protection, not a general API QPS quota and not forwarding-traffic rate limiting.

Current `401` responses include `WWW-Authenticate: Bearer realm="PortBridge"`; the `429` handler does not set `Retry-After`. Clients should reduce retries with bad credentials and must not rely on a retry-time header that does not exist.[^auth]

## 3. Common HTTP and JSON Conventions

### 3.1 Request encoding

`PUT /api/settings`, `POST /api/rules`, and `PUT /api/rules/{id}` require:

```http
Content-Type: application/json
```

A parameterized media type such as `application/json; charset=utf-8` is accepted by MIME parsing. The request body limit is **1,048,576 bytes (1 MiB)**. The decoder rejects unknown fields, type mismatches, malformed JSON, and any second JSON value after the first. Clients should always send one object rather than an array or `null`.[^json]

These parsing errors currently return **400**, including unsupported Content-Type and oversized bodies; do not hard-code the more conventional `415` or `413`. `null` has no dedicated non-object check and falls through into Go zero values and later business validation; it is not a supported way to “clear the object.”[^json][^config-validation]

Bodyless token rotation and delete handlers do not call this JSON decoder, do not require Content-Type, and define no request-body parameters.[^rule-handlers]

`DisallowUnknownFields` is not full JSON schema validation: duplicate keys are not explicitly rejected, and field matching can be case-insensitive. Send each documented lowercase field exactly once; do not rely on duplicate-key overwrite order.

### 3.2 Response encoding

JSON responses use:

```http
Content-Type: application/json; charset=utf-8
Cache-Control: no-store
```

There is no common `data` envelope. Create/update return a Rule directly; delete returns an empty body; settings returns `{ "ok": true, "restart_required": ... }`; other response bodies are documented per endpoint. Field ordering is not part of the protocol.[^json]

Unknown paths, method mismatches, HTTP ACL rejection, and transport failures are not guaranteed to be JSON. Clients should inspect the status and Content-Type before attempting JSON decoding, and must not JSON-decode a `204` response.[^routes][^headers]

### 3.3 Fields, timestamps, and collections

| Type/situation | Convention |
|---|---|
| Ports, limits, seconds | JSON integers, not strings; `"9080"` cannot replace `9080` |
| Booleans | JSON `true` / `false`, not strings |
| Time | `time.Time` JSON strings in RFC3339-style format, potentially with fractional seconds and timezone offsets |
| Uninitialized time | `started_at`, `not_after`, `sampled_at` and `nft_hooks_sampled_at` may appear as `0001-01-01T00:00:00Z`; under the current toolchain, `omitempty` does not omit zero-value `time.Time` here |
| Empty collections | Rules, allowlists, DNS lists from `/api/config`, and ACL lists from `/api/status` generally return `[]` |
| Optional Rule fields | `omitempty` fields may be absent when zero/empty; see Section 10 |
| Accumulated counters | JSON numbers backed by Go `uint64`; very large values can exceed exact integer precision in JavaScript Number |
| Error codes | There are no machine-readable business error codes, field-error arrays, or request IDs |

Request senders should use the documented field set; response consumers should tolerate additional future fields. When an optional response field is absent, apply that field's documented zero/default semantics rather than interpreting every missing numeric value as “unlimited.”[^json][^stats][^tls][^config-clone]

### 3.4 Request timeouts and connection limits

The native Web Server uses: Header read timeout `5s`, read timeout `15s`, write timeout `30s`, idle timeout `60s`, `MaxHeaderBytes=32 KiB`, and `MaxHeaderValueCount=128`. Each management listener is wrapped with a maximum of **256** connections. Timeout/limit failures are not guaranteed to produce APIError JSON.[^web-start][^listener]

There is no paging, cursor, sorting, or filtering query contract; these handlers do not read URL query parameters. Do not expect appended `page`, `limit`, or `enabled` parameters to change the result.[^read-handlers][^rule-handlers]

## 4. Obtain CSRF: `GET /api/bootstrap`

**Authentication:** Bearer Token. **CSRF:** not required. **Request body/query parameters:** none.[^read-handlers]

Example request:

```http
GET /api/bootstrap HTTP/1.1
Host: pb.example:9080
Authorization: Bearer <admin-token>
```

Successful `200 OK` response:

```json
{
  "csrf": "0123456789abcdef0123456789abcdef0123456789abcdef",
  "name": "Go-nftables-portbridge"
}
```

| Field | Type | Description |
|---|---|---|
| `csrf` | string | CSRF value for this process; the value shown is a placeholder and the actual response must be used |
| `name` | string | Fixed project name `Go-nftables-portbridge` |

This endpoint does not create an account, issue a Bearer token, return the application version, or set an authentication cookie. Typical failures are `401`, `429`, or access-layer rejection. If writes start failing CSRF validation after a restart, call this endpoint again to obtain the current value.

## 5. Read Configuration: `GET /api/config`

**Authentication:** Bearer Token. **CSRF:** not required. Success is `200 OK`.[^read-handlers]

Example response for an empty-rule deployment prepared for native HTTPS (certificate fingerprint and validity are illustrative):

```json
{
  "web": {
    "port": 9080,
    "listen_ipv4": "127.0.0.1",
    "listen_ipv6": "::1",
    "auto_lan_acl": false,
    "strict_ip_allowlist": false,
    "allow_insecure_http": false,
    "whitelist": [],
    "tls_cert_file": "/etc/portbridge-tls/fullchain.pem",
    "tls_key_file": "/etc/portbridge-tls/privkey.pem",
    "tls_min_version": "1.2",
    "dns_servers": []
  },
  "rules": [],
  "https": {
    "required": true,
    "certificate": {
      "enabled": true,
      "self_signed": true,
      "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "not_after": "2036-01-01T00:00:00Z"
    }
  }
}
```

| Top-level field | Type | Description |
|---|---|---|
| `web` | object | The 11 management-setting fields listed in Section 7, using the persisted configuration values |
| `rules` | Rule[] | Persistent rule list in configuration order; does not include runtime-only cleanup records |
| `https` | object | Enforced HTTPS policy and currently loaded certificate information |

`https` structure:

| Field | Type | Description |
|---|---|---|
| `required` | boolean | Configured `web.require_https`, exposed read-only; it is not a settingsRequest field |
| `certificate.enabled` | boolean | Whether native TLS certificate use was enabled at startup |
| `certificate.self_signed` | boolean | Whether the loaded leaf certificate matches the source's self-signed test; this is not a trust-validation conclusion |
| `certificate.sha256` | string, optional | SHA-256 of the loaded leaf certificate's raw DER, 64 lowercase hexadecimal characters without colons |
| `certificate.not_after` | string | Expiration time of the loaded certificate; may be the zero-value time when TLS is not active |

**Persisted configuration and the running instance represent two different points in time.** If TLS paths are changed but the service has not restarted, `web.tls_cert_file`/`tls_key_file` may show the new paths while `https.certificate` still describes the old loaded certificate. Replacing certificate contents at the same path also does not hot-reload them.[^tls][^settings]

This response is not raw `config.json`: it omits `version`, `resource_limits`, `nftables`, `admin_token_sha256`, and `allow_unsafe_all_address_acl`, and never returns certificate/private-key file contents. Do not treat the entire response as a full configuration backup or submit it verbatim to `/api/settings`; only `.web` matches the current settings request model.[^read-handlers][^config-model]

## 6. Read Runtime Status: `GET /api/status`

**Authentication:** Bearer Token. **CSRF:** not required. Success is `200 OK`.[^read-handlers]

Empty-rule example:

```json
{
  "uptime_seconds": 120,
  "rules": [],
  "acl": {
    "auto": ["127.0.0.0/8", "::1/128"],
    "whitelist": [],
    "bootstrap": [],
    "strict": false
  }
}
```

| Field | Type | Description |
|---|---|---|
| `uptime_seconds` | integer/int64 | Whole seconds since the Web Server object was created; not operating-system uptime |
| `rules` | RuleRuntime[] | Runtime rules; see Section 11; sorted by rule name and then ID |
| `acl.auto` | string[] | Current effective automatically allowed prefixes; always includes loopback, even when automatic LAN discovery is disabled |
| `acl.whitelist` | string[] | Current effective persistent management allowlist |
| `acl.bootstrap` | string[] | Current effective temporary startup allowlist; empty in strict mode |
| `acl.strict` | boolean | Whether the ACL manager is currently operating in strict mode |

`rules` can contain records removed from `/api/config.rules` whose retirement has not finished, as well as runtime-only cleanup entries such as `kernel-pending-...` and `kernel-recovery-unverified...`. These are not newly generated editable configuration rules. To determine whether an ID can be updated or deleted, first locate it in `/api/config.rules`.[^manager-runtime][^kernel-state]

A `200` from the status endpoint only means that the read succeeded. Rule startup failures or unverified kernel state do not turn it into a `503`. Monitoring must inspect `stats.last_error`, `stats.running`, `go_running`, and `kernel_state` rather than checking only the HTTP status. Counter semantics and health limitations are described in Section 11.[^manager]

## 7. Save Management Settings: `PUT /api/settings`

**Authentication:** Bearer Token + CSRF; browser writes must also pass same-origin validation. **Request format:** one JSON object whose fields are directly at the top level, not wrapped in `web`.[^settings]

### 7.1 Request fields

| Field | JSON type | Values/constraints | Activation |
|---|---|---|---|
| `port` | integer | `1–65535`; omission becomes 0 and fails validation | Restart |
| `listen_ipv4` | string | IPv4 management listener address; empty disables this address | Restart |
| `listen_ipv6` | string | IPv6 management listener address; empty disables this address | Restart |
| `auto_lan_acl` | boolean | Automatically allow directly connected private/link-local networks; must be false in strict mode | ACL refreshed immediately |
| `strict_ip_allowlist` | boolean | Strict management allowlist; current request must already use native HTTPS | ACL refreshed immediately |
| `allow_insecure_http` | boolean | Explicit acknowledgement for non-loopback plaintext HTTP; cannot be true when `require_https=true` | A change contributes to restart calculation |
| `whitelist` | string[] | IPs or CIDRs; normalized, de-duplicated, sorted; maximum 1024 | ACL refreshed immediately |
| `tls_cert_file` | string | Absolute server-local certificate-file path; configured together with private key | Restart |
| `tls_key_file` | string | Absolute server-local private-key path; configured together with certificate | Restart |
| `tls_min_version` | string | `"1.2"` / `"1.3"`; omitted or empty preserves current policy | Restart when the effective policy changes |
| `dns_servers` | string[] | Up to 8 de-duplicated DNS servers; empty uses the system resolver | Resolver updated and desired rules reapplied |

**This is replacement-style persistence, not PATCH.** Only an omitted/empty `tls_min_version` preserves the existing policy; other omitted booleans become false, strings become empty, and lists normalize to empty lists. Sending only the field you want to change can clear certificate paths/allowlists, disable security modes, or fail validation. Correct usage is to read `/api/config`, extract `.web`, modify the required field, and PUT the complete object.[^settings]

### 7.2 Request and response example

```json
{
  "port": 9080,
  "listen_ipv4": "127.0.0.1",
  "listen_ipv6": "::1",
  "auto_lan_acl": false,
  "strict_ip_allowlist": false,
  "allow_insecure_http": false,
  "whitelist": ["192.0.2.10/32"],
  "tls_cert_file": "/etc/portbridge-tls/fullchain.pem",
  "tls_key_file": "/etc/portbridge-tls/privkey.pem",
  "tls_min_version": "1.3",
  "dns_servers": ["1.1.1.1:53", "[2606:4700:4700::1111]:53"]
}
```

Certificate files must already exist **on the server** and be readable by the service process; this endpoint does not upload certificates. The allowlist address above is only illustrative.

Successful `200 OK`:

```json
{
  "ok": true,
  "restart_required": true
}
```

`restart_required` compares persisted settings with the listener configuration captured **when the listener started**, not with the previously saved configuration. Re-saving the same unapplied change can therefore continue returning true; restoring values to the currently running listener configuration can return false. Changes to strict ACL, automatic LAN, and the allowlist themselves do not require restart.[^settings]

If certificate contents change at the same path, this comparison does not inspect file contents and cannot be relied on to detect that replacement. There is also no dedicated “pending restart” query or service restart endpoint.[^settings][^routes]

### 7.3 Additional checks for strict allowlisting

When enabling/saving `strict_ip_allowlist=true`:

1. The current request must already be using server-native HTTPS; `X-Forwarded-Proto: https` does not count.
2. At least one persistent allowlist entry is required, `/0` is prohibited, and `auto_lan_acl=false` is required.
3. TLS certificate and private-key paths must be configured.
4. The direct client IP of the current request must be inside the submitted new allowlist; loopback has a recovery-path exception, but the non-empty allowlist requirement still applies.

These are the actual current handler/configuration-model rules. They do not imply any identity recovery of end clients behind a reverse proxy.[^settings][^config-validation]

### 7.4 Allowlist and DNS formats

The management `whitelist` accepts an individual IP and converts it to `/32` or `/128`; CIDRs are normalized to network prefixes, blank entries are removed, and entries are de-duplicated and sorted. IPv4-mapped IPv6 **CIDRs** are rejected; use normal IPv4 CIDRs instead.[^normalize-lists]

DNS entries may be IP or IP:port. For example, IPv4 `1.1.1.1` becomes `1.1.1.1:53`, and IPv6 `2606:4700:4700::1111` becomes `[2606:4700:4700::1111]:53`. An IPv6 server with a custom port must be written `[IPv6]:port`. Ports are `1–65535`; the server address must be an IP literal, not a hostname, DoH URL, or DoT URL. Normalization preserves first-seen order while de-duplicating, with a maximum of 8 entries.[^normalize-lists]

### 7.5 TLS file validation and implementation boundaries

When a non-empty certificate/private-key pair is saved, local TLS checks cover regular-file status, certificate/key matching, and current certificate validity. On Unix, private-key permissions may grant owner read/write and optional group read, but may not grant access to other users or execution bits; owner identity is also checked. A self-signed certificate can pass these local material checks, but clients still need to establish trust.[^tls]

Current Web listener validation performs basic checks such as requiring IP literals, but **does not strictly guarantee that `listen_ipv4` contains an IPv4 address and `listen_ipv6` contains an IPv6 address**. Use the fields for their intended families; swapping families may persist and only fail when the service restarts and attempts to bind. Do not submit both listener addresses as empty: the API does not explicitly reject that combination, while configuration reload can repopulate both with loopback defaults.[^config-validation][^config-defaults]

Persistence failures normally return `400`. If ACL refresh fails, the handler attempts to roll back configuration and ACL state and returns `500`. DNS/rule application happens after configuration persistence and ACL refresh; data-plane failures must be read from `/api/status` and are not guaranteed away by `{ "ok": true }`.[^settings]

## 8. Rotate Token: `POST /api/token/rotate`

**Authentication:** current valid Bearer Token + CSRF. **Request body:** none.[^rule-handlers][^token-storage]

```http
POST /api/token/rotate HTTP/1.1
Host: pb.example:9080
Authorization: Bearer <current-admin-token>
X-PortBridge-CSRF: <current-csrf>
```

Successful `200 OK`:

```json
{
  "token": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
}
```

The actual token is newly generated random data; the example value must not be used. The response contains a secret and should not be written to normal access logs, CI output, or tickets. The response is returned after the server updates both the configured token hash and token file. Subsequent authentication immediately uses the new value; there is no dual-validity period for old and new tokens. Requests that already completed authentication with the old token are not retroactively cancelled.[^auth][^token-storage]

The CSRF value does not change during token rotation. A client may still re-bootstrap using the new token to keep initialization logic consistent. Other clients holding the old token will normally receive `401` on later requests; errors do not reveal the replacement token.[^auth]

Failures during generation, reading the old token file, writing files, or persistence return `500`. The source implements a two-file transaction with rollback handling, but rollback itself can also fail and may include local recovery instructions in the error text; do not interpret such an error as proof that no state changed.[^token-storage]

**Do not automatically retry token rotation.** If the response is lost, the server may already have rotated the token. First verify state using known credentials and, when required, recover through the authorized local token file/recovery path rather than issuing repeated rotations. This is a client-integration recommendation based on the side effects of the current endpoint.

## 9. Create, Replace, and Delete Rules

### 9.1 Create a rule: `POST /api/rules`

**Authentication:** Bearer Token + CSRF. **Request body:** Rule object, documented in Section 10.[^rule-handlers]

Minimal practical example, explicitly disabled so it can be reviewed before activation:

```json
{
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

This example is for a locally owned service only; the operator must provide the target service at `127.0.0.1:8080`. With `enabled:false`, no new desired forwarding path is started. A loopback target is also a restricted target and therefore requires both `allow_private_target:true` and a matching target CIDR.

Successful `201 Created` returns the **fully normalized Rule** directly, without an outer `rule` or `data` wrapper:

```json
{
  "id": "0123456789abcdef",
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "connect_timeout_seconds": 10,
  "tcp_idle_timeout_seconds": 300,
  "max_tcp_connections": 2048,
  "max_tcp_connections_per_source": 256,
  "udp_idle_timeout_seconds": 60,
  "max_udp_sessions": 4096,
  "max_udp_sessions_per_source": 512,
  "udp_new_sessions_per_second_per_source": 1000,
  "udp_packets_per_second_per_source": 100000,
  "udp_batch_size": 64,
  "udp_packet_buffer_size": 2048,
  "udp_listener_buffer_bytes": 4194304,
  "udp_session_buffer_bytes": 65536,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

The server generates an 8-byte random ID encoded as 16 hexadecimal characters. Any `id` supplied in the create body is overwritten by the handler; persist the returned server-generated ID. The current implementation does not set a `Location` response header and has no idempotency key. Repeating the POST may create another record rather than update the original rule.[^rule-handlers][^token-storage]

Validation/persistence errors return `400`; random-ID generation failure returns `500`. After successful creation, read runtime status. nftables, DNS, or other runtime problems may coexist with a `201`, with details in `stats.last_error`.[^rule-handlers][^manager]

### 9.2 Full replacement: `PUT /api/rules/{id}`

`{id}` is the existing rule ID; do not include literal braces in the request. IDs created by the API can be inserted directly in the path. Other locally imported valid IDs should be encoded as a single path segment by the client.[^rule-handlers][^config-validation]

**Dot-segment exception for locally imported IDs:** configuration validation in this version accepts `.` and `..` as IDs, but literal requests to `/api/rules/.` or `/api/rules/..` are normalized by Go 1.27.1 ServeMux and can redirect before reaching the API handler. Python's `urllib.parse.quote(id, safe="")` still preserves those dots. Explicitly encode a complete dot segment as `%2E` or `%2E%2E`. The Section 14 client handles this case; do not work around it by enabling automatic redirects. Normal 16-character hexadecimal IDs generated by the API are unaffected. This is a Go ServeMux path-normalization boundary, not a new ID-format requirement.

The request body uses the same Rule model. The path ID overrides any `id` in the body, so this endpoint cannot rename a rule ID. Success is `200 OK` and returns the full normalized Rule. A missing ID returns `404`; the endpoint does not implicitly create the rule.[^rule-handlers]

**PUT does not merge with the existing rule.** If an original rule has `enabled:true` and `data_plane:"go"`, omitting those fields during update produces `enabled:false` and `data_plane:"nftables"`. Likewise, omitted custom timeout, connection, or UDP values return to normalization defaults. Read the original object from `/api/config.rules`, change the intended fields, and submit the full object.[^normalize-rule]

There is no dedicated enable/disable endpoint; update the complete Rule's `enabled` field. The conceptual disable flow is:

```text
GET /api/config
→ find the complete object with the matching id in rules
→ set enabled to false
→ PUT /api/rules/{id} with the complete object
→ GET /api/status and inspect retirement state
```

Do **not** submit only an `enabled` fragment. Configuration changes can stop and recreate Go listeners; seamless migration of established connections is not promised. Accumulated counters for the same rule ID are generally retained through update because the existing Stats object is reused; PUT is not a counter-reset endpoint.[^manager]

### 9.3 Delete: `DELETE /api/rules/{id}`

**Authentication:** Bearer Token + CSRF. No request body. Success is:

```http
HTTP/1.1 204 No Content
```

There is no JSON response body. A missing ID returns `404`:

```json
{
  "error": "rule \"not-found\" not found"
}
```

Deletion updates persistent configuration first and then invokes rule-application logic. A `204` does not prove that surviving NAT/conntrack flows have been verified as retired. If retirement is incomplete, the ID or a cleanup record can continue to appear in `/api/status` while being absent from `/api/config.rules`. A second DELETE for that ID returns `404`; it is not a “continue cleanup” operation.[^rule-handlers][^kernel-state]

For leftover runtime state, inspect `kernel_state` and `stats.last_error`, allow the manager to reconcile when environmental prerequisites become available, and review host logs where appropriate. Do not copy runtime cleanup records back into persistent configuration, and do not declare safe retirement solely because the ID disappeared from `/api/config.rules`.[^manager][^kernel-state]

## 10. Complete Rule Schema and Validation

A Rule contains **27 JSON fields**. “Default” below means the result produced by `NormalizeRule` for API create/replace requests; it does not imply the WebGUI form's default selection. `protocol` has no API default, while omitted `enabled` becomes false.[^config-model][^normalize-rule]

### 10.1 Identity, protocol, and target

| Field | Type | Default/required | Validation and notes |
|---|---|---|---|
| `id` | string | Generated by server on create; path value on update | Local configuration requires non-empty, maximum 128 bytes; a body ID sent by an API client does not choose the persisted record ID |
| `name` | string | Required | Must be non-empty after trimming; maximum **80 bytes**, not 80 Unicode characters; names need not be unique |
| `protocol` | string | Required | Trimmed and lowercased; only `tcp`, `udp`, `both`; empty does not default to tcp |
| `data_plane` | string | `nftables` | Trimmed and lowercased; only `nftables` or `go`; runtime labels `go-proxy`/`hybrid` are invalid in configuration |
| `listen_host` | string | `*` | `*`, IPv4 literal, or IPv6 literal; multicast prohibited; empty normalizes to `*` |
| `listen_port` | integer | Required | `1–65535` |
| `listen_port_end` | integer | `0` (single port) | `0` means the start port; otherwise valid and not lower than the start |
| `target_host` | string | Required | Non-empty after trimming, maximum 253 bytes; IP literal or hostname for the resolver, not a URL |
| `target_port` | integer | Required | `1–65535` |
| `target_port_end` | integer | `0` (single port) | Must define the same number of ports as the listen range; end not lower than start |
| `enabled` | boolean | `false` | Administrator-desired activation state, not runtime feedback |
| `allow_private_target` | boolean | `false` | Explicitly permits restricted targets only when constrained by the CIDR allowlist |
| `target_cidr_allowlist` | string[] | Empty | CIDR notation required; at most 64 normalized/de-duplicated entries; bare IPs and `/0` are rejected |

Outer square brackets are stripped from `listen_host`/`target_host`, e.g. `[::1]` → `::1`; the field itself must not contain a port. Hostname DNS resolution is not performed as part of literal-IP configuration validation, so “saved successfully” does not mean the hostname is reachable.[^normalize-rule][^config-validation][^plan]

### 10.2 TCP/UDP common limits and connection budgets

All values below are integers. When these defaulted fields are omitted or sent as `0`, API normalization fills the listed default. **`0` does not mean unlimited or disabled timeout.** Negative values are not replaced by defaults; they fail validation.[^normalize-rule][^config-validation]

| Field | Default | Valid range | Unit/meaning |
|---|---:|---|---|
| `connect_timeout_seconds` | 10 | `1–300` | Seconds; related timeout for target resolution and Go upstream connection establishment |
| `tcp_idle_timeout_seconds` | 300 | `5–86400` | Seconds; Go TCP idle connection timeout |
| `max_tcp_connections` | 2048 | `1–resource_limits.max_tcp_connections` | Concurrent TCP budget for the rule's Go path |
| `max_tcp_connections_per_source` | 256 | `1–max_tcp_connections` | TCP budget per source IP for this rule |
| `udp_idle_timeout_seconds` | 60 | `5–86400` | Seconds; Go UDP session idle timeout |
| `max_udp_sessions` | 4096 | `1–10000000` and no greater than global UDP session limit | Go UDP session budget for this rule |
| `max_udp_sessions_per_source` | 512 | `1–max_udp_sessions` | UDP session budget per source IP within the rule |
| `udp_new_sessions_per_second_per_source` | 1000 | `1–10000000` | UDP new-session refill rate per source IP, sessions/s |
| `udp_packets_per_second_per_source` | 100000 | `1–100000000` | Inbound UDP packet budget refill rate per source IP, packets/s; not bit/s |

UDP numeric fields are normalized and validated even when `protocol:"tcp"`; TCP fields are still validated when `protocol:"udp"`. If local global limits are configured below the per-rule defaults, clients may need to explicitly lower both rule-level and per-source values; omission is not guaranteed to validate.[^config-validation]

These budgets apply to the Go path and do not automatically constrain kernel nftables/flowtable traffic. Multiple ports, address families, workers, and derived Go runners share logical rule/source budgets; do not multiply the configured budget by the number of workers when interpreting external capacity. UDP rates use token buckets with burst capacity, not a promise that every arbitrary one-second window can never exceed the configured numeric value.[^budgets][^udp-doc]

### 10.3 UDP workers and buffers

| Field | Default | Valid range | Meaning |
|---|---:|---|---|
| `udp_workers` | 0 | `0–128` | 0 = automatic; current automatic budget is `min(GOMAXPROCS,16)`, at least 1 |
| `udp_batch_size` | 64 | `1–256` | Number of messages in batched read/write operations |
| `udp_packet_buffer_size` | 2048 | `512–65535` | Bytes in each preallocated datagram buffer |
| `udp_listener_buffer_bytes` | 4194304 | `65536–268435456` | Requested buffer size for each listener socket |
| `udp_session_buffer_bytes` | 65536 | `65536–16777216` | Requested buffer size for each connected UDP upstream socket |

`udp_workers` is a rule-level budget, not a guarantee that every port starts exactly that many workers. After a rule is split into multiple listener endpoints, each endpoint needs at least one worker; when endpoint count exceeds the configured budget, actual total workers can exceed the configured value. The current status API does not expose actual worker count.[^plan][^udp-implementation]

Datagrams larger than `udp_packet_buffer_size` that are truncated are dropped and counted as application drops; truncated payload is not forwarded. Socket buffer values are requests, not guaranteed kernel-granted sizes. The status API does not expose effective socket buffer sizes or memory-budget consumption.[^udp-implementation][^udp-doc]

v2.5.0 preserves valid UDP sessions under transient send pressure, but unsent packets are still counted as drops; these parameters do not guarantee zero loss under overload and do not create an unbounded retry queue.[^udp-doc]

### 10.4 Port ranges

Effective range sizes are:

```text
listen_count = (listen_port_end == 0 ? listen_port : listen_port_end) - listen_port + 1
target_count = (target_port_end == 0 ? target_port : target_port_end) - target_port + 1
```

The counts must be equal, and each rule supports at most **4096 ports**. Mapping preserves the offset; it does not collapse all inbound ports onto one target port.[^config-validation][^runner]

Example:

```json
{
  "name": "Local UDP range",
  "protocol": "udp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 40000,
  "listen_port_end": 40009,
  "target_host": "127.0.0.1",
  "target_port": 50000,
  "target_port_end": 50009,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
```

This maps `40000→50000`, `40001→50001`, through `40009→50009`.

### 10.5 Restricted targets and the actual meaning of CIDR allowlisting

Target-address policy is applied to IP literals and DNS resolution results. Invalid addresses, unspecified addresses, multicast, and addresses classified by the source as non-valid unicast targets are rejected. Loopback, link-local unicast, private addresses, and explicitly listed `100.64.0.0/10` and `100.100.100.200/32` are restricted targets.[^target-policy]

A restricted target is allowed only when both conditions hold: `allow_private_target:true` and the target matches `target_cidr_allowlist`. Either one alone is insufficient. `allow_private_target:true` with an empty list fails configuration validation. IPv4-mapped IPv6 CIDRs are unsupported.[^target-policy]

**`target_cidr_allowlist` is not a general destination restriction for all public targets.** The current code first determines whether a target is in a restricted category. A valid non-restricted unicast target passes without being required to match this list. If every destination must be constrained, do not mistake this field for a complete egress firewall.[^target-policy]

When a hostname resolves to multiple addresses, every valid result must satisfy target policy. An unauthorized restricted address among the results causes authorization failure for that resolution rather than being silently dropped while other addresses are used. Literal configuration validation at save time and runtime DNS authorization are separate phases.[^plan]

### 10.6 Configured data plane versus actual runtime data plane

| `Rule.data_plane` | Current planning behavior |
|---|---|
| `go` | Forces the Go proxy; supports same-family and cross-family paths |
| `nftables` | Prefers nftables for eligible same-family, non-loopback ingress; cross-family paths, explicit loopback, targets with zones, and related cases are selected for Go by the planner |

`listen_host:"*"` expresses desired IPv4 and IPv6 ingress. `0.0.0.0` means IPv4 wildcard only; `::` means IPv6 wildcard only. Wildcard nftables plans may also add a loopback Go path, so a rule configured as `nftables` can appear as `hybrid` at runtime.[^plan]

The Go path is selected by planning based on ingress/target conditions; it is **not** an unconditional fallback after nftables creation fails. If an old kernel path has not been retired, startup of an overlapping Go path can be blocked. Inspect runtime state rather than inferring fallback.[^manager][^kernel-state]

### 10.7 Conflicts, counts, and omitted response fields

Configuration supports at most **1024 rules**, including disabled rules. Every rule undergoes basic field validation, but listener conflicts are checked only when both rules are enabled. A conflict requires overlapping protocol, overlapping listen-port ranges, and overlapping listen addresses. `both` overlaps both TCP and UDP; `*` overlaps every address; same-family wildcard addresses overlap concrete addresses in that family.[^config-validation][^rule-conflicts]

This compares only configured rules; it cannot guarantee that another host process is not already using the port. External port ownership may fail only during data-plane application, so status must still be checked.[^manager][^runner]

The following Rule fields use `omitempty` and can be absent when zero/empty:

```text
data_plane
listen_port_end
target_port_end
udp_workers
udp_batch_size
udp_packet_buffer_size
udp_listener_buffer_bytes
udp_session_buffer_bytes
allow_private_target
target_cidr_allowlist
```

After normal API create/replace, non-empty `data_plane` and defaulted batch/buffer values are normally present; `udp_workers:0`, zero range endpoints, false `allow_private_target`, and empty target lists are commonly omitted. Absence of `udp_workers` does not mean that the server lacks worker support. Runtime cleanup records do not necessarily pass through normal Rule normalization and can contain port 0, empty targets, or other values that should not be submitted back as ordinary configuration rules.[^config-model][^kernel-state]

## 11. Runtime, Stats, and Kernel State

### 11.1 RuleRuntime

Each element of `/api/status.rules[]` has this structure:[^manager-runtime]

| Field | Type | Meaning |
|---|---|---|
| `rule` | Rule | Rule object associated with the runtime record; it may not be a normal persistent-config rule |
| `stats` | StatsSnapshot | Running flag, errors, and Go-path statistics |
| `traffic` | TrafficSnapshot | Background-sampled Go/nft observations, hook counters, per-rule rates and validity flags; see [section 11.5](#115-trafficsnapshot-and-sampling-validity) and [monitoring](MONITORING.en-US.md) |
| `data_plane` | string | Data-plane label from the runtime/risk perspective; distinct from `rule.data_plane` |
| `go_running` | boolean | Whether at least one registered Go runner exists for the logical rule; not proof that every derived ingress path is healthy |
| `kernel_state` | string | Manager classification of kernel-state evidence; see below |

Runtime `data_plane` values:

| Value | Meaning |
|---|---|
| `disabled` | Normal disabled plan |
| `nftables` | Kernel path, or a conservatively retained kernel-risk label |
| `go-proxy` | Go path |
| `hybrid` | Mixed kernel/Go path, or retained kernel risk while a Go runner also exists |
| empty string | Planning failed before a data-plane label was produced, for example target-resolution failure; inspect `last_error` |

Do not write runtime values `go-proxy`, `hybrid`, or `disabled` into configuration `Rule.data_plane`, which accepts only `go` or `nftables`.[^plan][^manager]

### 11.2 Complete `kernel_state` enum

The current `nftRuleState` can return these 8 values. Their order below summarizes source check precedence; it is not a health score.[^kernel-state]

| Value | Actual meaning | Integration note |
|---|---|---|
| `retirement-pending` | A kernel path for this rule is awaiting retirement | Old forwarding cannot be considered retired |
| `admission-suspended` | New NFT traffic admission is suspended | Existing NAT connections may remain; this is not a complete stop |
| `active-verified` | Corresponding active path exists and overall state evidence has been verified and is not unknown | Not proof of application reachability or hardware offload |
| `active-unverified` | Active path is recorded but state evidence is not fully verified | Do not treat as normal healthy state |
| `unknown` | Kernel state is unknown | Cannot infer absence of old forwarding |
| `inactive-verified` | No matching active/pending/suspended path and state evidence is verified | Applies to the current observation, not a future persistence guarantee |
| `unverified` | Not verified and not classified by the cases above | Requires interpretation with errors and environment |
| `not-reported` | Current backend does not expose this state-report interface | Does not mean `inactive-verified` |

### 11.3 Complete StatsSnapshot fields

Counters are aggregated on the logical rule's Stats object. Workload counters are primarily produced by the Go proxy and do not cover all nftables data-plane traffic.[^stats][^tcp-stats][^udp-implementation]

| Field | Type | Meaning |
|---|---|---|
| `running` | boolean | Manager running/risk flag; may remain conservatively true because old kernel forwarding might still exist |
| `started_at` | string | Time recorded when `running` changes from false to true; may be zero time if uninitialized; not the timestamp of the most recent workload packet |
| `last_error` | string, optional | Most recently recorded management/path error; omitted when empty; not a structured error code |
| `active_tcp` | integer/int64 | TCP connections currently accepted through the Go TCP budget, including connections still dialing upstream |
| `active_udp_sessions` | integer/int64 | Current Go UDP sessions |
| `total_tcp` | integer/uint64 | Cumulative TCP admissions through the Go connection budget; an upstream dial can fail after this increment |
| `total_udp_sessions` | integer/uint64 | Cumulative Go UDP sessions created; not unique client IP count |
| `tcp_rejected` | integer/uint64 | Go TCP rejections caused by source identification/resource budgets; not all connection errors |
| `bytes_up` | integer/uint64 | Cumulative Go-proxy payload bytes from client → target |
| `bytes_down` | integer/uint64 | Cumulative Go-proxy payload bytes from target → client |
| `udp_packets_up` | integer/uint64 | Upstream UDP messages successfully handed to the send syscall by the Go path; does not prove remote receipt |
| `udp_packets_down` | integer/uint64 | Downstream UDP messages successfully handed to the send syscall by the Go path |
| `udp_drops` | integer/uint64 | Application-observable UDP drops, such as truncation, invalid packets, budget exhaustion, session creation failure, and unsent batched messages |

**Statistics have update-timing differences.** TCP byte counts are aggregated after the current bidirectional copy operation finishes, so a long-lived connection can have visibly stale byte totals while traffic is active. UDP workers merge local counters into shared Stats during maintenance/cleanup. A snapshot is not an atomic transaction across every counter, so differences between two `bytes_up` snapshots should not be treated as a precise real-time link-rate measurement.[^tcp-stats][^udp-implementation][^stats]

These values are not a complete traffic ledger for the instance. A pure nftables path can carry real traffic while Go counters remain zero; hybrid records reflect only the Go component. `udp_drops` is not the sum of all losses in the host kernel, NIC, network, and remote endpoint.[^udp-doc]

When a rule ID is retained, stop/start cycles generally retain cumulative counters. After a rule is fully deleted/cleaned up or the process restarts, counter continuity should not be expected. There is no counter-reset endpoint and no persistent historical time series.[^manager][^stats]

`traffic.go` adds active TCP observations; `stats.bytes_up/bytes_down` retain their copy-completion semantics above. nft uses best-effort conntrack accounting, with hook counters reported separately. An unavailable or warming-up rate is not zero traffic. See [traffic and Prometheus](MONITORING.en-US.md).

### 11.4 Risk semantics of `running=true`

When the runtime environment cannot prove that the old kernel path is empty, saving a disabled rule can produce a **risk-state response fragment** like the following:

```json
{
  "data_plane": "nftables",
  "go_running": false,
  "kernel_state": "unknown",
  "stats": {
    "running": true,
    "last_error": "previous kernel forwarding may still be active; revocation is incomplete: kernel state is not proven empty: netfilter inventory is nonempty or incomplete"
  }
}
```

This is not a healthy data-plane example and does not assert that forwarding actually existed. It shows that the server did not misrepresent “old kernel path could not be proven absent” as a fully stopped condition. The production source likewise retains explicit risk flags for pending retirement/suspended states.[^manager][^kernel-state]

Integrators may use the following **recommended strategy**; it is not an additional server health contract. When desired configuration is enabled, require no `last_error`, a runtime label consistent with expectations, expected Go-path presence where applicable, and no unresolved kernel-state risk; then perform real workload payload probes. For disable/delete, verify both desired configuration and runtime retirement evidence rather than counting only `enabled` or `running` booleans.

### 11.5 TrafficSnapshot and sampling validity

The collector samples in the background about once per second. Reading status does not trigger nft/conntrack commands. The API keeps Go payload and best-effort nft L3 observations separate; WebGUI alone combines their cumulative bytes into an approximate display total, and still shows separate rates.[^telemetry][^metrics][^gui]

| TrafficSnapshot field | JSON type | Meaning |
|---|---|---|
| `go` | TrafficSeries | Go payload observations; packet counters describe UDP only |
| `nft` | TrafficSeries | Best-effort conntrack L3 observations, including flowtable counters when synchronized |
| `nft_hooks` | NFTHookCounter[] | Cumulative observed hook counters, sorted by hook name; initially `[]` |
| `nft_hooks_sampled_at` | string | Time of the last successful owned-hook sample, or zero-value time |
| `nft_hooks_available` | boolean | Hook sample is available and fresh; independent of conntrack accounting availability |
| `nft_best_effort` | boolean | The sampled runtime plan uses nft; false before initialization or for a Go-only plan. Not a completeness guarantee |
| `nft_status` | string | Collection state below, not forwarding health |
| `counter_resets` | integer/uint64 | Detected decreases in nft hook/conntrack counters, not a count of every Go or process reset |

Both `go` and `nft` contain all 12 TrafficSeries fields:

| TrafficSeries field(s) | JSON type | Meaning |
|---|---|---|
| `bytes_up`, `bytes_down` | integer/uint64 | Observed cumulative bytes, client → target / target → client |
| `packets_up`, `packets_down` | integer/uint64 | Observed packets in each direction; UDP only for Go |
| `bytes_up_per_second`, `bytes_down_per_second` | number/float64 | Byte-rate estimates, usable only when both validity flags are true |
| `packets_up_per_second`, `packets_down_per_second` | number/float64 | Packet-rate estimates with the same validity requirement |
| `sampled_at` | string | Last successful sample time, or zero-value time |
| `interval_seconds` | number/float64 | Interval used for the latest valid delta; zero when a newly collected sample cannot form a rate |
| `available` | boolean | Source sample is available and no more than three seconds old |
| `rate_ready` | boolean | A valid recent delta exists; check together with `available` |

Each NFTHookCounter contains `hook` (string), `bytes` and `packets` (integer/uint64). Hook labels are `prerouting`, `output`, `postrouting`, `forward` or `flowtable`. Hooks overlap and miss fast-path bypass packets; never add them together or treat them as full forwarding throughput.

| `nft_status` | Meaning |
|---|---|
| `pending` | No sample yet for this rule/Stats identity |
| `not_applicable` | The sampled plan does not use nft |
| `sampled` | nft collection succeeded and complete conntrack accounting is available for this rule |
| `accounting_unavailable` | Hook collection succeeded, but this rule has no complete usable conntrack accounting sample |
| `unavailable` | nft reader is absent or collection failed; can be superseded by `stale` |
| `stale` | An nft-using row has no successful hook sample within three seconds, including an uninitialized hook timestamp |

The first sample, recovery after an unavailable sample, counter decreases and overly long sampling gaps require a new valid delta. Stale reads clear validity flags but may retain old numeric rates, intervals and counters. **Neither a zero numeric rate nor a retained value establishes current traffic: require `available && rate_ready` before using a rate.** An incomplete nft sample retains the last complete flow baseline; hook data may still be usable. Go sample availability does not prove a runner is healthy or active.

Flowtable synchronization may lag, and short-lived connections may never appear in a sample. Counters are process-local observations, not durable history or billing data. See [monitoring boundaries](MONITORING.en-US.md).

## 12. Error Responses and Handling

### 12.1 JSON error shape

The handlers use a one-field standard error object:[^json]

```json
{
  "error": "error description"
}
```

There is no `code`, `message`, `details`, `errors[]`, or `request_id`. In v2.5.0, fixed authentication/CSRF/JSON handler errors can still be Chinese while configuration-validation errors are English. The bilingual GUI translates known messages when English is selected; its language switch does not change the API protocol. **API error text is not guaranteed to be entirely English and there is no Accept-Language negotiation.**[^auth][^json][^gui]

### 12.2 Common status codes

| Status | Scenario | Response form / note |
|---:|---|---|
| `200` | Read, save settings, rotate token, or update success | Endpoint-specific JSON |
| `201` | Persistent rule creation succeeded | Rule JSON; does not guarantee runtime path success |
| `204` | Persistent rule deletion succeeded and apply logic was invoked | Empty response body; does not guarantee verified retirement |
| `400` | JSON, field, or configuration validation failure; some persistence failures | Usually APIError; oversized body and Content-Type failures also use this code |
| `401` | Missing, invalid, or unacceptable token format | APIError with WWW-Authenticate |
| `403` | CSRF or same-origin rejection | APIError; HTTP management-ACL rejection is plain text |
| `404` | PUT/DELETE ID absent, or nonexistent GET path | Former is JSON; latter can be plain text |
| `405` | Method not accepted by the route, e.g. POST /api/status | Go ServeMux plain text plus Allow header, not APIError |
| `429` | Too many failed authentications | APIError; no Retry-After contract |
| `500` | Token/ID generation or rotation error, ACL refresh failure, etc. | APIError; may contain local error context |

Go ServeMux GET routes also match HEAD. The root GET registration is also a fallback match, so some `Allow` headers can include `GET, HEAD`; this does not mean the resource implements a useful GET API. In v2.5.0, `OPTIONS /api/settings` returns `405` with `Allow: GET, HEAD, PUT`; do not interpret that as CORS support.[^routes]

### 12.3 Representative source error text

The table below preserves current source wording. Dynamic IDs, addresses, and operating-system error details can vary. Clients should primarily use HTTP status plus operation context instead of hard-coding entire error strings.[^auth][^json][^settings][^config-validation][^target-policy]

| HTTP | Example/original `error` | What to check |
|---:|---|---|
| 401 | `管理员令牌无效` | Token source, length, header format, and whether rotation occurred |
| 429 | `认证请求过于频繁，请稍后重试` | Reduce retries using bad tokens; valid-token authentication is not locked out |
| 403 | `跨站请求被拒绝` | Origin, actual TLS scheme, Host:port, Sec-Fetch-Site |
| 403 | `CSRF 校验失败，请刷新页面` | GET bootstrap again; check whether the service restarted |
| 400 | `Content-Type 必须是 application/json` | Only the three JSON write endpoints need this media type |
| 400 | `JSON 格式错误: json: unknown field "extra"` | Remove fields that do not belong to the request model |
| 400 | `请求只能包含一个 JSON 对象` | Check for concatenated JSON values |
| 400 | `JSON 请求体不能超过 1048576 字节` | Reduce request size; there is no batch-rule endpoint |
| 400 | `web port must be 1-65535` | Check whether settings PUT omitted `port` |
| 400 | `tls_min_version 仅支持 1.2 或 1.3` | Use string `"1.2"` or `"1.3"` |
| 400 | `请先配置 TLS 并重启服务，再通过 HTTPS 启用严格 IP 白名单` | Current request is not native HTTPS |
| 400 | `严格 IP 白名单必须包含当前客户端地址` | Keep the current direct source IP or a valid loopback recovery path |
| 400 | `this deployment requires HTTPS: certificate/key cannot be cleared and insecure HTTP cannot be enabled` | Preserve complete certificate paths; do not attempt an API downgrade |
| 400 | `rule "<id>" target: local/private target 127.0.0.1 is denied by default` | Verify the restricted-target dual authorization |
| 400 | `rule "<id>" listen and target port ranges must have the same size` | Make both ranges the same length |
| 404 | `rule "<id>" not found` | Confirm the ID comes from persistent configuration, not a runtime cleanup record |

Configuration write I/O failure can still return `400` because handlers place `Store.Update` failures in that branch. A `400` therefore does not mechanically mean “the server itself is healthy”; read the specific error and inspect permissions, disk, and configuration path. Conversely, 2xx is not a data-plane success guarantee.[^rule-handlers][^settings]

## 13. Complete curl Integration Flow

This section is an integration example, not a server-supplied script. It requires Bash, curl with `--fail-with-body`, and jq. The snippets are intended to run sequentially in the same Bash session. First verify that HTTPS is prepared, the client source is allowed by the ACL, and the certificate name matches. The example does not bypass TLS verification.

Do not enter real tokens with shell tracing (`set -x`), curl verbose/trace or session recording enabled. Configuration/status responses and errors may expose runtime endpoints and local paths; do not publish them unredacted. The example explicitly bypasses ambient proxies and disables shell tracing; validate the trust boundary before adding a proxy.

### 13.1 Initialize token, trusted certificate, and CSRF

```bash
set +x
set -euo pipefail

PB_BASE='https://127.0.0.1:9080'
PB_CA='/path/to/trusted-ca-or-verified-server-cert.pem'

# Temporary files are not written to normal logs; the authorization header is
# not expanded directly into curl process arguments.
umask 077
PB_WORK=$(mktemp -d)
trap 'rm -rf -- "$PB_WORK"' EXIT

read -rsp 'Administrator token: ' PB_TOKEN
printf '\n'
printf 'Authorization: Bearer %s\n' "$PB_TOKEN" > "$PB_WORK/headers"
unset PB_TOKEN

CURL=(curl -q --silent --show-error --fail-with-body
      --connect-timeout 5 --max-time 60 --noproxy '*' --cacert "$PB_CA")

pb_api() {
  local method="$1" path="$2"
  shift 2
  "${CURL[@]}" --header "@$PB_WORK/headers" \
    --request "$method" "$PB_BASE$path" "$@"
}

PB_CSRF=$(pb_api GET /api/bootstrap | jq -er '.csrf')
printf 'X-PortBridge-CSRF: %s\n' "$PB_CSRF" >> "$PB_WORK/headers"

pb_api GET /api/config | jq .
pb_api GET /api/status | jq .
```

If the service uses a publicly trusted CA already present in the system trust store, adapt the command to use curl's system trust store. Do not remove CA validation and add `-k` merely to make the example work quickly. `curl -q` prevents automatic loading of the default curl configuration file, and redirects are not followed, preventing hidden configuration from changing credential-bearing requests.

### 13.2 Create a disabled rule and capture the server ID

```bash
cat > "$PB_WORK/create.json" <<'JSON'
{
  "name": "Local TCP service",
  "protocol": "tcp",
  "data_plane": "go",
  "listen_host": "127.0.0.1",
  "listen_port": 18080,
  "target_host": "127.0.0.1",
  "target_port": 8080,
  "enabled": false,
  "allow_private_target": true,
  "target_cidr_allowlist": ["127.0.0.1/32"]
}
JSON

pb_api POST /api/rules \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/create.json" > "$PB_WORK/created.json"

PB_RULE_ID=$(jq -er '.id' "$PB_WORK/created.json")
printf 'Created rule ID: %s\n' "$PB_RULE_ID"
jq . "$PB_WORK/created.json"
```

### 13.3 Read the complete rule, then enable it

The following performs a real write. Before running it, verify that `127.0.0.1:8080` is an owned target service you intend to forward and that `127.0.0.1:18080` does not conflict with an existing listener. The example modifies the complete persisted object, preserving custom fields.

```bash
pb_api GET /api/config > "$PB_WORK/config-before-enable.json"
jq -e --arg id "$PB_RULE_ID" \
  '.rules[] | select(.id == $id) | .enabled = true' \
  "$PB_WORK/config-before-enable.json" > "$PB_WORK/enable.json"

pb_api PUT "/api/rules/$PB_RULE_ID" \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/enable.json" | jq .

pb_api GET /api/status | jq --arg id "$PB_RULE_ID" \
  '.rules[] | select(.rule.id == $id) |
   {id: .rule.id, desired_enabled: .rule.enabled,
    data_plane, go_running, kernel_state, stats, traffic}'
```

If the write returns 2xx but `last_error` is non-empty or kernel evidence is not verified, resolve the indicated environment/path issue before treating the workload as accepted.

### 13.4 Change minimum TLS version while preserving complete settings

This separate example changes the saved minimum TLS policy to 1.3. The management client must support the resulting policy. It does not restart the service or change listeners/allowlists.

```bash
pb_api GET /api/config > "$PB_WORK/config-before-settings.json"
jq '.web | .tls_min_version = "1.3"' \
  "$PB_WORK/config-before-settings.json" > "$PB_WORK/settings.json"

pb_api PUT /api/settings \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/settings.json" | jq .
```

If restart is required, perform it through the authorized local operational procedure. After restart, GET bootstrap again and update `PB_CSRF` and the temporary header file. Do not keep using the old CSRF value. There is no `/api/restart`.

### 13.5 Disable, delete, and check both configuration and runtime state

```bash
pb_api GET /api/config > "$PB_WORK/config-before-disable.json"
jq -e --arg id "$PB_RULE_ID" \
  '.rules[] | select(.id == $id) | .enabled = false' \
  "$PB_WORK/config-before-disable.json" > "$PB_WORK/disable.json"

pb_api PUT "/api/rules/$PB_RULE_ID" \
  --header 'Content-Type: application/json' \
  --data-binary "@$PB_WORK/disable.json" | jq .

# Successful deletion has no response body, so do not pipe it to jq.
pb_api DELETE "/api/rules/$PB_RULE_ID"

pb_api GET /api/config | jq --arg id "$PB_RULE_ID" \
  '[.rules[] | select(.id == $id)]'
pb_api GET /api/status | jq .
```

The first read checks whether the persistent record is gone. The second checks whether an old path still has pending/unknown retirement state. They are not interchangeable.

### 13.6 Perform token rotation separately

Rotation invalidates old tokens held by other clients. Run this only as an intentional rotation procedure, not as part of ordinary health checking.

```bash
pb_api POST /api/token/rotate > "$PB_WORK/rotation.json"
NEW_TOKEN=$(jq -er '.token' "$PB_WORK/rotation.json")

# Atomically replace the temporary client authentication headers.
# CSRF remains valid within this server process.
{
  printf 'Authorization: Bearer %s\n' "$NEW_TOKEN"
  printf 'X-PortBridge-CSRF: %s\n' "$PB_CSRF"
} > "$PB_WORK/headers.new"
mv -- "$PB_WORK/headers.new" "$PB_WORK/headers"
unset NEW_TOKEN

pb_api GET /api/bootstrap > "$PB_WORK/bootstrap-after-rotation.json"
jq '{name, csrf_received: (.csrf | length == 48)}' \
  "$PB_WORK/bootstrap-after-rotation.json"
```

The configured server-side token file is updated. Temporary client files are removed when the shell exits. Long-lived automation should store the new token in its own controlled secret store rather than printing rotation output publicly.

## 14. Python Standard-Library Client Example

The following integration client is an example, not a project SDK. It requires Python 3.10 or later and no third-party HTTP package. It preserves TLS verification, refuses automatic redirects, ignores ambient proxy settings by default, handles non-JSON failures and `204`, and **does not automatically retry writes**. The client also converts incomplete response reads and other `http.client.HTTPException` failures to `PortBridgeTransportError`, including failures while reading an HTTP error body. A write encountering such a failure still has an unknown outcome and is not retried automatically.

Save it as `portbridge_client.py` and run:

```bash
python3 portbridge_client.py \
  --base 'https://127.0.0.1:9080' \
  --ca '/path/to/trusted-ca-or-verified-server-cert.pem'
```

By default, the token is read interactively without echo. A locally protected secret file can also be used:

```bash
python3 portbridge_client.py \
  --base 'https://127.0.0.1:9080' \
  --ca '/path/to/trusted-ca-or-verified-server-cert.pem' \
  --token-file '/secure/path/admin.token'
```

The CLI entry point only reads bootstrap and status; it does not create, update, delete, or rotate. Object methods can be used in your own automation. `get_rule` and `set_enabled` are client-side composite operations, not additional server endpoints.

```python
#!/usr/bin/env python3
"""Go-nftables-portbridge v2.5.0 client; CLI performs read-only calls."""
from __future__ import annotations

import argparse
import getpass
from http import client as http_client
import json
import math
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib import error, parse, request

class PortBridgeAPIError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"HTTP {status}: {message}")

class PortBridgeTransportError(RuntimeError):
    pass

class _NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # Never forward management credentials to a redirect target.

class PortBridgeClient:
    def __init__(self, base_url: str, token: str,
                 ca_file: str | None = None, timeout: float = 60.0) -> None:
        parts = parse.urlsplit(base_url)
        if (parts.scheme != "https" or not parts.hostname or
                parts.username is not None or parts.password is not None or
                parts.path not in ("", "/") or parts.query or parts.fragment):
            raise ValueError("base_url must be an HTTPS origin without credentials or a path")
        token = token.strip()
        if len(token) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in token):
            raise ValueError("This example requires a program-generated 64-character hexadecimal administrator token")
        if timeout <= 0 or not math.isfinite(timeout):
            raise ValueError("timeout must be positive and finite")
        self.base_url = f"https://{parts.netloc}"
        self.token = token
        self.csrf = ""
        self.timeout = timeout
        tls_context = ssl.create_default_context(cafile=ca_file)
        self._opener = request.build_opener(
            request.ProxyHandler({}),  # Explicitly avoid ambient proxy settings.
            request.HTTPSHandler(context=tls_context),
            _NoRedirect(),
        )

    def _request(self, method: str, path: str,
                 body: dict[str, Any] | None = None) -> Any:
        if not path.startswith("/api/") or "?" in path or "#" in path:
            raise ValueError("Use a documented /api/ path without query or fragment")
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json"}
        if method != "GET":
            if not self.csrf:
                self.bootstrap()
            headers["X-PortBridge-CSRF"] = self.csrf
        payload = None
        if body is not None:
            payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
            headers["Content-Type"] = "application/json"
        req = request.Request(self.base_url + path, data=payload, headers=headers, method=method)
        # The outer handler also covers failures while reading an HTTPError body.
        try:
            try:
                with self._opener.open(req, timeout=self.timeout) as response:
                    raw = response.read()
                    if response.status == 204:
                        return None
                    if response.headers.get_content_type() != "application/json":
                        raise PortBridgeAPIError(response.status, "Expected a JSON response")
                    try:
                        return json.loads(raw)
                    except (ValueError, UnicodeError) as exc:
                        raise PortBridgeAPIError(response.status, "Malformed JSON response") from exc
            except error.HTTPError as exc:
                with exc:
                    raw = exc.read().decode("utf-8", errors="replace")
                try:
                    decoded = json.loads(raw)
                    message = str(decoded.get("error", raw)) if isinstance(decoded, dict) else raw
                except ValueError:
                    message = raw.strip() or str(exc.reason)
                raise PortBridgeAPIError(exc.code, message) from exc
        except (error.URLError, http_client.HTTPException, TimeoutError, OSError) as exc:
            detail = "Read failed" if method == "GET" else "Write outcome is unknown; inspect state before retrying"
            raise PortBridgeTransportError(f"{detail}: {exc}") from exc

    def bootstrap(self) -> dict[str, Any]:
        data = self._request("GET", "/api/bootstrap")
        if not isinstance(data, dict) or not isinstance(data.get("csrf"), str) or len(data["csrf"]) != 48:
            raise ValueError("Unexpected bootstrap response")
        self.csrf = data["csrf"]
        return data

    def get_config(self) -> dict[str, Any]:
        return self._request("GET", "/api/config")

    def get_status(self) -> dict[str, Any]:
        return self._request("GET", "/api/status")

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        # This is local lookup, not GET /api/rules/{id}.
        for rule in self.get_config()["rules"]:
            if rule["id"] == rule_id:
                return dict(rule)
        raise KeyError(f"Rule is absent from persistent configuration: {rule_id}")

    def create_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        return self._request("POST", "/api/rules", rule)

    @staticmethod
    def _rule_path(rule_id: str) -> str:
        if not isinstance(rule_id, str) or not rule_id:
            raise ValueError("rule_id must be a non-empty string")
        segment = parse.quote(rule_id, safe="")
        # quote(..., safe="") still leaves dots unescaped. Encode complete dot
        # segments so ServeMux does not redirect these locally imported IDs.
        if rule_id in (".", ".."):
            segment = segment.replace(".", "%2E")
        return "/api/rules/" + segment

    def replace_rule(self, rule_id: str, rule: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", self._rule_path(rule_id), rule)

    def set_enabled(self, rule_id: str, enabled: bool) -> dict[str, Any]:
        if not isinstance(enabled, bool):
            raise TypeError("enabled must be bool")
        rule = self.get_rule(rule_id)
        rule["enabled"] = enabled
        return self.replace_rule(rule_id, rule)

    def delete_rule(self, rule_id: str) -> None:
        self._request("DELETE", self._rule_path(rule_id))

    def save_settings(self, complete_web_settings: dict[str, Any]) -> dict[str, Any]:
        return self._request("PUT", "/api/settings", complete_web_settings)

    def rotate_token(self) -> str:
        # Not retried. The old token stops authenticating after a successful rotation.
        data = self._request("POST", "/api/token/rotate")
        new_token = data.get("token") if isinstance(data, dict) else None
        if (not isinstance(new_token, str) or len(new_token) != 64 or
                any(ch not in "0123456789abcdef" for ch in new_token)):
            raise ValueError("Rotation may have succeeded, but the response token is invalid")
        self.token = new_token
        return new_token

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="HTTPS origin, e.g. https://127.0.0.1:9080")
    parser.add_argument("--ca", help="Trusted CA or verified self-signed certificate PEM")
    parser.add_argument("--token-file", help="Local secret file; otherwise prompt without echo")
    args = parser.parse_args()
    try:
        token = (Path(args.token_file).read_text(encoding="utf-8").strip()
                 if args.token_file else getpass.getpass("Administrator token: "))
        client = PortBridgeClient(args.base, token, args.ca)
        client.bootstrap()
        print(json.dumps(client.get_status(), ensure_ascii=False, indent=2))
        return 0
    except (PortBridgeAPIError, PortBridgeTransportError, ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
```

When modifying a rule, first fetch the complete object:

```python
rule = client.get_rule(rule_id)
rule["udp_packet_buffer_size"] = 4096
updated = client.replace_rule(rule_id, rule)
status = client.get_status()
```

When saving settings, pass only `.web` from the configuration projection:

```python
settings = client.get_config()["web"]
settings["tls_min_version"] = "1.3"
result = client.save_settings(settings)
print("Requires service restart:", result["restart_required"])
```

These snippets assume an already initialized `client` and a valid `rule_id`; they are not stand-alone scripts. On a CSRF 403, inspect the error, call `client.bootstrap()`, and then let the operator decide whether to resubmit the original write. This example client does not implement cross-process token synchronization or multi-threaded write serialization.

## 15. Concurrency, Retries, and Operational Boundaries

A successful HTTP status with a non-JSON or malformed response can still mean a write was applied: read back before retrying. The Python example accepts program-generated hexadecimal tokens only; that is a client constraint, not an additional server-side format check.

### 15.1 What still needs to happen after a successful HTTP write

Create/update ordering is “decode → normalize → validate and persist → Apply → return configuration object,” not a rollback-capable transaction of “persist + every kernel path succeeded.” Saving settings can additionally trigger ACL, DNS, and rule application.[^rule-handlers][^settings]

Automation should therefore model two results: the **configuration submission result** and the **data-plane acceptance result**. After submission, re-read `/api/config` and `/api/status`; for enable operations, perform a workload-level round trip using the target protocol; for disable/delete operations, confirm that there is no unresolved old-path retirement state. This is an integration strategy, not a claim that a particular deployment passed acceptance testing.

### 15.2 Concurrent modification

The Store locks updates and atomically replaces the configuration file, preventing interleaved writes inside one process, but the API exposes no ETag, If-Match, revision, or compare-and-swap mechanism. If two clients separately read an old Rule and then both PUT complete replacements, the later write can overwrite unrelated fields changed by the first client.[^config-store][^routes]

Serialize rule/settings writes per instance on the client side and read the latest complete object before submission. This reduces overwrite risk but cannot provide strict optimistic concurrency without a server-side version condition. Token rotation should be owned by a single controlled workflow.

### 15.3 Retry behavior and unknown outcomes

| Operation | Recommended handling after transport failure |
|---|---|
| GET reads | Limited retry is reasonable after validating address/TLS/ACL; do not hammer authentication failures |
| POST create rule | Do not automatically retry; read configuration and determine whether creation already occurred to avoid duplicates |
| PUT rule/settings | Read back first to determine whether persistence happened; resubmitting the same object can retrigger runtime logic |
| DELETE | Inspect both configuration and runtime state; a later 404 only proves the persistent ID is absent, not that the kernel path is gone |
| POST token rotation | Do not automatically retry; the old token may already be invalid, requiring a known new value or local recovery channel |
| Explicit CSRF 403 | Fetch a new bootstrap value, determine whether the process restarted, then decide whether to repeat the original operation |

Client disconnect and data-plane application are not a transaction. DNS planning has its own timeout, and applying multiple rules/kernel operations can take time. A read/write timeout does not prove that an earlier persistence step did not happen.[^plan][^web-start][^rule-handlers]

### 15.4 Configuration refresh and service restart

The main program obtains the current in-memory Store configuration every **30 seconds**, refreshes interface ACL state, and calls rule `Refresh`. This is not a 30-second reread of on-disk `config.json`. Directly editing the disk file is not hot-loaded by that loop and can be overwritten by a later API save. Fields that exist only in local configuration should be changed through a controlled stop/edit/restart procedure.[^main-refresh][^config-store]

On periodic DNS refresh failure, the planner may retain a previously resolved address when the hostname is unchanged and the cached address still satisfies current target authorization. Authorization failures cannot be bypassed with the cache. Active Apply caused by rule writes or DNS-setting updates is distinct from periodic Refresh that may use cached resolution. The API does not expose resolved target addresses, TTLs, or cache-hit status.[^plan]

The frontend itself uses serialized status polling, starting the next request roughly 500 ms after the previous request completes. External monitoring should likewise choose a suitably low serialized polling rate for its environment instead of building up concurrent requests. The server does not promise fixed status latency or a success-request QPS.[^gui][^web-start]

### 15.5 Native TLS and reverse-proxy boundary

The ACL identifies the direct connection source, while Origin validation uses actual `r.TLS` and `r.Host`; forwarded headers are not used to reconstruct the original client IP/scheme. A generic reverse proxy cannot be assumed compatible by default: the proxy itself can become the source seen by the ACL, and changes in Host or upstream TLS can trigger same-origin rejection.[^auth][^acl]

This API exposes no “trusted proxy IP list.” If a proxy deployment is required, separately validate native TLS on the upstream leg, Host preservation, real-client access control, and same-origin behavior. Do not work around failures by removing security headers, disabling TLS, or opening the ACL to every address.

## 16. Capabilities Not Exposed by the Current API

The table below prevents clients from inventing endpoints based on common REST naming conventions. It is derived from the complete route registration and request models in this version.[^routes][^read-handlers][^config-model]

| Capability | Current status / actual alternative |
|---|---|
| `GET /api/rules`, `GET /api/rules/{id}` | Not implemented; read rules from GET config/status |
| `PATCH /api/rules/{id}`, partial field updates | Not implemented; read the complete Rule and PUT it |
| `POST /api/login`, `POST /api/logout` | Not implemented; authenticate directly with Bearer, clear token client-side on logout |
| Multiple users, roles, read-only tokens, per-rule authorization | Not implemented; one administrator token |
| Batch create/delete, raw config import/export | Not implemented; one rule per request, and GET config is not the complete disk configuration |
| Set token to a client-chosen value or read current plaintext token | Not implemented; rotation can only generate a new value, or an authorized local administrator can manage local state |
| Remote restart/stop, certificate hot reload | Not implemented; local operational action |
| Certificate/private-key upload, ACME issuance | Not implemented; settings accept server-local file paths only |
| Log query/download, SSE, WebSocket, event subscription | Not implemented |
| Anonymous workload `/healthz` | Not implemented; status and `/metrics` both require administrator authentication |
| Statistics history, counter reset, paging/filtering | Not implemented |
| Software-version query, dynamic OpenAPI/Swagger | Not registered; `/api/bootstrap.name` is not a version number |
| Read/change global resource limits, conntrack mark, flowtable master switch | Not exposed through API; configured in local full configuration |
| Read actual resolved target, worker count, socket buffers, total memory use | Not exposed by the current status structure |
| Source ACL/firewall management for forwarded service ports | Management Web ACL is not a substitute; current API does not provide complete firewall management |

### 16.1 Important fields available only in local configuration

These are configuration-model capabilities, not extra API parameters. Adding them to `PUT /api/settings` causes an unknown-field error.[^config-model][^config-defaults][^config-validation]

| Local field | Source default/range | API visibility |
|---|---|---|
| `version` | Config schema version `2`, not software release 2.5.0 | Not returned by GET config |
| `web.admin_token_sha256` | SHA-256 of administrator token string | Not returned; cannot be set through settings |
| `web.require_https` | Installation flow sets true; raw Default is false | Read only through `https.required`; settings does not accept it |
| `web.allow_unsafe_all_address_acl` | Default false | Not returned/not API-modifiable; strict mode still rejects `/0` |
| `resource_limits.max_tcp_connections` | Default 8192; range `1–1000000` | Not returned/not API-modifiable |
| `resource_limits.max_udp_sessions` | Default 16384; range `1–10000000` | Not returned/not API-modifiable |
| `resource_limits.max_udp_memory_bytes` | Default 1073741824; range `67108864–1099511627776` | Not returned/not API-modifiable; estimated budget, not exact RSS |
| `nftables.conntrack_mark` | Must be non-zero; Default constant `0x50420001`; new-config creation generates a random non-zero instance mark | Not returned/not API-modifiable; do not assume the constant is every instance's actual value |
| `nftables.enable_flowtable` | Default true | Not returned/not API-modifiable; enabled does not prove observed hardware offload |

---

## 17. Prometheus metrics

`GET /metrics` shares management HTTPS, source-IP allowlisting and Bearer authentication; GET needs no CSRF. Success returns `text/plain; version=0.0.4; charset=utf-8`, not JSON. Metrics omit rule names, forwarding endpoints and tokens. The credential still grants full administrator access, not read-only monitoring. Unavailable/warming-up rate samples are omitted; retained counters must be interpreted with validity gauges. No alert rules are configured automatically. All 15 metric families, their types/labels and a scrape example are documented in [monitoring](MONITORING.en-US.md).[^metrics]

## Implementation References and Source Links

The links below assume this file is stored in the repository `docs/` directory and point to the v2.5.0 implementation. References use file-level links to avoid stale line ranges. Source footnotes distinguish implemented server behavior from client recommendations explicitly identified as such in this document.

[^routes]: [`internal/web/server.go`](../internal/web/server.go). Complete route registration, root page, and static-resource fallback.
[^web-start]: [`internal/web/server.go`](../internal/web/server.go). Listener addresses, native TLS, HTTP timeouts, and Header limits.
[^web-constructor]: [`internal/web/server.go`](../internal/web/server.go). Web Server initialization timestamp and random CSRF generation.
[^headers]: [`internal/web/server.go`](../internal/web/server.go). Security response headers, HTTP-layer ACL, and JSON response headers.
[^auth]: [`internal/web/server.go`](../internal/web/server.go). Bearer extraction, token validation, same-origin checks, CSRF, and 401/403/429 handling.
[^auth-limiter]: [`internal/web/security.go`](../internal/web/security.go). Global/source-IP token buckets for failed authentication.
[^listener]: [`internal/web/security.go`](../internal/web/security.go). ACL listener before HTTP/TLS and connection-limit wrapper.
[^read-handlers]: [`internal/web/server.go`](../internal/web/server.go). Actual bootstrap/status/config response projections.
[^settings]: [`internal/web/server.go`](../internal/web/server.go). Settings request model, persistence, ACL/DNS application, and restart-required comparison.
[^rule-handlers]: [`internal/web/server.go`](../internal/web/server.go). Token rotation and Rule create/replace/delete handlers.
[^json]: [`internal/web/server.go`](../internal/web/server.go). 1 MiB limit, strict JSON decode, APIError, and response encoding.
[^tls]: [`internal/web/security.go`](../internal/web/security.go), [`internal/web/tls_owner_unix.go`](../internal/web/tls_owner_unix.go). TLS material loading/checking, minimum version, certificate status, Unix permissions, and ownership validation.
[^config-model]: [`internal/config/config.go`](../internal/config/config.go). Config, WebConfig, Rule, ResourceLimits, NFTConfig fields and JSON tags.
[^config-defaults]: [`internal/config/config.go`](../internal/config/config.go). Default configuration, load backfills, new-instance mark, and global budget defaults.
[^config-store]: [`internal/config/config.go`](../internal/config/config.go). Store.Get, locked update, validation, atomic file replacement, and failure fallback.
[^token-storage]: [`internal/config/config.go`](../internal/config/config.go). Token rotation transaction, local-file consistency, token/ID generation, and hashing.
[^normalize-rule]: [`internal/config/config.go`](../internal/config/config.go). Rule string normalization, numeric defaults, range endpoints, and Host-bracket handling.
[^config-validation]: [`internal/config/config.go`](../internal/config/config.go). Web/TLS/ACL/global resource/Rule validation and actual error strings.
[^normalize-lists]: [`internal/config/config.go`](../internal/config/config.go). Management allowlist, target CIDR, and DNS server normalization/count limits.
[^target-policy]: [`internal/config/config.go`](../internal/config/config.go). Target CIDR format, restricted-address set, and authorization evaluation order.
[^rule-conflicts]: [`internal/config/config.go`](../internal/config/config.go). Protocol, port, and address overlap checks between enabled rules.
[^config-clone]: [`internal/config/config.go`](../internal/config/config.go). Preservation of empty collections as arrays in configuration copies.
[^acl]: [`internal/acl/acl.go`](../internal/acl/acl.go). Effective ACL snapshot, loopback recovery, strict mode, auto-LAN behavior, and direct-source evaluation.
[^manager]: [`internal/proxy/manager.go`](../internal/proxy/manager.go). DNS configuration, Apply/Refresh, startup/retirement risk, Stats reuse, and runtime retention.
[^manager-runtime]: [`internal/proxy/manager.go`](../internal/proxy/manager.go). RuleRuntime fields/sorting and Go-runner existence checks.
[^kernel-state]: [`internal/proxy/manager_nft_state.go`](../internal/proxy/manager_nft_state.go). Runtime cleanup records, unknown state, kernel-state enum, and Go-path admission blocking.
[^plan]: [`internal/proxy/plan.go`](../internal/proxy/plan.go). Config/runtime data-plane enums, IPv4/IPv6 planning, DNS validation/cache, and worker allocation.
[^runner]: [`internal/proxy/manager.go`](../internal/proxy/manager.go). Go-runner startup, port-offset mapping, and bind errors.
[^stats]: [`internal/proxy/stats.go`](../internal/proxy/stats.go). All StatsSnapshot fields, running/started_at updates, and cumulative-counter snapshots.
[^telemetry]: [`internal/proxy/telemetry.go`](../internal/proxy/telemetry.go). TrafficSnapshot/TrafficSeries, hook counters, collection states, sampling and validity.
[^metrics]: [`internal/web/metrics.go`](../internal/web/metrics.go). Authenticated Prometheus response format, metric families, types, labels and unavailable-rate omission.
[^tcp-stats]: [`internal/proxy/tcp.go`](../internal/proxy/tcp.go). Admission counts, upstream dial, and byte aggregation after bidirectional copy completes.
[^udp-implementation]: [`internal/proxy/udp.go`](../internal/proxy/udp.go). Automatic workers, UDP packet filtering/drop/send counters, and maintenance aggregation.
[^budgets]: [`internal/proxy/budget.go`](../internal/proxy/budget.go). Shared source budgets across runners/workers/ports/address families and UDP token buckets.
[^udp-doc]: [`docs/udp-dataplane.md`](udp-dataplane.md) sections Scope and Defaults and capacity boundaries; [`README.md`](../README.md). Go/kernel counter and budget boundaries, defaults, and batch-send error semantics.
[^gui]: [`internal/web/static/app.js`](../internal/web/static/app.js) and [`i18n.js`](../internal/web/static/i18n.js). API client wrapper, bootstrap, 500 ms serialized status polling, complete settings/Rule submission, language selection, known-error translation, and local logout.
[^cli]: [`cmd/portbridge/main.go`](../cmd/portbridge/main.go). Default config/token paths and related startup flags.
[^deployment]: [`README.md`](../README.md), [`packaging/portbridge.service`](../packaging/portbridge.service). Installed native-HTTPS enforcement, certificate trust, and loopback recovery guidance.
[^main-refresh]: [`cmd/portbridge/main.go`](../cmd/portbridge/main.go). Initialization, 30-second Store snapshot refresh of ACL/rules, and shutdown signals.
