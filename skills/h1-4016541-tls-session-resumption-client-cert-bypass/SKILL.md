---
name: tls-session-resumption-client-cert-bypass
description: Hunt mTLS authentication bypass where TLS session resumption (session ID/ticket cache) is not bound to the client certificate used, so a resumed session inherits the identity established under a different or absent certificate — including certs installed dynamically via SSL_CTX callbacks. Use for libcurl client, mTLS service, or TLS session-cache audits.
---

# TLS Session Resumption Client Cert Bypass

## 1 Trigger Conditions
- Client presents (or must present) a TLS client certificate: mTLS API, VPN, gRPC, IoT gateway, service mesh.
- One handle/process makes repeated connections to the same host and TLS sessions are cached by default (session ID or ticket).
- The client cert changes between requests: per-tenant certs, rotation, cert removed, or injected at runtime.
- Cert/key is installed via a callback rather than the primary cert option: `CURLOPT_SSL_CTX_FUNCTION`, `SSL_CTX_use_certificate*`, custom or shared SSL_CTX.
- The server may skip re-verifying the client cert when a session resumes (permitted by the TLS spec).

## 2 Root Cause Pattern
The session-cache lookup is keyed on host/port/scheme/TLS config but **not** on client-cert identity. The guard that disables resumption "when a client cert is used" reads only the primary cert option field; a cert applied later inside an SSL_CTX callback leaves that field empty, so the session stays resumable. The server resumes it and may reuse the previously authenticated identity without re-checking the client cert ⇒ authentication bypass by primary weakness (CWE-305). Same family as incomplete connection-reuse matching, where private-key/cert-type settings are omitted from the match.

## 3 Recon Checklist
- [ ] Find mTLS clients: `CURLOPT_SSLCERT`, `clientcert`, `SSL_CTX_use_certificate`, `CURLOPT_SSL_CTX_FUNCTION`.
- [ ] Grep resumption toggles: `CURLOPT_SSL_SESSIONID_CACHE`, `SSL_CTX_set_session_cache_mode`, `SSLSessionContext`, tickets, `CURLSSLOPT_EARLYDATA`.
- [ ] Is the cert set only in a callback or shared/cached SSL_CTX, not via the main cert option?
- [ ] Does the app change certs/keys per request while keeping a handle or connection pool alive?
- [ ] Server: mTLS terminator (nginx, Envoy, Java, Go), `ssl_verify_client`, ticket keys, OCSP stapling.
- [ ] Version check against curl advisories 7.50.1 / 7.54.0 / 8.21.0 and the connection-reuse series.

## 4 Hunt Methodology
1. Run a TLS server requiring a client cert, logging the peer cert and whether the handshake resumed (`openssl s_server -Verify 1`, log `SSL_session_reused`).
2. Baseline: handle + cert A → full handshake, identity A.
3. Probe: same handle/SSL_CTX with cert B (or none), especially via the SSL_CTX callback; force a new TCP connection but let the session cache be consulted.
4. Diff `SSL_session_reused()` / server logs: resumed *and* old identity = bypass.
5. Confirm the guard: primary cert option stops resumption; callback-installed cert does not.
6. Minimize and prove identity B obtained A's authorization; capture both handshakes.
7. Escalate: cross-tenant data, privilege retained after revocation, impersonation.

## 5 Payload Patterns
- Same easy handle and URL; swap SSL_CTX/callback cert between `curl_easy_perform` calls.
- `CURLOPT_SSL_CTX_FUNCTION` calling `SSL_CTX_use_certificate_chain_file`/`_PrivateKey`, with no `CURLOPT_SSLCERT` set.
- SSL_CTX shared across handles using different certs.
- Toggle `CURLOPT_SSL_SESSIONID_CACHE=0` to isolate behavior.
- Server side: replay a session ticket captured from the victim's authenticated connection.

## 6 WAF Bypass Tips
WAFs see valid TLS and a valid or absent client cert — nothing to block. Bypass is protocol/state level:
- Split the identity switch across connections so no single request looks anomalous.
- Resume the cached ticket before the cert change takes effect or before revocation propagates.
- If pinning is enforced, install the alternate cert via the callback path the pinning code does not inspect.
- Prefer TLS 1.3 tickets and early data to send bytes before cert verification completes.

## 7 Triage Guidance
- Real only with determinism: baseline (cert A, full handshake, identity A) vs probe (cert B, *resumed*, identity A). A resumed session alone is not a bug; the identity mix-up is.
- Capture server evidence (`SSL_session_reused` true, peer cert still A) and client handle state.
- Severity: High across a tenant/privilege boundary or past revocation; Medium for same-principal reuse; Low if no boundary depends on the cert.
- Reject: resumption disabled, cert set only via the guarded primary option, no cert change, or server re-verifies on resume.
- Report needs: versions, TLS backend, minimal reproducer, handshake logs, exact option/callback used.

## 8 Example
An app loads a unique client cert per tenant inside `CURLOPT_SSL_CTX_FUNCTION`. The resumption guard reads only the primary cert field, which is empty, so session caching stays on. Tenant B's request reuses tenant A's cached TLS session; the server resumes it and skips the client-cert check, serving A's data to B. Fix: disable resumption whenever any client cert/key is in play and include cert/key identity in session and connection match keys. Mitigation: `CURLOPT_SSL_SESSIONID_CACHE=0L`.
