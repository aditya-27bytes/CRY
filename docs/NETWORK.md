# CRY Active Network Testing & Target Authorization Guide

## 1. Legal and Ethical Scanning Policy

CRY is designed to help indie developers and engineering teams audit their own systems and applications.

> [!IMPORTANT]
> **Strict Authorization Requirement:**
> CRY enforces a deterministic pre-flight authorization gate. Active network probes (TCP connections, TLS handshakes, HTTP security header evaluations) will **never** be dispatched against a public third-party host unless the operator has proven ownership and control of that target.

Probing computer systems without explicit, verifiable permission is illegal in many jurisdictions under computer crime statutes (e.g., US CFAA, UK Computer Misuse Act). CRY enforces authorization at the engine level to prevent unauthorized scanning.

---

## 2. Proof of Control & Target Authorization

Before CRY initiates active probes against any public domain or IP, it verifies proof of target ownership.

### How It Works

1. Run `cry net <target>`. If the target is not yet authorized, CRY issues a deterministic verification token:
   ```text
   cry-verify-xxxxxxxxxxxxxxxxxxxxxxxx
   ```
2. Choose one of two verification channels:
   - **DNS TXT Record:** Add a TXT record for your domain (or `_cry-challenge.<domain>`) containing:
     ```text
     cry-verification=cry-verify-xxxxxxxxxxxxxxxxxxxxxxxx
     ```
   - **HTTP Well-Known File:** Host a plain text file accessible over HTTP or HTTPS at:
     ```text
     https://<domain>/.well-known/cry-challenge.txt
     ```
     containing only the token string.
3. Validate and persist authorization locally:
   ```bash
   cry net <target> --authorize
   ```
4. Once verified, the authorization record is saved to your local `~/.cry/authorizations.json`. Subsequent scans of `<target>` proceed automatically.

---

## 3. Local Development Scanning (`--allow-local`)

To test locally hosted development servers, staging containers, or microservices:
- Targets resolving to loopback (`127.0.0.1`, `localhost`, `::1`) or private subnets (RFC-1918 `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, link-local `169.254.0.0/16`) are blocked by default to prevent accidental intranet probing.
- Pass the `--allow-local` flag to authorize active scanning of developer-controlled local machines:
  ```bash
  cry net localhost:8000 --allow-local
  cry net 127.0.0.1:3000 --allow-local
  ```

> [!CAUTION]
> **Cloud Instance Metadata (IMDS) Is Permanently Forbidden:**
> Cloud metadata IP addresses (`169.254.169.254`, `169.254.169.253`, and AWS IMDSv2 IPv6 `fd00:ec2::254`) are **never** probed under any circumstances, even if `--allow-local` is set. Probing cloud metadata risks accidental IAM role credential exposure and is blocked unconditionally.

---

## 4. Active Probing Capabilities

### A. TCP Port Reachability & Database Exposure Alerts
- **Default Port List:** Probes 15 essential development and service ports (`80`, `443`, `8080`, `8443`, `22`, `21`, `25`, `3000`, `5000`, `8000`, `3306`, `5432`, `6379`, `27017`, `9200`).
- **Custom Ports:** Use `--ports` / `-p` with comma-separated numbers or ranges (e.g. `--ports 80,443,8000-8010`). Probes are strictly capped at 100 ports maximum.
- **Rate Limiting & Timeouts:** Short socket connection timeouts (1.5s) and inter-probe rate delays (30ms) prevent denial-of-service on scanned endpoints.
- **Public Database Exposure:** If database or cache services (`PostgreSQL 5432`, `MySQL 3306`, `Redis 6379`, `MongoDB 27017`, `Elasticsearch 9200`) are found open on a public IP address, CRY raises a **CRITICAL / HIGH** severity alert recommending immediate VPC firewall ingress restrictions.

### B. TLS Review & Deprecated Cipher Analysis
- **Certificate Telemetry:** Checks certificate validity, remaining days before expiration, subject common name, issuer authority, and negotiated TLS version.
- **Weak Cipher Detection:** Flags weak or obsolete cipher suites (RC4, 3DES, DES, MD5, NULL, EXPORT, CBC).
- **Legacy Protocol Probe (`--deep`):** Probes whether the server negotiates deprecated TLS 1.0 or TLS 1.1 handshakes.
- **Platform Limitation Note:** Probing legacy TLS 1.0/1.1 protocols depends on the host system's OpenSSL configuration. If the client operating system enforces OpenSSL security level 2 (`SECLEVEL=2` or higher), the local crypto library refuses to initiate legacy handshakes. CRY documents this platform constraint transparently.

### C. HTTP Defense-in-Depth Headers & Edge CDN / WAF Ingress
- Evaluates 6 modern browser security headers (`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`).
- Inspects response headers to identify Edge CDN and WAF ingress platforms (Cloudflare, AWS CloudFront, Fastly, Akamai, Vercel, Netlify, Imperva, Envoy). Edge CDN detection is classified strictly as **INFORMATIONAL** metadata, never as a vulnerability.

### D. DNS Re-binding Protection
To prevent DNS-rebinding attacks where a public domain is abruptly pointed to an internal IP (e.g., `127.0.0.1` or `169.254.169.254`) between pre-flight authorization and socket connect, CRY re-resolves and validates the target IP immediately prior to each socket connection.

### E. Service Offline Detection
If the specified target port (e.g. `localhost:3001`) or default web ports (`80` / `443`) are closed or filtered, CRY identifies that the service is offline and reports `STATUS: SERVICE OFFLINE`. HTTP security header evaluation and SSL probes are skipped gracefully instead of misreporting missing headers with an artificial failing grade.


---

## 5. Local Audit Logging

Every authorized active network scan is recorded in an append-only audit log stored at:
```text
~/.cry/audit.log
```
Each entry captures:
- Timestamp (UTC ISO 8601)
- Target host and resolved IP address
- Checks executed (`dns`, `ports`, `tls`, `headers`, `deep_ports_and_ciphers`)
- Deep mode toggle (`is_deep`)
- Authorization status (`AUTHORIZED_LOCAL` or `AUTHORIZED_PUBLIC`)
- Local operating system user / caller identity

---

## 6. Observability Guarantee

> [!NOTE]
> **CRY Never Claims a Host Is "Secure":**
> Active network scans observe only exposed technical indicators and service responses at the exact moment of testing. CRY reports observable technical facts (open ports, header configurations, certificate attributes) and explicitly makes **no claim** that a target host is invulnerable or secure from compromise.
