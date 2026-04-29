# Web Application Security

> Tools, techniques, and reference material for testing and understanding web application vulnerabilities. Covers reconnaissance, API scanning, injection attacks, authentication testing, and the core concepts behind web security assessments.

---

## Directory Structure

```
WebSecurity/
└── Reconnaissance/
    ├── api-tester/     — AI-powered API endpoint scanner (Go)
    └── README.md       — Burp Suite proxy setup, SQLi discovery, whatweb fingerprinting
```

---

## Core Concepts

| Concept | Description |
|---------|-------------|
| **CIA Triad** | Confidentiality, Integrity, Availability — the foundational security model |
| **Access Controls** | RBAC (Role-Based), MAC (Mandatory), DAC (Discretionary) |
| **Risk** | Threat modelling, likelihood × impact, liability |
| **Compliance** | Logging, audit trails, legal investigations |
| **Standards** | [NIST SSDF (SP 800-218)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf), [OWASP](https://owasp.org/), GDPR |

---

## Security Testing Approach

A structured methodology for web application penetration testing:

1. **Recon / Discovery** — fingerprint the stack, find endpoints, identify authentication mechanisms
2. **Authentication / Authorization attacks** — broken auth, session fixation, privilege escalation
3. **Business logic attacks** — price tampering, workflow bypasses, race conditions
4. **Technology-specific attacks** — CMS vulns, framework CVEs, misconfigured dependencies
5. **SSRF** — Server-Side Request Forgery to reach internal services
6. **Injection** — SQL, NoSQL, LDAP, command, template injection
7. **Vulnerability scanning** — automated scanning with Burp Suite Pro, OWASP ZAP, nuclei

---

## Tools

### AI API Scanner ([`Reconnaissance/api-tester/`](Reconnaissance/api-tester/))

An AI-powered, colourised console tool for API endpoint reconnaissance and pentest risk summarisation, written in **Go**.

Probes endpoints using OWASP/PortSwigger-inspired wordlists, discovers routes from live OpenAPI/Swagger docs, tests HTTP verbs per endpoint, and optionally generates an AI-powered risk summary via OpenAI.

```bash
go run . https://target.example.com --with-ai YOUR_OPENAI_API_KEY
```

See the [api-tester README](Reconnaissance/api-tester/README.md) for full usage details.

---

## Reconnaissance Reference ([`Reconnaissance/`](Reconnaissance/))

### Burp Suite Proxy — [portswigger.net/burp](https://portswigger.net/burp/documentation/desktop/tools/proxy)

1. Configure the Burp proxy listener (default: `127.0.0.1:8080`)
2. Point your browser's proxy settings at that address
3. Disable intercept to passively map traffic
4. Browse the application to populate the Site Map
5. Run `whatweb -v -a 3 <site_url>` to fingerprint the technology stack
6. Use Burp Scanner (Pro) or manually inspect requests for injection points

### SQL Injection Discovery

1. Find input fields: login forms, search boxes, URL parameters, JSON bodies
2. Test with `'`, `''`, `1=1`, `1=0`, `OR 1=1--`, `; DROP TABLE users--`
3. Observe error messages, timing differences (`SLEEP(5)`), and boolean response changes
4. Automate with `sqlmap`:
   ```bash
   sqlmap -u "https://target.com/search?q=test" --dbs
   sqlmap -r request.txt --level=5 --risk=3
   ```

### Common Tools

| Tool | Purpose |
|------|---------|
| [Burp Suite](https://portswigger.net/burp) | Intercepting proxy, scanner, repeater, intruder |
| [OWASP ZAP](https://www.zaproxy.org/) | Open-source web scanner |
| [whatweb](https://www.kali.org/tools/whatweb/) | Technology fingerprinting |
| [sqlmap](https://sqlmap.org/) | Automated SQL injection detection and exploitation |
| [ffuf](https://github.com/ffuf/ffuf) | Fast web fuzzer for directory and parameter discovery |
| [nuclei](https://github.com/projectdiscovery/nuclei) | Template-based vulnerability scanning |

---

## References

- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — free, practical vulnerability labs
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NIST SSDF (SP 800-218)](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-218.pdf)
