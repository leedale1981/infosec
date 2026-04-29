# Web Reconnaissance

> Techniques and tooling for the initial reconnaissance phase of a web application security assessment. The goal is to map the application surface, fingerprint the technology stack, and identify entry points before active testing begins.

---

## Contents

- [`api-tester/`](api-tester/) — AI-powered API endpoint scanner (Go) — see its own README for full usage
- This file — manual reconnaissance techniques and tool usage

---

## Burp Suite Proxy — [portswigger.net/burp](https://portswigger.net/burp/documentation/desktop/tools/proxy)

### Basic Reconnaissance Workflow

1. Open Burp Suite and confirm the proxy listener is active (`Proxy → Options`, default `127.0.0.1:8080`)
2. Configure your browser to route traffic through that proxy
3. Set intercept to **off** to let traffic flow freely while Burp maps it passively
4. Browse the full application — every page, authenticated and unauthenticated
5. Review the **Target → Site Map** to see all discovered endpoints, parameters, and responses
6. Run `whatweb` to fingerprint the server-side stack:
   ```bash
   whatweb -v -a 3 <site_url_or_ip>
   ```
7. Check HTTP response headers for technology clues (`Server`, `X-Powered-By`, `Set-Cookie` names)

### Useful Burp Features for Recon

| Feature | Location | Use |
|---------|----------|-----|
| **Spider / Crawler** | Target → Scope | Automatically discover linked content |
| **Content Discovery** | Engagement Tools | Brute-force hidden paths from a wordlist |
| **Search** | Target → Site Map | Filter responses by status code, MIME type, keyword |
| **Passive Scanner** | Scanner (Pro) | Flag issues without sending any additional requests |

---

## Technology Fingerprinting

### whatweb

```bash
# Aggressive scan with full version detection
whatweb -v -a 3 https://target.example.com

# Output to JSON for further processing
whatweb -a 3 --log-json=output.json https://target.example.com
```

### Manual header inspection

```bash
curl -I https://target.example.com
```

Look for: `Server`, `X-Powered-By`, `X-Generator`, `X-AspNet-Version`, `Set-Cookie` naming conventions, and `Content-Security-Policy`.

### Wappalyzer

Browser extension that passively identifies frameworks, CMS, and analytics tools from page content and headers without sending any extra requests.

---

## Directory / Endpoint Discovery

```bash
# Fast fuzzing with ffuf
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
     -u https://target.example.com/FUZZ \
     -mc 200,301,302,403

# With extension discovery
ffuf -w wordlist.txt -u https://target.example.com/FUZZ \
     -e .php,.asp,.aspx,.jsp,.html,.txt,.bak

# gobuster alternative
gobuster dir -u https://target.example.com -w wordlist.txt -t 50
```

---

## SQL Injection Discovery

1. Identify all input vectors: URL parameters, form fields, JSON request bodies, HTTP headers (`User-Agent`, `Referer`, `Cookie`)
2. Test manually with:
   - `'` — triggers a syntax error in unparameterised queries
   - `''` — escaped quote, should return normally if the app sanitises
   - `1 AND 1=1` / `1 AND 1=2` — boolean-based blind detection
   - `'; WAITFOR DELAY '0:0:5'--` (MSSQL) / `'; SELECT SLEEP(5)--` (MySQL)
3. Automate with sqlmap:
   ```bash
   # Basic scan on a GET parameter
   sqlmap -u "https://target.com/page?id=1" --dbs

   # From a saved Burp request file
   sqlmap -r burp_request.txt --level=5 --risk=3 --batch

   # Dump a specific table
   sqlmap -u "https://target.com/page?id=1" -D dbname -T users --dump
   ```

---

## API-Specific Recon

See [`api-tester/`](api-tester/) for a purpose-built Go tool that:
- Probes common API path patterns (`/api/v1/`, `/graphql`, `/swagger.json`, etc.)
- Parses live OpenAPI/Swagger/ReDoc documentation to discover additional routes
- Tests all HTTP verbs per endpoint
- Optionally generates an AI-powered risk summary

For manual API recon:
```bash
# Check for exposed API documentation
curl https://target.com/swagger.json
curl https://target.com/api-docs
curl https://target.com/openapi.yaml
curl https://target.com/.well-known/

# Enumerate with a dedicated wordlist
ffuf -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
     -u https://target.com/FUZZ -mc 200,201,400,401,403
```

---

## References

- [PortSwigger Web Security Academy — Recon](https://portswigger.net/web-security/information-disclosure)
- [SecLists wordlists](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [whatweb](https://www.kali.org/tools/whatweb/)
- [ffuf](https://github.com/ffuf/ffuf)
