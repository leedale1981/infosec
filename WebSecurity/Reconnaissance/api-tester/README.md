# AI API Tester: Endpoint Recon and Risk Analyzer

An AI-powered, colorful console app for API reconnaissance and pentest risk summarization.

It takes a base URL plus a line-delimited endpoint file, probes likely API/documentation/well-known routes, discovers additional endpoints from OpenAPI/Swagger docs, and reports:

- discovered endpoints and HTTP verb behavior
- likely accepted query parameters and JSON body fields
- documentation-derived endpoint expansion results
- AI-generated risk/vulnerability summary for pentesting
- source attribution for endpoint candidates

---

## ASCII Art (Because Recon Should Look Cool)

```text
       .-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-.
      /   API SCANNER DRONE :: RECON MODE :: ONLINE          \
     /_________________________________________________________\
            \      ^__^      /
             \____(oo)______/      [GET] [POST] [PUT] [PATCH]
             /----(__)----\        [HEAD] [OPTIONS] [DELETE]
          .-'  /|::::|\  '-.
         /    /_|::::|_\    \
        |  []   /____\   []  |      >>> Sweeping endpoint space...
        |_____________________|      >>> Mapping docs + well-known paths
            /_/      \_\
```

---

## What This AI Tool Does Exactly

1. Loads endpoint candidates from:

- local endpoint file (default: endpoint.txt)
- built-in curated security list (OWASP/PortSwigger-inspired docs + common API paths)
- optional remote public wordlists (SecLists, PortSwigger Param Miner, OWASP Amass)

2. Normalizes and deduplicates endpoint paths.

3. Probes each endpoint on the target base URL using likely HTTP verbs.

4. If documentation endpoints are found (OpenAPI/Swagger/ReDoc), it fetches and parses docs to discover additional API paths, then probes those discovered paths too.

5. Marks an endpoint as discovered when the response is not a plain 404/405 miss.

6. Performs lightweight parameter probing:

- GET: tests common query params like id, q, page, limit
- POST/PUT/PATCH: tests common JSON fields like id, name, email

7. Prints colorized console output:

- Green: 2xx
- Yellow: 401/403 (auth likely required)
- Red: other non-404/non-405 discovered responses

8. Optionally sends the full scan evidence to OpenAI and generates a structured pentest risk summary with:

- Executive Summary
- High/Medium/Low risk findings
- recommended next tests
- defensive remediation notes

---

## Installation

### Build From Source (Any Platform)

Requirements:

- Go 1.26+

From the project folder:

```bash
go mod tidy
go build -o dist/api-tester .
```

Or with Make targets:

```bash
make build
make test
```

### Build Release Artifacts (Binary + .deb)

This project includes a GoReleaser config that builds:

- Linux binaries (`tar.gz`)
- Windows binaries (`zip`)
- Debian package (`.deb`) for apt-based installs

Install GoReleaser, then run:

```bash
make release-snapshot
```

Artifacts are generated into `dist/`.

### Linux (APT Install)

Install from the published APT repository:

```bash
curl -fsSL https://leedale1981.github.io/infosec/apt/public.key \
  | sudo gpg --dearmor -o /usr/share/keyrings/api-tester-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/api-tester-archive-keyring.gpg arch=amd64,arm64] https://leedale1981.github.io/infosec/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/api-tester.list >/dev/null

sudo apt update
sudo apt install -y api-tester
```

If you already have a `.deb` artifact locally:

```bash
sudo apt install ./dist/api-tester_<version>_<arch>.deb
```

Install directly from a GitHub release using the helper script:

```bash
chmod +x scripts/install-apt.sh
./scripts/install-apt.sh 1.0.0 leedale1981/infosec
```

Arguments:

- `<version>`: release version without the `v` prefix (example: `1.0.0`)
- `[repo]`: optional GitHub repo in `owner/name` format (default: `leedale1981/infosec`)

### Windows (WinGet)

Install from WinGet:

```powershell
winget install --id leedale1981.api-tester --exact --source winget
```

Upgrade:

```powershell
winget upgrade --id leedale1981.api-tester --exact --source winget
```

### Windows (PowerShell Install Script)

Install the latest release:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

Install a specific version:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1 -Version 1.0.0 -Repo leedale1981/infosec
```

The script installs `api-tester.exe` into:

```text
%LOCALAPPDATA%\Programs\api-tester
```

and adds that directory to the user `PATH` if needed.

### Automated Publishing (All 3 Workflows)

This repo now supports three release/publish workflows:

1. Full publish: `.github/workflows/release-and-publish.yml`
2. APT-only republish: `.github/workflows/publish-apt-only.yml`
3. WinGet-only republish: `.github/workflows/publish-winget-only.yml`

#### 1) Full Publish (Recommended)

Tagging a version like `v1.0.0` triggers `.github/workflows/release-and-publish.yml`, which:

- builds and publishes release artifacts with GoReleaser
- updates the APT repo hosted on GitHub Pages (`gh-pages/apt`)
- submits a WinGet manifest update via `wingetcreate`

#### 2) APT-Only Republish

Use Actions -> `publish-apt-only` and provide `version` (for example `1.0.0`) to rebuild and republish only the APT repository from existing release `.deb` assets.

#### 3) WinGet-Only Republish

Use Actions -> `publish-winget-only` and provide `version` (for example `1.0.0`) to submit only the WinGet manifest update from the existing release Windows artifact.

Required repository configuration:

- Secret: `APT_GPG_PRIVATE_KEY` (ASCII-armored private key for signing APT metadata)
- Optional Secret: `APT_GPG_PASSPHRASE` (if the key is passphrase-protected)
- Secret: `WINGET_TOKEN` (GitHub token allowed to submit to `microsoft/winget-pkgs`)
- Optional Variable: `WINGET_PACKAGE_IDENTIFIER` (override default `leedale1981.api-tester`)

---

## Usage

Basic:

```bash
go run . https://target.example.com
```

With explicit endpoint file:

```bash
go run . https://target.example.com -f endpoint.txt
```

Disable remote wordlists (faster, offline-friendly):

```bash
go run . https://target.example.com --remote-lists=false
```

Tune timeout and remote list size:

```bash
go run . https://target.example.com -t 12 --remote-max-lines 400
```

Generate an AI-based pentest risk summary from scan results:

```bash
go run . https://target.example.com --with-ai YOUR_OPENAI_API_KEY
```

---

## CLI Arguments

Positional:

- base-url: target API root URL (required)

Flags:

- -f, --endpoints-file string (default: endpoint.txt)
  - line-delimited endpoint list
- -t, --timeout int (default: 8)
  - HTTP timeout in seconds
- --remote-lists bool (default: true)
  - include public SecLists/PortSwigger/OWASP wordlist sources
- --remote-max-lines int (default: 250)
  - max candidates loaded per remote list
- --with-ai string (default: "")
  - OpenAI API key to generate an AI risk/vulnerability summary for pentest reporting

---

## Endpoint File Format

Use one path per line:

```text
/swagger
/openapi/v1.json
/v3/api-docs
/.well-known/openid-configuration
/graphql
/health
```

Notes:

- Lines starting with # are treated as comments
- Empty lines are ignored
- Paths are normalized (leading slash enforced)

---

## Output Example

```text
Discovered Endpoints

https://target.example.com/swagger [OWASP API docs testing]
  GET -> 200
    query params: id, limit, page, q
    notes: Allow header: GET, OPTIONS

https://target.example.com/graphql [PortSwigger GraphQL testing]
  POST -> 401 (auth/authorization required)
    body fields: email, id, name
```

---

## Security and Scope Notes

This tool is for authorized testing only.
Always ensure you have explicit permission before scanning targets.

---

## Developer Notes

Architecture follows a layered, service-oriented approach:

- domain models for endpoint/discovery concepts
- application services for endpoint collection and scanning
- infrastructure adapters for HTTP, providers, and reporting

Unit tests exist for core services and providers.

Run tests:

```bash
go test ./...
```
