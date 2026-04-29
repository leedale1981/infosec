# API Tester: Endpoint Recon Scanner

A fast, colorful console app for API reconnaissance.

It takes a base URL plus a line-delimited endpoint file, probes likely API/documentation/well-known routes, and reports discovered endpoints with:

- HTTP method hints
- status code behavior
- likely accepted query parameters
- likely accepted JSON body fields
- source of the endpoint candidate list

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

## What This Tool Does Exactly

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

---

## Installation

Requirements:

- Go 1.26+

From the project folder:

```bash
go mod tidy
```

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
