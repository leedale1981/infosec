# 🔍 AnalysisAI

**AnalysisAI** is a Linux console utility that performs **dynamic binary analysis**. It runs a target binary under `ltrace`, captures the library and system calls it makes, and sends those traces to an AI model (OpenAI, Claude, or Copilot) for a vulnerability review — producing a risk profile, a security grade, and a Markdown report.

Unlike static scanners, it reasons about what the binary **actually did at runtime**. And because a trace is only as useful as the code path it exercised, AnalysisAI can **drive the target itself** — either with arguments you supply, or by **fuzzing** it with well-known payloads until a vulnerable code path is reached.

---

## ✨ What it does

- 🧪 Runs a target binary under `ltrace`, capturing both **library calls** and **system calls**
- 🎯 **Drives the target** so the trace reflects real execution:
  - runs with **explicit arguments** you pass via `--args`, or
  - **fuzzes** the binary with a corpus of known attack payloads until a dangerous code path is hit
- 🧭 **Assesses coverage** — did the target actually execute its own logic, or exit immediately?
- 🧠 Builds a prompt from the captured traces and sends it to an AI provider
- 📝 Produces a console summary and a `summary.md` report with a **risk level** and **security grade**
- 📁 Saves every artifact into a per-run, GUID-named session folder

---

## 🚀 Features

| | |
|---|---|
| 🛡️ Security-oriented dynamic analysis | 🔬 Library **and** system call tracing |
| 🎯 `--args` passthrough to reach specific paths | 🧬 Automatic **fuzzing** when no args are given |
| 🧭 **Coverage gating** — no false "all clear" | 🧠 AI-assisted vulnerability review |
| 📁 Session-based output folders | 📝 Markdown report generation |

---

## ▶️ Usage

```bash
./AnalysisAI -b <binary> -m <model> -k <api_key> [-a "<target args>"]
```

### Arguments

| Flag | Long form | Required | Description |
|------|-----------|:--------:|-------------|
| `-b` | `--binary` | ✅ | Path to the binary executable to analyze |
| `-m` | `--model`  | ✅ | AI model type: `openai`, `claude`, or `copilot` |
| `-k` | `--key`    | ✅ | API key for the selected AI model |
| `-a` | `--args`   |   | Arguments to pass to the **target** binary when tracing. If omitted, the target is **fuzzed** automatically. |
| `-h` | `--help`   |   | Show help text |

---

## 🎯 Driving the target: `--args` and automatic fuzzing

A dynamic analyzer can only see the code that runs. If a binary needs a specific
subcommand or input to reach its interesting logic, tracing it with no arguments
tells you nothing.

**If you know the input**, supply it directly — it is passed to the target as-is:

```bash
./AnalysisAI -b ./vuln -m claude -k sk-ant-... -a "hello world"
```

**If you don't**, omit `-a` and AnalysisAI fuzzes the target with well-known
techniques until it reaches a dangerous operation (a *sink*) or exhausts the corpus:

- **Subcommand dictionary** — `hello`, `bye`, `help`, `version`, `admin`, `debug`, … (many CLIs branch on `argv[1]`)
- **Command injection** — `; id`, `| id`, `$(id)`, `` `id` ``, `&& id`, newline
- **Format string** — `%s%s%s…`, `%n%n…`, `%x%x…`
- **Path traversal** — `../../../../etc/passwd`
- **Buffer overflow** — 256 / 1024 / 4096-byte buffers
- **Combinations** — every keyword paired with every payload (this is what reaches guarded paths like `hello <payload>`)

Fuzz payloads are safely single-quoted before launch, so shell metacharacters
reach the target as **literal `argv`** — it is the target's *own* unsafe handling
that triggers the vulnerability, not the launching shell. Every run is wrapped in
a `timeout` with stdin from `/dev/null`, so a hanging or interactive target can't
stall the fuzzer.

---

## 🧭 Coverage gating (no false "all clear")

AnalysisAI classifies how much of the target actually ran:

| Coverage | Meaning | Outcome |
|----------|---------|---------|
| **SINK** | Reached a dangerous call (or crashed) | Full AI analysis; the triggering input is reported |
| **SHALLOW** | Executed target code, but no sink | Full AI analysis, with the coverage noted |
| **NONE** | Never got past process startup | **INCONCLUSIVE** report — the AI is *not* asked, and the run is **not** graded "A" |

This closes a common trap: a binary that exits immediately produces an empty
trace, which naïvely looks like a clean, grade-A result. AnalysisAI instead
reports it as **INCONCLUSIVE** and tells you to re-run with `--args`.

---

## 🧪 Walkthrough: catching a command-injection bug

Consider this deliberately vulnerable program (`vuln.c`):

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
    char command[100];

    if (argc < 2) {
        return 1;
    }

    if (strcmp(argv[1], "hello") == 0) {
        if (argc != 3) {
            return 1;
        }
        snprintf(command, sizeof(command), "echo Hello, %s", argv[2]);
        system(command);          // ⚠️ argv[2] flows unsanitized into a shell
    } else if (strcmp(argv[1], "bye") == 0) {
        printf("bye bye\n");
    } else {
        printf("Invalid option\n");
    }

    return 0;
}
```

The flaw: `argv[2]` is concatenated straight into a string that is handed to
`system()`. Anything the shell treats as a command separator — `;`, `|`,
`$(...)`, backticks — runs as a **command injection**. But the sink is
**guarded**: you only reach `system()` when `argv[1]` is exactly `hello` **and**
there are exactly three arguments. Tracing `./a.out` with no input never gets
there — it hits `argc < 2` and returns immediately (an **INCONCLUSIVE** result).

Compile it and point AnalysisAI at it **with no `--args`**, letting the fuzzer
find the path:

```bash
gcc -o a.out vuln.c
./AnalysisAI -b ./a.out -m openai -k sk-your-api-key
```

### 1. Fuzzing finds the vulnerable path

With no arguments supplied, AnalysisAI fuzzes the binary. On the **33rd** input
it pairs the subcommand keyword `hello` with the command-injection payload
`; id`, satisfying the `argv[1] == "hello"` / `argc == 3` guard and reaching the
`system()` sink:

![AnalysisAI fuzzing the vulnerable binary and reaching the system() sink](images/Screenshot%202026-08-13%20132537.png)

> `Fuzzing tried 33 input(s); best coverage: reached a dangerous sink`
> `Trace captured (Reached a dangerous operation ('system') after 33 input(s). Triggering input: hello ; id. Library calls observed: 3.)`

The captured `ltrace_libs.txt` shows exactly why:

```text
strcmp("hello", "hello")                              = 0
snprintf("echo Hello, ; id", 100, "echo Hello, %s", "; id") = 16
system("echo Hello, ; id" <no return ...>
```

### 2. The AI report catches the vulnerability

The traces (plus the coverage note) are sent to the model, which identifies the
command-injection vulnerability and grades it:

![AnalysisAI vulnerability report: CRITICAL, grade F, command injection via system()](images/Screenshot%202026-08-13%20132249.png)

> **Risk Level:** `CRITICAL` &nbsp;•&nbsp; **Security Grade:** `F`
> **Source:** User input &nbsp;•&nbsp; **Sink:** `system()` &nbsp;•&nbsp; **Vector:** Command injection via user input

The same result is written to `summary.md` in the session folder, with
remediation guidance (sanitize/validate input, avoid `system()`, use
parameterized execution).

---

## 📁 Output

Each run creates a new GUID-named directory in the current working directory containing:

- `ltrace_libs.txt` — captured library calls
- `ltrace_syscalls.txt` — captured system calls
- `summary.md` — the Markdown vulnerability report

---

## 🛠️ Build

Dependencies (Ubuntu/Debian) — `gcc`, `libuuid`, `libcurl`, `libcjson`, and the `ltrace` + `timeout` runtime tools:

```bash
cd AnalysisAI
make install-deps      # one-time: installs build + runtime dependencies
```

Build the full analyzer (with live AI integration):

```bash
cd AnalysisAI
make                   # produces ./AnalysisAI
```

Or build the stub version (mocked AI/trace, for testing the workflow without an API key or dependencies):

```bash
cd AnalysisAI
make -f Makefile.quick
```

---

## ⚠️ Notes

- `ltrace` and `timeout` (coreutils) must be installed and available on your Linux system
- The target binary must be executable and accessible
- AI analysis requires a valid API key and network access
- Fuzzing currently drives the target via **command-line arguments**; binaries that take input only from **stdin or files** are best analyzed by pointing `--args` at an input file

---

## 🚀 Quick start

```bash
cd AnalysisAI
make
./AnalysisAI -h
```
