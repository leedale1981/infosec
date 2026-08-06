# 🔍 AnalysisAI

AnalysisAI is a Linux console utility that performs dynamic binary analysis using `ltrace` and then sends the captured traces to an AI model for vulnerability review.

## ✨ What it does

- 🧪 Analyzes a binary executable passed on the command line
- 🔬 Runs `ltrace` twice:
  - once for library calls
  - once for system calls
- 📁 Saves both outputs into a new session folder named with a GUID
- 🧠 Builds a prompt from the captured traces
- 🤖 Sends the prompt to an AI provider such as OpenAI, Claude, or Copilot
- 📝 Produces a console summary and a `summary.md` report
- 🛡️ Assigns a risk profile and security grade to the analyzed binary

## 🚀 Features

- 🛡️ Security-oriented dynamic analysis
- 🔬 Library and system call tracing
- 🧠 AI-assisted vulnerability analysis
- 📁 Session-based output folders
- 📝 Markdown report generation
- 🖥️ Clean terminal-based ASCII banner

## ▶️ Usage

Run the program like this:

```bash
./AnalysisAI -b /path/to/binary -m openai -k your-api-key
```

### Arguments

- `-b, --binary` : path to the binary executable to analyze
- `-m, --model` : AI model type (`openai`, `claude`, `copilot`)
- `-k, --key` : API key for the selected AI model
- `-h, --help` : show help text

## 📌 Examples

```bash
./AnalysisAI -b /bin/ls -m openai -k sk-your-api-key
```

```bash
./AnalysisAI -b /usr/bin/curl -m claude -k sk-ant-your-api-key
```

## 📁 Output

Each run creates a new GUID-named directory containing:

- `ltrace_libs.txt`
- `ltrace_syscalls.txt`
- `summary.md`

## 🛠️ Build

From the project root:

```bash
make -f Makefile.quick rebuild
```

## ⚠️ Notes

- `ltrace` must be installed and available on your Linux system
- The binary must be executable and accessible
- AI analysis requires a valid API key and network access

## 🚀 Quick Start

```bash
cd /home/leedale/src/infosec/AIDynamicAnalysis/AnalysisAI
./AnalysisAI -h
```
