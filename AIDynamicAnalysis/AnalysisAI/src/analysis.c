#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <unistd.h>

// Seconds to allow each traced run before timeout(1) kills it. Keeps the fuzzer
// from hanging on targets that block on stdin or loop forever.
#define TRACE_TIMEOUT_SECS 5

// Helper function to generate a UUID string
static char *generate_uuid(void)
{
    uuid_t binuuid;
    char *struuid = malloc(37); // UUID string is 36 chars + null terminator
    if (struuid == NULL)
    {
        return NULL;
    }
    uuid_generate(binuuid);
    uuid_unparse(binuuid, struuid);
    return struuid;
}

// Helper function to read file contents into a string
static char *read_file(const char *filepath)
{
    FILE *file = fopen(filepath, "r");
    if (file == NULL)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *content = malloc(file_size + 1);
    if (content == NULL)
    {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(content, 1, file_size, file);
    content[read_size] = '\0';
    fclose(file);

    return content;
}

// Wraps `arg` in single quotes, escaping any embedded single quotes, so it
// reaches the target as one literal argv element even when it contains shell
// metacharacters (essential when fuzzing with `; id`, `$(...)`, backticks, etc.).
// Returns a malloc'd string the caller must free. NULL is treated as "".
static char *shell_quote(const char *arg)
{
    if (arg == NULL)
    {
        arg = "";
    }

    // Worst case: every char is a single quote, expanding to 4 chars ('\'').
    size_t len = strlen(arg);
    char *out = malloc(len * 4 + 3);
    if (out == NULL)
    {
        return NULL;
    }

    size_t pos = 0;
    out[pos++] = '\'';
    for (size_t i = 0; i < len; i++)
    {
        if (arg[i] == '\'')
        {
            // Close quote, emit escaped quote, reopen quote: '\''
            out[pos++] = '\'';
            out[pos++] = '\\';
            out[pos++] = '\'';
            out[pos++] = '\'';
        }
        else
        {
            out[pos++] = arg[i];
        }
    }
    out[pos++] = '\'';
    out[pos] = '\0';
    return out;
}

// Builds and runs a traced invocation, writing ltrace output to `out_basename`
// inside the session directory and returning the captured trace (caller-owned)
// via *out_content. `extra_flag` is inserted into the ltrace command (e.g. "-S"
// for syscalls, "" for library calls). `target_args` is appended verbatim after
// "-- <binary>" and must already be shell-safe.
static int run_ltrace(AnalysisSession *session, const char *extra_flag,
                      const char *out_basename, const char *target_args,
                      char **out_content)
{
    if (session == NULL || session->binary_path == NULL)
    {
        return -1;
    }
    if (target_args == NULL)
    {
        target_args = "";
    }

    char output_file[512];
    snprintf(output_file, sizeof(output_file), "%s/%s", session->session_dir, out_basename);

    char *quoted_binary = shell_quote(session->binary_path);
    char *quoted_output = shell_quote(output_file);
    if (quoted_binary == NULL || quoted_output == NULL)
    {
        free(quoted_binary);
        free(quoted_output);
        return -1;
    }

    // timeout guards against hangs; stdin from /dev/null so interactive reads
    // get EOF; target stdout/stderr discarded so its own output does not spam
    // the console (ltrace still writes the trace to -o independently).
    size_t cmd_size = strlen(quoted_binary) + strlen(quoted_output) +
                      strlen(target_args) + strlen(extra_flag) + 128;
    char *cmd = malloc(cmd_size);
    if (cmd == NULL)
    {
        free(quoted_binary);
        free(quoted_output);
        return -1;
    }

    snprintf(cmd, cmd_size,
             "timeout %d ltrace %s -o %s -- %s %s < /dev/null > /dev/null 2>&1",
             TRACE_TIMEOUT_SECS, extra_flag, quoted_output, quoted_binary, target_args);

    if (system(cmd) != 0)
    {
        // Non-zero is expected (target may exit non-zero, crash, or time out);
        // the trace file is still usually valid, so we press on.
    }

    free(cmd);
    free(quoted_binary);
    free(quoted_output);

    char *content = read_file(output_file);
    if (out_content != NULL)
    {
        free(*out_content);
        *out_content = content;
    }
    else
    {
        free(content);
    }

    return (content == NULL) ? -1 : 0;
}

AnalysisSession *analysis_create_session(const char *binary_path)
{
    if (binary_path == NULL)
    {
        fprintf(stderr, "Error: binary_path cannot be NULL\n");
        return NULL;
    }

    // Check if binary exists and is executable
    if (access(binary_path, F_OK) != 0)
    {
        fprintf(stderr, "Error: Binary file not found: %s\n", binary_path);
        return NULL;
    }

    AnalysisSession *session = malloc(sizeof(AnalysisSession));
    if (session == NULL)
    {
        return NULL;
    }

    // Generate UUID for session directory
    session->guid = generate_uuid();
    if (session->guid == NULL)
    {
        free(session);
        return NULL;
    }

    // Create session directory
    session->session_dir = malloc(256);
    if (session->session_dir == NULL)
    {
        free(session->guid);
        free(session);
        return NULL;
    }

    snprintf(session->session_dir, 256, "./%s", session->guid);

    if (mkdir(session->session_dir, 0755) != 0)
    {
        fprintf(stderr, "Error: Failed to create session directory: %s\n", session->session_dir);
        free(session->guid);
        free(session->session_dir);
        free(session);
        return NULL;
    }

    // Duplicate binary path
    session->binary_path = malloc(strlen(binary_path) + 1);
    if (session->binary_path == NULL)
    {
        free(session->guid);
        free(session->session_dir);
        free(session);
        return NULL;
    }
    strcpy(session->binary_path, binary_path);

    session->ltrace_libs_output = NULL;
    session->ltrace_syscalls_output = NULL;
    session->chosen_input = NULL;

    return session;
}

int analysis_run_ltrace_libs(AnalysisSession *session, const char *target_args)
{
    return run_ltrace(session, "", "ltrace_libs.txt", target_args,
                      session ? &session->ltrace_libs_output : NULL);
}

int analysis_run_ltrace_syscalls(AnalysisSession *session, const char *target_args)
{
    return run_ltrace(session, "-S", "ltrace_syscalls.txt", target_args,
                      session ? &session->ltrace_syscalls_output : NULL);
}

// Dangerous library/system calls whose presence in a trace marks a reached sink.
// Matched in "name(" form so they anchor to an actual call, not to substrings
// that happen to appear inside a traced string argument or path.
static const char *COVERAGE_SINKS[] = {
    "system", "popen", "execl", "execlp", "execle", "execv", "execvp", "execve",
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "memcpy", "fork", "dlopen"
};
static const int COVERAGE_SINK_COUNT =
    sizeof(COVERAGE_SINKS) / sizeof(COVERAGE_SINKS[0]);

// Fatal-signal markers ltrace prints (e.g. "--- SIGSEGV ---"); a crash under
// fuzzing is itself strong evidence of a memory-safety vulnerability.
static const char *COVERAGE_SIGNALS[] = {"SIGSEGV", "SIGABRT", "SIGBUS", "SIGFPE"};
static const int COVERAGE_SIGNAL_COUNT =
    sizeof(COVERAGE_SIGNALS) / sizeof(COVERAGE_SIGNALS[0]);

// Counts library-call lines in an ltrace library trace. A call line begins with
// an identifier character and contains a '(' (e.g. `strcmp("a", "b") = 0`);
// loader/status lines ("+++ exited ...", "--- SIGSEGV ---") do not qualify.
static int count_lib_calls(const char *output)
{
    if (output == NULL)
    {
        return 0;
    }

    int count = 0;
    const char *line = output;
    while (*line != '\0')
    {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);

        // Skip leading whitespace
        size_t i = 0;
        while (i < len && isspace((unsigned char)line[i]))
        {
            i++;
        }
        if (i < len && (isalpha((unsigned char)line[i]) || line[i] == '_'))
        {
            if (memchr(line + i, '(', len - i) != NULL)
            {
                count++;
            }
        }

        if (end == NULL)
        {
            break;
        }
        line = end + 1;
    }
    return count;
}

CoverageInfo analysis_assess_coverage(const char *libs_output,
                                      const char *syscalls_output)
{
    CoverageInfo info;
    info.level = COVERAGE_NONE;
    info.lib_call_count = 0;
    info.sink_hit[0] = '\0';

    info.lib_call_count = count_lib_calls(libs_output);

    // Look for a reached sink or a crash signal across whichever traces we have.
    const char *sources[2] = {libs_output, syscalls_output};
    for (int s = 0; s < 2 && info.sink_hit[0] == '\0'; s++)
    {
        const char *text = sources[s];
        if (text == NULL)
        {
            continue;
        }

        for (int i = 0; i < COVERAGE_SIGNAL_COUNT; i++)
        {
            if (strstr(text, COVERAGE_SIGNALS[i]) != NULL)
            {
                snprintf(info.sink_hit, sizeof(info.sink_hit), "crash (%s)",
                         COVERAGE_SIGNALS[i]);
                break;
            }
        }
        if (info.sink_hit[0] != '\0')
        {
            break;
        }

        for (int i = 0; i < COVERAGE_SINK_COUNT; i++)
        {
            char token[64];
            snprintf(token, sizeof(token), "%s(", COVERAGE_SINKS[i]);
            if (strstr(text, token) != NULL)
            {
                snprintf(info.sink_hit, sizeof(info.sink_hit), "%s", COVERAGE_SINKS[i]);
                break;
            }
        }
    }

    if (info.sink_hit[0] != '\0')
    {
        info.level = COVERAGE_SINK;
    }
    else if (info.lib_call_count > 0)
    {
        info.level = COVERAGE_SHALLOW;
    }
    else
    {
        info.level = COVERAGE_NONE;
    }

    return info;
}

// ---------------------------------------------------------------------------
// Fuzzing corpus (used when no explicit --args is supplied)
// ---------------------------------------------------------------------------

// Common CLI subcommand / dispatch keywords. Many programs branch on argv[1]
// before doing anything interesting, so pairing these with payloads reaches
// code paths a single blind payload would miss.
static const char *FUZZ_KEYWORDS[] = {
    "hello", "bye", "help", "--help", "-h", "version", "--version",
    "test", "run", "list", "admin", "debug", "config", "0", "1"
};
static const int FUZZ_KEYWORD_COUNT =
    sizeof(FUZZ_KEYWORDS) / sizeof(FUZZ_KEYWORDS[0]);

// Payloads ordered so the highest-signal classes (command injection) come first,
// giving early-exit the best chance to stop quickly once a sink is reached.
static const char *FUZZ_PAYLOADS[] = {
    // Command injection
    "; id", "| id", "$(id)", "`id`", "&& id", "\n id",
    // Format string
    "%s%s%s%s%s%s%s%s", "%n%n%n%n", "%x%x%x%x%x%x",
    // Path traversal
    "../../../../../../../../etc/passwd",
    // Numeric / boundary
    "-1", "2147483648", "65536"
};
static const int FUZZ_PAYLOAD_COUNT =
    sizeof(FUZZ_PAYLOADS) / sizeof(FUZZ_PAYLOADS[0]);

// Overflow payload lengths (buffers of 'A') appended to the payload set.
static const int FUZZ_OVERFLOW_SIZES[] = {256, 1024, 4096};
static const int FUZZ_OVERFLOW_COUNT =
    sizeof(FUZZ_OVERFLOW_SIZES) / sizeof(FUZZ_OVERFLOW_SIZES[0]);

// Produces a short, printable label for an argument (long overflow buffers are
// collapsed to "AAAA...(xN)"). Returns a malloc'd string.
static char *make_label(const char *arg)
{
    size_t len = strlen(arg);
    if (len > 32)
    {
        char *label = malloc(48);
        if (label != NULL)
        {
            snprintf(label, 48, "%.8s...(x%zu)", arg, len);
        }
        return label;
    }
    char *label = malloc(len + 1);
    if (label != NULL)
    {
        strcpy(label, arg);
    }
    return label;
}

// Runs a library-only probe with the given already-quoted args and returns the
// coverage level observed (cheaper than also running the syscall trace).
static CoverageLevel probe_candidate(AnalysisSession *session, const char *quoted_args)
{
    if (analysis_run_ltrace_libs(session, quoted_args) != 0)
    {
        // No trace file; treat as no coverage but keep going.
        return COVERAGE_NONE;
    }
    CoverageInfo info = analysis_assess_coverage(session->ltrace_libs_output, NULL);
    return info.level;
}

// Considers one candidate; updates the running best. Returns 1 if a sink was
// reached (caller should stop fuzzing), 0 otherwise.
static int consider_candidate(AnalysisSession *session, const char *quoted_args,
                              const char *label, CoverageLevel *best,
                              char **best_args, char **best_label, int *attempts)
{
    (*attempts)++;
    CoverageLevel level = probe_candidate(session, quoted_args);
    if (level > *best)
    {
        *best = level;
        free(*best_args);
        free(*best_label);
        *best_args = strdup(quoted_args);
        *best_label = strdup(label);
    }
    return (level == COVERAGE_SINK) ? 1 : 0;
}

// Runs the fuzzing corpus. Leaves the best-covering quoted args in *best_args
// and a human label in *best_label (both caller-owned). Returns attempt count.
static int fuzz_corpus(AnalysisSession *session, char **best_args,
                       char **best_label, CoverageLevel *best_level)
{
    int attempts = 0;
    CoverageLevel best = COVERAGE_NONE;
    char *b_args = strdup("");
    char *b_label = strdup("(no arguments)");

    // Assemble the payload set: static payloads plus generated overflow buffers.
    int n_payloads = FUZZ_PAYLOAD_COUNT + FUZZ_OVERFLOW_COUNT;
    char **payloads = malloc(sizeof(char *) * n_payloads);
    if (payloads == NULL || b_args == NULL || b_label == NULL)
    {
        free(payloads);
        *best_args = b_args;
        *best_label = b_label;
        *best_level = best;
        return attempts;
    }
    for (int i = 0; i < FUZZ_PAYLOAD_COUNT; i++)
    {
        payloads[i] = strdup(FUZZ_PAYLOADS[i]);
    }
    for (int i = 0; i < FUZZ_OVERFLOW_COUNT; i++)
    {
        int size = FUZZ_OVERFLOW_SIZES[i];
        char *buf = malloc(size + 1);
        if (buf != NULL)
        {
            memset(buf, 'A', size);
            buf[size] = '\0';
        }
        payloads[FUZZ_PAYLOAD_COUNT + i] = buf;
    }

    int done = 0;

    // Stage 1: no arguments at all.
    done = consider_candidate(session, "", "(no arguments)", &best,
                              &b_args, &b_label, &attempts);

    // Stage 2: each keyword on its own (many tools dispatch on argv[1]).
    for (int k = 0; !done && k < FUZZ_KEYWORD_COUNT; k++)
    {
        char *q = shell_quote(FUZZ_KEYWORDS[k]);
        if (q != NULL)
        {
            done = consider_candidate(session, q, FUZZ_KEYWORDS[k], &best,
                                      &b_args, &b_label, &attempts);
            free(q);
        }
    }

    // Stage 3: each payload on its own.
    for (int p = 0; !done && p < n_payloads; p++)
    {
        if (payloads[p] == NULL)
        {
            continue;
        }
        char *q = shell_quote(payloads[p]);
        char *label = make_label(payloads[p]);
        if (q != NULL && label != NULL)
        {
            done = consider_candidate(session, q, label, &best,
                                      &b_args, &b_label, &attempts);
        }
        free(q);
        free(label);
    }

    // Stage 4: keyword x payload combinations (reaches guarded sub-paths such as
    // `prog hello <payload>`).
    for (int k = 0; !done && k < FUZZ_KEYWORD_COUNT; k++)
    {
        char *qk = shell_quote(FUZZ_KEYWORDS[k]);
        if (qk == NULL)
        {
            continue;
        }
        for (int p = 0; !done && p < n_payloads; p++)
        {
            if (payloads[p] == NULL)
            {
                continue;
            }
            char *qp = shell_quote(payloads[p]);
            if (qp != NULL)
            {
                size_t argl = strlen(qk) + strlen(qp) + 2;
                char *args = malloc(argl);
                char plabel[80];
                snprintf(plabel, sizeof(plabel), "%s %.40s", FUZZ_KEYWORDS[k], payloads[p]);
                if (args != NULL)
                {
                    snprintf(args, argl, "%s %s", qk, qp);
                    done = consider_candidate(session, args, plabel, &best,
                                              &b_args, &b_label, &attempts);
                    free(args);
                }
                free(qp);
            }
        }
        free(qk);
    }

    for (int i = 0; i < n_payloads; i++)
    {
        free(payloads[i]);
    }
    free(payloads);

    *best_args = b_args;
    *best_label = b_label;
    *best_level = best;
    return attempts;
}

int analysis_drive_binary(AnalysisSession *session, const char *user_args,
                          CoverageInfo *out_cov, int *out_attempts)
{
    if (session == NULL)
    {
        return -1;
    }

    CoverageInfo cov;

    if (user_args != NULL)
    {
        // Operator-supplied arguments: run exactly once, passed through as given.
        fprintf(stderr, "[*] Running target with supplied arguments\n");
        analysis_run_ltrace_libs(session, user_args);
        analysis_run_ltrace_syscalls(session, user_args);

        free(session->chosen_input);
        session->chosen_input = strdup(user_args[0] != '\0' ? user_args : "(no arguments)");

        cov = analysis_assess_coverage(session->ltrace_libs_output,
                                       session->ltrace_syscalls_output);
        if (out_attempts != NULL)
        {
            *out_attempts = 1;
        }
        if (out_cov != NULL)
        {
            *out_cov = cov;
        }
        return 0;
    }

    // No arguments supplied: fuzz until a vulnerable path is reached or the
    // corpus is exhausted.
    fprintf(stderr, "[*] No --args supplied; fuzzing target to find a live code path...\n");
    char *best_args = NULL;
    char *best_label = NULL;
    CoverageLevel best_level = COVERAGE_NONE;
    int attempts = fuzz_corpus(session, &best_args, &best_label, &best_level);

    fprintf(stderr, "[*] Fuzzing tried %d input(s); best coverage: %s\n", attempts,
            best_level == COVERAGE_SINK ? "reached a dangerous sink"
            : best_level == COVERAGE_SHALLOW ? "executed target code (no sink)"
                                             : "no meaningful execution");

    // Re-run the winning input to capture BOTH traces for the AI analysis.
    const char *final_args = (best_args != NULL) ? best_args : "";
    analysis_run_ltrace_libs(session, final_args);
    analysis_run_ltrace_syscalls(session, final_args);

    free(session->chosen_input);
    session->chosen_input = (best_label != NULL) ? best_label : strdup("(no arguments)");
    best_label = NULL; // ownership transferred to session

    free(best_args);

    cov = analysis_assess_coverage(session->ltrace_libs_output,
                                   session->ltrace_syscalls_output);
    if (out_attempts != NULL)
    {
        *out_attempts = attempts;
    }
    if (out_cov != NULL)
    {
        *out_cov = cov;
    }
    return 0;
}

void analysis_free_session(AnalysisSession *session)
{
    if (session == NULL)
    {
        return;
    }

    if (session->guid != NULL)
    {
        free(session->guid);
    }
    if (session->session_dir != NULL)
    {
        free(session->session_dir);
    }
    if (session->binary_path != NULL)
    {
        free(session->binary_path);
    }
    if (session->ltrace_libs_output != NULL)
    {
        free(session->ltrace_libs_output);
    }
    if (session->ltrace_syscalls_output != NULL)
    {
        free(session->ltrace_syscalls_output);
    }
    if (session->chosen_input != NULL)
    {
        free(session->chosen_input);
    }

    free(session);
}
