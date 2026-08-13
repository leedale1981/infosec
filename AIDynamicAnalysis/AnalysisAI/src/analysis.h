#ifndef ANALYSIS_H
#define ANALYSIS_H

#include <time.h>

typedef struct
{
    char *guid;
    char *session_dir;
    char *binary_path;
    char *ltrace_libs_output;
    char *ltrace_syscalls_output;
    // Human-readable description of the input that produced the retained traces
    // (e.g. "hello '; id'", "(no arguments)"). Owned by the session.
    char *chosen_input;
} AnalysisSession;

/// <summary>
/// How much of the target's own code the retained traces actually exercised.
/// </summary>
typedef enum
{
    COVERAGE_NONE = 0,   // Never got past loader/early return - no library calls captured
    COVERAGE_SHALLOW,    // Executed target code, but reached no dangerous operation
    COVERAGE_SINK        // Reached a dangerous sink (or crashed) - candidate vulnerable path
} CoverageLevel;

/// <summary>
/// Result of assessing execution coverage from ltrace output.
/// </summary>
typedef struct
{
    CoverageLevel level;
    int lib_call_count;   // Number of library-call lines observed
    char sink_hit[64];    // Name of the sink/signal that was reached (empty if none)
} CoverageInfo;

/// <summary>
/// Creates a new analysis session with a GUID-based directory
/// </summary>
/// <param name="binary_path">Path to the binary to analyze</param>
/// <returns>Pointer to new AnalysisSession or NULL on failure</returns>
AnalysisSession *analysis_create_session(const char *binary_path);

/// <summary>
/// Runs ltrace to capture library calls from the binary.
/// </summary>
/// <param name="session">The analysis session</param>
/// <param name="target_args">Shell-ready argument string appended after the
/// binary (already quoted by the caller). May be NULL or "" for no arguments.</param>
/// <returns>0 on success, non-zero on failure</returns>
int analysis_run_ltrace_libs(AnalysisSession *session, const char *target_args);

/// <summary>
/// Runs ltrace to capture system calls from the binary.
/// </summary>
/// <param name="session">The analysis session</param>
/// <param name="target_args">Shell-ready argument string appended after the
/// binary (already quoted by the caller). May be NULL or "" for no arguments.</param>
/// <returns>0 on success, non-zero on failure</returns>
int analysis_run_ltrace_syscalls(AnalysisSession *session, const char *target_args);

/// <summary>
/// Assesses how much of the target executed, based on ltrace output. Either
/// argument may be NULL (e.g. when only the library trace is available).
/// </summary>
/// <param name="libs_output">ltrace library-call output, or NULL</param>
/// <param name="syscalls_output">ltrace system-call output, or NULL</param>
/// <returns>A populated CoverageInfo describing the coverage observed</returns>
CoverageInfo analysis_assess_coverage(const char *libs_output,
                                      const char *syscalls_output);

/// <summary>
/// Drives the target binary to obtain a meaningful execution trace.
/// If user_args is non-NULL the binary is run once with exactly those arguments.
/// Otherwise the binary is fuzzed with a corpus of well-known argument payloads
/// (subcommand keywords, command-injection, format-string, overflow, traversal)
/// until a vulnerable code path is reached or the corpus is exhausted.
/// On return the session holds the traces for the chosen input.
/// </summary>
/// <param name="session">The analysis session</param>
/// <param name="user_args">Explicit argument string, or NULL to fuzz</param>
/// <param name="out_cov">Receives the coverage of the retained traces</param>
/// <param name="out_attempts">Receives the number of inputs tried (may be NULL)</param>
/// <returns>0 on success, non-zero on failure</returns>
int analysis_drive_binary(AnalysisSession *session, const char *user_args,
                          CoverageInfo *out_cov, int *out_attempts);

/// <summary>
/// Frees all resources associated with an analysis session
/// </summary>
/// <param name="session">The analysis session to free</param>
void analysis_free_session(AnalysisSession *session);

#endif // ANALYSIS_H
