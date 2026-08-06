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
} AnalysisSession;

/// <summary>
/// Creates a new analysis session with a GUID-based directory
/// </summary>
/// <param name="binary_path">Path to the binary to analyze</param>
/// <returns>Pointer to new AnalysisSession or NULL on failure</returns>
AnalysisSession *analysis_create_session(const char *binary_path);

/// <summary>
/// Runs ltrace to capture library calls from the binary
/// </summary>
/// <param name="session">The analysis session</param>
/// <returns>0 on success, non-zero on failure</returns>
int analysis_run_ltrace_libs(AnalysisSession *session);

/// <summary>
/// Runs ltrace to capture system calls from the binary
/// </summary>
/// <param name="session">The analysis session</param>
/// <returns>0 on success, non-zero on failure</returns>
int analysis_run_ltrace_syscalls(AnalysisSession *session);

/// <summary>
/// Frees all resources associated with an analysis session
/// </summary>
/// <param name="session">The analysis session to free</param>
void analysis_free_session(AnalysisSession *session);

#endif // ANALYSIS_H
