#ifndef ANALYSIS_H
#define ANALYSIS_H

typedef struct
{
    char *guid;
    char *session_dir;
    char *binary_path;
    char *ltrace_libs_output;
    char *ltrace_syscalls_output;
} AnalysisSession;

AnalysisSession *analysis_create_session(const char *binary_path);
int analysis_run_ltrace_libs(AnalysisSession *session);
int analysis_run_ltrace_syscalls(AnalysisSession *session);
void analysis_free_session(AnalysisSession *session);

#endif // ANALYSIS_H
