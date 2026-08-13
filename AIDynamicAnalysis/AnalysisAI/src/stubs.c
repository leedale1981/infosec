// Stub implementations for testing refactored main.c structure.
// Includes the real headers so the stub ABI always matches production.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uuid/uuid.h>
#include <sys/stat.h>
#include <unistd.h>

#include "analysis.h"
#include "ai_client.h"
#include "vulnerability_analyzer.h"

// ========== ANALYSIS STUBS ==========

AnalysisSession *analysis_create_session(const char *binary_path)
{
    if (binary_path == NULL || access(binary_path, F_OK) != 0)
    {
        fprintf(stderr, "Error: Binary file not found: %s\n", binary_path);
        return NULL;
    }

    AnalysisSession *session = malloc(sizeof(AnalysisSession));
    uuid_t binuuid;
    char *struuid = malloc(37);

    uuid_generate(binuuid);
    uuid_unparse(binuuid, struuid);

    session->guid = struuid;
    session->session_dir = malloc(256);
    snprintf(session->session_dir, 256, "./%s", session->guid);
    mkdir(session->session_dir, 0755);

    session->binary_path = malloc(strlen(binary_path) + 1);
    strcpy(session->binary_path, binary_path);

    session->ltrace_libs_output = malloc(1024);
    strcpy(session->ltrace_libs_output, "[ltrace library calls would be here]\n");

    session->ltrace_syscalls_output = malloc(1024);
    strcpy(session->ltrace_syscalls_output, "[ltrace system calls would be here]\n");

    session->chosen_input = NULL;

    return session;
}

int analysis_run_ltrace_libs(AnalysisSession *session, const char *target_args)
{
    (void)session;
    (void)target_args;
    return 0;
}

int analysis_run_ltrace_syscalls(AnalysisSession *session, const char *target_args)
{
    (void)session;
    (void)target_args;
    return 0;
}

CoverageInfo analysis_assess_coverage(const char *libs_output,
                                      const char *syscalls_output)
{
    (void)libs_output;
    (void)syscalls_output;
    CoverageInfo info;
    info.level = COVERAGE_SHALLOW;
    info.lib_call_count = 1;
    strcpy(info.sink_hit, "");
    return info;
}

int analysis_drive_binary(AnalysisSession *session, const char *user_args,
                          CoverageInfo *out_cov, int *out_attempts)
{
    free(session->chosen_input);
    session->chosen_input = strdup(user_args ? user_args : "(stub input)");
    if (out_cov != NULL)
    {
        *out_cov = analysis_assess_coverage(session->ltrace_libs_output,
                                            session->ltrace_syscalls_output);
    }
    if (out_attempts != NULL)
    {
        *out_attempts = 1;
    }
    return 0;
}

void analysis_free_session(AnalysisSession *session)
{
    if (session == NULL)
        return;
    free(session->guid);
    free(session->session_dir);
    free(session->binary_path);
    free(session->ltrace_libs_output);
    free(session->ltrace_syscalls_output);
    free(session->chosen_input);
    free(session);
}

// ========== AI CLIENT STUBS ==========

AIModelType ai_parse_model_type(const char *model_str)
{
    if (model_str == NULL)
        return AI_MODEL_UNKNOWN;

    if (strcasecmp(model_str, "openai") == 0)
        return AI_MODEL_OPENAI;
    else if (strcasecmp(model_str, "claude") == 0)
        return AI_MODEL_CLAUDE;
    else if (strcasecmp(model_str, "copilot") == 0)
        return AI_MODEL_COPILOT;

    return AI_MODEL_UNKNOWN;
}

AIClient *ai_create_client(AIModelType model_type, const char *api_key)
{
    if (api_key == NULL || model_type == AI_MODEL_UNKNOWN)
        return NULL;

    AIClient *client = malloc(sizeof(AIClient));
    client->model_type = model_type;
    client->api_key = malloc(strlen(api_key) + 1);
    strcpy(client->api_key, api_key);

    switch (model_type)
    {
    case AI_MODEL_OPENAI:
        client->model_name = malloc(16);
        strcpy(client->model_name, "gpt-4");
        client->endpoint = malloc(64);
        strcpy(client->endpoint, "https://api.openai.com/v1/chat/completions");
        break;
    case AI_MODEL_CLAUDE:
        client->model_name = malloc(32);
        strcpy(client->model_name, "claude-3-opus-20240229");
        client->endpoint = malloc(64);
        strcpy(client->endpoint, "https://api.anthropic.com/v1/messages");
        break;
    case AI_MODEL_COPILOT:
        client->model_name = malloc(32);
        strcpy(client->model_name, "gpt-4-turbo");
        client->endpoint = malloc(64);
        strcpy(client->endpoint, "https://api.openai.com/v1/chat/completions");
        break;
    default:
        free(client->api_key);
        free(client);
        return NULL;
    }

    return client;
}

char *ai_analyze_vulnerabilities(AIClient *client, const char *prompt)
{
    (void)client;
    (void)prompt;
    char *response = malloc(512);
    strcpy(response, "{\"risk_level\": \"medium\", \"grade\": \"B\", \"sources\": [], \"sinks\": []}");
    return response;
}

void ai_free_client(AIClient *client)
{
    if (client == NULL)
        return;
    free(client->api_key);
    free(client->model_name);
    free(client->endpoint);
    free(client);
}

// ========== VULNERABILITY ANALYZER STUBS ==========

char *vulnerability_create_prompt(const char *binary_name,
                                   const char *libs_output,
                                   const char *syscalls_output,
                                   const char *coverage_note)
{
    char *prompt = malloc(2048);
    snprintf(prompt, 2048,
             "Analyze binary %s for vulnerabilities\nCoverage: %s\nLibrary calls: %s\nSystem calls: %s",
             binary_name, coverage_note ? coverage_note : "n/a", libs_output, syscalls_output);
    return prompt;
}

VulnerabilityReport *vulnerability_create_inconclusive(const char *binary_name,
                                                        const char *coverage_note)
{
    (void)binary_name;
    VulnerabilityReport *report = malloc(sizeof(VulnerabilityReport));
    report->risk_level = RISK_LOW;
    report->grade = malloc(8);
    strcpy(report->grade, "N/A");
    report->summary = NULL;
    report->detailed_findings = malloc(256);
    strcpy(report->detailed_findings, "INCONCLUSIVE (stub): no coverage.");
    report->vulnerability_count = 0;
    report->inconclusive = 1;
    report->coverage_note = coverage_note ? strdup(coverage_note) : NULL;

    for (int i = 0; i < 50; i++)
    {
        report->potential_sources[i] = NULL;
        report->potential_sinks[i] = NULL;
    }

    return report;
}

VulnerabilityReport *vulnerability_parse_response(const char *ai_response,
                                                    const char *binary_name)
{
    (void)binary_name;
    VulnerabilityReport *report = malloc(sizeof(VulnerabilityReport));
    report->risk_level = RISK_MEDIUM;
    report->grade = malloc(32);
    strcpy(report->grade, "B");
    report->summary = malloc(256);
    strcpy(report->summary, "Sample vulnerability report");
    report->detailed_findings = malloc(strlen(ai_response) + 1);
    strcpy(report->detailed_findings, ai_response);
    report->vulnerability_count = 0;
    report->inconclusive = 0;
    report->coverage_note = NULL;

    for (int i = 0; i < 50; i++)
    {
        report->potential_sources[i] = NULL;
        report->potential_sinks[i] = NULL;
    }

    return report;
}

char *vulnerability_generate_summary(VulnerabilityReport *report)
{
    char *summary = malloc(8192);
    snprintf(summary, 8192,
             "╔════════════════════════════════════════════════════════════╗\n"
             "║           VULNERABILITY ANALYSIS REPORT                    ║\n"
             "╚════════════════════════════════════════════════════════════╝\n\n"
             "SECURITY RISK PROFILE\n"
             "━━━━━━━━━━━━━━━━━━━━━━\n"
             "%sSecurity Grade: %s\n"
             "Coverage: %s\n\n"
             "ANALYSIS DETAILS\n"
             "━━━━━━━━━━━━━━━━\n%s\n",
             report->inconclusive ? "Result: INCONCLUSIVE\n" : "Risk Level: MEDIUM\n",
             report->grade,
             report->coverage_note ? report->coverage_note : "n/a",
             report->detailed_findings);
    return summary;
}

int vulnerability_write_report(VulnerabilityReport *report, const char *output_path)
{
    FILE *file = fopen(output_path, "w");
    if (file == NULL)
    {
        fprintf(stderr, "Error: Could not open file for writing: %s\n", output_path);
        return -1;
    }

    fprintf(file, "# Security Vulnerability Analysis Report\n\n");
    fprintf(file, "## Risk Assessment\n\n");
    if (report->inconclusive)
    {
        fprintf(file, "> INCONCLUSIVE - no execution coverage.\n\n");
    }
    fprintf(file, "**Security Grade:** `%s`\n\n", report->grade);
    if (report->coverage_note)
    {
        fprintf(file, "**Execution Coverage:** %s\n\n", report->coverage_note);
    }
    fprintf(file, "## Detailed Analysis\n\n%s\n", report->detailed_findings);
    fprintf(file, "\n---\n*Report generated by AnalysisAI*\n");

    fclose(file);
    return 0;
}

void vulnerability_free_report(VulnerabilityReport *report)
{
    if (report == NULL)
        return;
    free(report->grade);
    free(report->summary);
    free(report->detailed_findings);
    free(report->coverage_note);

    for (int i = 0; i < 50; i++)
    {
        if (report->potential_sources[i] != NULL)
            free(report->potential_sources[i]);
        if (report->potential_sinks[i] != NULL)
            free(report->potential_sinks[i]);
    }

    free(report);
}
