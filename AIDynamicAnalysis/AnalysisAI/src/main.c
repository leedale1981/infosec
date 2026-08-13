#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "analysis.h"
#include "ai_client.h"
#include "vulnerability_analyzer.h"

// Application context structure
typedef struct
{
    char *binary_path;
    char *model_type_str;
    char *api_key;
    char *target_args;          // Explicit target arguments (--args), or NULL to fuzz
    AnalysisSession *session;
    AIClient *ai_client;
    VulnerabilityReport *report;
    CoverageInfo coverage;      // Coverage of the retained traces
    int fuzz_attempts;          // Number of inputs tried while driving the target
    char coverage_note[512];    // Human-readable coverage note for prompt/report
} AppContext;

// ASCII Art Banner
static void print_banner(void)
{
    printf("\n");
    printf("    ╔═══════════════════════════════════════════════════════╗\n");
    printf("    ║                                                       ║\n");
    printf("    ║     ███╗   ██╗ █████╗ ██╗     ██╗   ██╗███████╗██╗   ║\n");
    printf("    ║     ████╗  ██║██╔══██╗██║     ╚██╗ ██╔╝██╔════╝██║   ║\n");
    printf("    ║     ██╔██╗ ██║███████║██║      ╚████╔╝ ███████╗██║   ║\n");
    printf("    ║     ██║╚██╗██║██╔══██║██║       ╚██╔╝  ╚════██║██║   ║\n");
    printf("    ║     ██║ ╚████║██║  ██║███████╗  ██║   ███████║██║   ║\n");
    printf("    ║     ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝  ╚═╝   ╚══════╝╚═╝   ║\n");
    printf("    ║                                                       ║\n");
    printf("    ║        AI-Powered Binary Security Analyzer            ║\n");
    printf("    ║             Version 1.0 - Linux Edition               ║\n");
    printf("    ║                                                       ║\n");
    printf("    ╚═══════════════════════════════════════════════════════╝\n");
    printf("\n");
}

// Display usage information
static void print_usage(const char *program_name)
{
    printf("Usage: %s -b <binary> -m <model> -k <api_key> [options]\n\n", program_name);
    printf("Required Arguments:\n");
    printf("  -b, --binary <path>     Path to the binary executable to analyze\n");
    printf("  -m, --model <type>      AI model type (openai, claude, copilot)\n");
    printf("  -k, --key <api_key>     API key for the selected AI model\n\n");
    printf("Optional Arguments:\n");
    printf("  -a, --args <args>       Arguments to pass to the target binary when tracing.\n");
    printf("                          If omitted, the target is fuzzed with well-known\n");
    printf("                          payloads until a live/vulnerable code path is found.\n");
    printf("  -h, --help              Display this help message\n\n");
    printf("Example:\n");
    printf("  %s -b /path/to/binary -m openai -k sk-...\n", program_name);
    printf("  %s -b ./vuln -m claude -k sk-ant-... -a \"hello world\"\n", program_name);
    printf("  %s -b ./vuln -m claude -k sk-ant-...   (no -a: auto-fuzz)\n\n", program_name);
}

/// <summary>
/// Parses command-line arguments into the application context.
/// </summary>
/// <param name="argc">Argument count</param>
/// <param name="argv">Argument array</param>
/// <param name="ctx">Application context to populate</param>
/// <returns>0 on success, 1 on missing args, 2 on help requested</returns>
static int parse_command_line_arguments(int argc, char *argv[], AppContext *ctx)
{
    struct option long_options[] = {
        {"binary", required_argument, 0, 'b'},
        {"model", required_argument, 0, 'm'},
        {"key", required_argument, 0, 'k'},
        {"args", required_argument, 0, 'a'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "b:m:k:a:h", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
        case 'b':
            ctx->binary_path = optarg;
            break;
        case 'm':
            ctx->model_type_str = optarg;
            break;
        case 'k':
            ctx->api_key = optarg;
            break;
        case 'a':
            ctx->target_args = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 2;
        default:
            fprintf(stderr, "Error: Unknown option\n\n");
            print_usage(argv[0]);
            return 1;
        }
    }

    return 0;
}

/// <summary>
/// Validates that all required arguments are present.
/// </summary>
/// <param name="ctx">Application context to validate</param>
/// <param name="program_name">Program name for error messages</param>
/// <returns>0 on success, 1 on validation failure</returns>
static int validate_arguments(const AppContext *ctx, const char *program_name)
{
    if (ctx->binary_path == NULL || ctx->model_type_str == NULL || ctx->api_key == NULL)
    {
        fprintf(stderr, "Error: Missing required arguments\n\n");
        print_usage(program_name);
        return 1;
    }

    printf("┌─ Analyzing Binary ─────────────────────────────────────┐\n");
    printf("│ Binary Path: %s\n", ctx->binary_path);
    printf("│ Model Type:  %s\n", ctx->model_type_str);
    printf("└────────────────────────────────────────────────────────┘\n\n");

    return 0;
}

/// <summary>
/// Runs binary analysis using ltrace to capture library and system calls.
/// </summary>
/// <param name="ctx">Application context with session</param>
/// <returns>0 on success, non-zero on failure</returns>
static int run_binary_analysis(AppContext *ctx)
{
    printf("[*] Creating analysis session...\n");
    ctx->session = analysis_create_session(ctx->binary_path);
    if (ctx->session == NULL)
    {
        fprintf(stderr, "Fatal Error: Failed to create analysis session\n");
        return 1;
    }

    printf("[✓] Session created: %s\n", ctx->session->guid);
    printf("[*] Session directory: %s\n\n", ctx->session->session_dir);

    // Drive the target to obtain a meaningful trace: either with the supplied
    // --args, or by fuzzing until a live/vulnerable code path is reached.
    if (ctx->target_args != NULL)
    {
        printf("[*] Tracing target with supplied arguments: %s\n", ctx->target_args);
    }
    else
    {
        printf("[*] No --args supplied; fuzzing target to find a live code path...\n");
    }

    if (analysis_drive_binary(ctx->session, ctx->target_args,
                              &ctx->coverage, &ctx->fuzz_attempts) != 0)
    {
        fprintf(stderr, "Warning: binary analysis completed with status\n");
    }

    // Compose a human-readable coverage note used in the prompt and the report.
    const char *input = (ctx->session->chosen_input != NULL)
                            ? ctx->session->chosen_input
                            : "(unknown)";
    switch (ctx->coverage.level)
    {
    case COVERAGE_SINK:
        snprintf(ctx->coverage_note, sizeof(ctx->coverage_note),
                 "Reached a dangerous operation ('%s') after %d input(s). "
                 "Triggering input: %s. Library calls observed: %d.",
                 ctx->coverage.sink_hit, ctx->fuzz_attempts, input,
                 ctx->coverage.lib_call_count);
        break;
    case COVERAGE_SHALLOW:
        snprintf(ctx->coverage_note, sizeof(ctx->coverage_note),
                 "Target executed (%d library calls) but no dangerous sink was reached "
                 "across %d input(s). Input used: %s.",
                 ctx->coverage.lib_call_count, ctx->fuzz_attempts, input);
        break;
    case COVERAGE_NONE:
    default:
        snprintf(ctx->coverage_note, sizeof(ctx->coverage_note),
                 "No library calls were captured across %d input(s) - the target "
                 "returned or exited during startup without executing its own logic. "
                 "Last input tried: %s.",
                 ctx->fuzz_attempts, input);
        break;
    }

    printf("[✓] Trace captured (%s)\n", ctx->coverage_note);
    printf("\n");

    return 0;
}

/// <summary>
/// Initializes the AI client with the specified model type and API key.
/// </summary>
/// <param name="ctx">Application context</param>
/// <returns>0 on success, non-zero on failure</returns>
static int setup_ai_client(AppContext *ctx)
{
    AIModelType model_type = ai_parse_model_type(ctx->model_type_str);
    if (model_type == AI_MODEL_UNKNOWN)
    {
        fprintf(stderr, "Fatal Error: Unknown AI model type: %s\n", ctx->model_type_str);
        fprintf(stderr, "Supported models: openai, claude, copilot\n");
        return 1;
    }

    printf("[*] Initializing AI client...\n");
    ctx->ai_client = ai_create_client(model_type, ctx->api_key);
    if (ctx->ai_client == NULL)
    {
        fprintf(stderr, "Fatal Error: Failed to create AI client\n");
        return 1;
    }

    printf("[✓] AI client ready (%s)\n\n", ctx->ai_client->model_name);
    return 0;
}

/// <summary>
/// Extracts the binary filename from the full path.
/// </summary>
/// <param name="binary_path">Full path to binary</param>
/// <returns>Pointer to filename (basename) in the path</returns>
static char *extract_binary_name(const char *binary_path)
{
    char *filename = strrchr(binary_path, '/');
    return (filename == NULL) ? (char *)binary_path : (char *)filename + 1;
}

/// <summary>
/// Performs vulnerability analysis by sending traces to AI and parsing results.
/// </summary>
/// <param name="ctx">Application context</param>
/// <returns>0 on success, non-zero on failure</returns>
static int perform_vulnerability_analysis(AppContext *ctx)
{
    char *binary_name = extract_binary_name(ctx->binary_path);

    // If nothing of the target actually executed, do not ask the AI to judge an
    // empty trace (which yields a misleading "clean / grade A"). Report the run
    // as INCONCLUSIVE instead.
    if (ctx->coverage.level == COVERAGE_NONE)
    {
        printf("[!] No execution coverage obtained - marking analysis INCONCLUSIVE.\n");
        printf("    %s\n\n", ctx->coverage_note);
        ctx->report = vulnerability_create_inconclusive(binary_name, ctx->coverage_note);
        if (ctx->report == NULL)
        {
            fprintf(stderr, "Fatal Error: Failed to create inconclusive report\n");
            return 1;
        }
        return 0;
    }

    // Create analysis prompt
    printf("[*] Generating analysis prompt...\n");
    char *prompt = vulnerability_create_prompt(binary_name,
                                                ctx->session->ltrace_libs_output,
                                                ctx->session->ltrace_syscalls_output,
                                                ctx->coverage_note);
    if (prompt == NULL)
    {
        fprintf(stderr, "Fatal Error: Failed to create analysis prompt\n");
        return 1;
    }
    printf("[✓] Prompt generated\n\n");

    // Send to AI for analysis
    printf("[*] Sending to AI model for analysis...\n");
    char *ai_response = ai_analyze_vulnerabilities(ctx->ai_client, prompt);

    if (ai_response == NULL)
    {
        fprintf(stderr, "Fatal Error: AI analysis failed. Please check:\n");
        fprintf(stderr, "  1. API key is valid\n");
        fprintf(stderr, "  2. Network connection is available\n");
        fprintf(stderr, "  3. API service is not rate limited or down\n");
        free(prompt);
        return 1;
    }
    printf("[✓] Analysis received from AI\n\n");

    // Parse vulnerability report
    printf("[*] Parsing vulnerability analysis...\n");
    ctx->report = vulnerability_parse_response(ai_response, binary_name);
    if (ctx->report == NULL)
    {
        fprintf(stderr, "Warning: Could not parse AI response as JSON\n");
    }
    else
    {
        // Carry the observed coverage into the report for transparency.
        ctx->report->coverage_note = strdup(ctx->coverage_note);
    }
    printf("[✓] Report generated\n\n");

    free(prompt);
    free(ai_response);
    return 0;
}

/// <summary>
/// Generates console summary and saves markdown report to file.
/// </summary>
/// <param name="ctx">Application context</param>
/// <returns>0 on success, non-zero on failure</returns>
static int generate_and_save_reports(AppContext *ctx)
{
    // Generate and display console summary
    char *console_summary = vulnerability_generate_summary(ctx->report);
    printf("\n");
    printf("%s\n", console_summary);

    // Write markdown report
    char report_path[256];
    snprintf(report_path, 256, "%s/summary.md", ctx->session->session_dir);
    printf("\n[*] Writing markdown report...\n");
    if (vulnerability_write_report(ctx->report, report_path) == 0)
    {
        printf("[✓] Report saved to: %s\n", report_path);
    }
    else
    {
        fprintf(stderr, "Warning: Failed to write markdown report\n");
    }

    printf("\n[*] Analysis Complete!\n");
    printf("    Session ID: %s\n", ctx->session->guid);
    printf("    Output Directory: %s\n\n", ctx->session->session_dir);

    free(console_summary);
    return 0;
}

/// <summary>
/// Frees all allocated resources in the application context.
/// </summary>
/// <param name="ctx">Application context to cleanup</param>
void cleanup_resources(AppContext *ctx)
{
    if (ctx->session != NULL)
    {
        analysis_free_session(ctx->session);
    }
    if (ctx->ai_client != NULL)
    {
        ai_free_client(ctx->ai_client);
    }
    if (ctx->report != NULL)
    {
        vulnerability_free_report(ctx->report);
    }
}

/// <summary>
/// Main entry point for the AnalysisAI application.
/// Orchestrates the full vulnerability analysis workflow.
/// </summary>
int main(int argc, char *argv[])
{
    AppContext ctx = {0};

    print_banner();

    // Parse command-line arguments
    int parse_result = parse_command_line_arguments(argc, argv, &ctx);
    if (parse_result == 2)
    {
        // Help was requested
        return 0;
    }
    if (parse_result != 0)
    {
        return 1;
    }

    // Validate arguments
    if (validate_arguments(&ctx, argv[0]) != 0)
    {
        return 1;
    }

    // Run binary analysis with ltrace
    if (run_binary_analysis(&ctx) != 0)
    {
        cleanup_resources(&ctx);
        return 1;
    }

    // Setup AI client with model type and API key. Skipped when the target
    // produced no coverage - there is nothing for the AI to analyze.
    if (ctx.coverage.level != COVERAGE_NONE)
    {
        if (setup_ai_client(&ctx) != 0)
        {
            cleanup_resources(&ctx);
            return 1;
        }
    }

    // Perform vulnerability analysis
    if (perform_vulnerability_analysis(&ctx) != 0)
    {
        cleanup_resources(&ctx);
        return 1;
    }

    // Generate and save reports
    if (generate_and_save_reports(&ctx) != 0)
    {
        cleanup_resources(&ctx);
        return 1;
    }

    // Cleanup resources
    cleanup_resources(&ctx);

    printf("╔═══════════════════════════════════════════════════════╗\n");
    printf("║             Analysis Workflow Complete               ║\n");
    printf("╚═══════════════════════════════════════════════════════╝\n\n");

    return 0;
}
