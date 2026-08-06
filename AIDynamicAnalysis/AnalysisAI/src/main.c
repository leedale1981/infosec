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
    AnalysisSession *session;
    AIClient *ai_client;
    VulnerabilityReport *report;
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
    printf("  -h, --help              Display this help message\n\n");
    printf("Example:\n");
    printf("  %s -b /path/to/binary -m openai -k sk-...\n", program_name);
    printf("  %s -b /usr/bin/curl -m claude -k sk-ant-...\n\n", program_name);
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
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    int opt;
    int option_index = 0;

    while ((opt = getopt_long(argc, argv, "b:m:k:h", long_options, &option_index)) != -1)
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

    // Run ltrace for library calls
    printf("[*] Executing ltrace (library calls)...\n");
    if (analysis_run_ltrace_libs(ctx->session) != 0)
    {
        fprintf(stderr, "Warning: ltrace library analysis completed with status\n");
    }
    printf("[✓] Library calls captured\n\n");

    // Run ltrace for system calls
    printf("[*] Executing ltrace (system calls)...\n");
    if (analysis_run_ltrace_syscalls(ctx->session) != 0)
    {
        fprintf(stderr, "Warning: ltrace syscalls analysis completed with status\n");
    }
    printf("[✓] System calls captured\n\n");

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

    // Create analysis prompt
    printf("[*] Generating analysis prompt...\n");
    char *prompt = vulnerability_create_prompt(binary_name,
                                                ctx->session->ltrace_libs_output,
                                                ctx->session->ltrace_syscalls_output);
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

    // Setup AI client with model type and API key
    if (setup_ai_client(&ctx) != 0)
    {
        cleanup_resources(&ctx);
        return 1;
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
