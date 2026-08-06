#include "analysis.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <uuid/uuid.h>
#include <unistd.h>

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

// Helper function to extract filename from path
static char *extract_filename(const char *path)
{
    const char *filename = strrchr(path, '/');
    return filename ? (char *)(filename + 1) : (char *)path;
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

    return session;
}

int analysis_run_ltrace_libs(AnalysisSession *session)
{
    if (session == NULL || session->binary_path == NULL)
    {
        return -1;
    }

    char cmd[512];
    char output_file[256];

    // Create output file path
    snprintf(output_file, 256, "%s/ltrace_libs.txt", session->session_dir);

    // Run ltrace to capture library calls
    snprintf(cmd, 512, "ltrace -o %s %s 2>&1", output_file, session->binary_path);

    fprintf(stderr, "Running: %s\n", cmd);

    if (system(cmd) != 0)
    {
        fprintf(stderr, "Warning: ltrace execution completed with status (output may still be valid)\n");
    }

    // Read the output file
    session->ltrace_libs_output = read_file(output_file);
    if (session->ltrace_libs_output == NULL)
    {
        fprintf(stderr, "Warning: Could not read ltrace library output file\n");
        return -1;
    }

    return 0;
}

int analysis_run_ltrace_syscalls(AnalysisSession *session)
{
    if (session == NULL || session->binary_path == NULL)
    {
        return -1;
    }

    char cmd[512];
    char output_file[256];

    // Create output file path
    snprintf(output_file, 256, "%s/ltrace_syscalls.txt", session->session_dir);

    // Run ltrace to capture system calls with -S flag
    snprintf(cmd, 512, "ltrace -S -o %s %s 2>&1", output_file, session->binary_path);

    fprintf(stderr, "Running: %s\n", cmd);

    if (system(cmd) != 0)
    {
        fprintf(stderr, "Warning: ltrace execution completed with status (output may still be valid)\n");
    }

    // Read the output file
    session->ltrace_syscalls_output = read_file(output_file);
    if (session->ltrace_syscalls_output == NULL)
    {
        fprintf(stderr, "Warning: Could not read ltrace syscalls output file\n");
        return -1;
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

    free(session);
}
