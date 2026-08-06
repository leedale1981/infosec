#ifndef AI_CLIENT_H
#define AI_CLIENT_H

typedef enum
{
    AI_MODEL_OPENAI,
    AI_MODEL_CLAUDE,
    AI_MODEL_COPILOT,
    AI_MODEL_UNKNOWN
} AIModelType;

typedef struct
{
    AIModelType model_type;
    char *api_key;
    char *model_name;
    char *endpoint;
} AIClient;

/// <summary>
/// Parses the AI model type from a string argument
/// </summary>
/// <param name="model_str">String specifying model type (openai, claude, copilot)</param>
/// <returns>AIModelType enum value</returns>
AIModelType ai_parse_model_type(const char *model_str);

/// <summary>
/// Creates an AI client with the specified configuration
/// </summary>
/// <param name="model_type">Type of AI model to use</param>
/// <param name="api_key">API key for the model</param>
/// <returns>Pointer to new AIClient or NULL on failure</returns>
AIClient *ai_create_client(AIModelType model_type, const char *api_key);

/// <summary>
/// Sends a vulnerability analysis prompt to the AI model
/// </summary>
/// <param name="client">The AI client</param>
/// <param name="prompt">The analysis prompt to send</param>
/// <returns>AI response string or NULL on failure (caller must free)</returns>
char *ai_analyze_vulnerabilities(AIClient *client, const char *prompt);

/// <summary>
/// Frees all resources associated with an AI client
/// </summary>
/// <param name="client">The AI client to free</param>
void ai_free_client(AIClient *client);

#endif // AI_CLIENT_H
