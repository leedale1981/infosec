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

AIModelType ai_parse_model_type(const char *model_str);
AIClient *ai_create_client(AIModelType model_type, const char *api_key);
char *ai_analyze_vulnerabilities(AIClient *client, const char *prompt);
void ai_free_client(AIClient *client);

#endif // AI_CLIENT_H
