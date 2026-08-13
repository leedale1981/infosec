#include "ai_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>

// Memory buffer for curl response
typedef struct
{
    char *data;
    size_t size;
} ResponseBuffer;

// Callback for curl to write response data
// Signature must match libcurl's curl_write_callback typedef exactly
static size_t response_write_callback(char *contents, size_t size, size_t nmemb, void *userdata)
{
    ResponseBuffer *userp = (ResponseBuffer *)userdata;
    size_t realsize = size * nmemb;
    char *ptr = realloc(userp->data, userp->size + realsize + 1);

    if (ptr == NULL)
    {
        fprintf(stderr, "Error: Not enough memory for curl response\n");
        return 0;
    }

    userp->data = ptr;
    memcpy(&(userp->data[userp->size]), contents, realsize);
    userp->size += realsize;
    userp->data[userp->size] = 0;

    return realsize;
}

// Helper to convert string to lowercase
static char *str_tolower(const char *str)
{
    char *result = malloc(strlen(str) + 1);
    if (result == NULL)
    {
        return NULL;
    }

    for (size_t i = 0; str[i]; i++)
    {
        result[i] = tolower(str[i]);
    }
    result[strlen(str)] = '\0';

    return result;
}

AIModelType ai_parse_model_type(const char *model_str)
{
    if (model_str == NULL)
    {
        return AI_MODEL_UNKNOWN;
    }

    char *lower = str_tolower(model_str);
    if (lower == NULL)
    {
        return AI_MODEL_UNKNOWN;
    }

    AIModelType type = AI_MODEL_UNKNOWN;

    if (strcmp(lower, "openai") == 0)
    {
        type = AI_MODEL_OPENAI;
    }
    else if (strcmp(lower, "claude") == 0)
    {
        type = AI_MODEL_CLAUDE;
    }
    else if (strcmp(lower, "copilot") == 0)
    {
        type = AI_MODEL_COPILOT;
    }

    free(lower);
    return type;
}

AIClient *ai_create_client(AIModelType model_type, const char *api_key)
{
    if (api_key == NULL || model_type == AI_MODEL_UNKNOWN)
    {
        fprintf(stderr, "Error: Invalid model type or API key\n");
        return NULL;
    }

    AIClient *client = malloc(sizeof(AIClient));
    if (client == NULL)
    {
        return NULL;
    }

    client->model_type = model_type;
    client->api_key = malloc(strlen(api_key) + 1);
    if (client->api_key == NULL)
    {
        free(client);
        return NULL;
    }

    strcpy(client->api_key, api_key);

    // Set model-specific configurations
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

// Send request to OpenAI API
static char *ai_call_openai(AIClient *client, const char *prompt)
{
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        return NULL;
    }

    // Prepare JSON payload
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "model", client->model_name);

    cJSON *messages = cJSON_CreateArray();
    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "role", "user");
    cJSON_AddStringToObject(message, "content", prompt);
    cJSON_AddItemToArray(messages, message);

    cJSON_AddItemToObject(root, "messages", messages);
    cJSON_AddNumberToObject(root, "temperature", 0.7);
    cJSON_AddNumberToObject(root, "max_tokens", 2000);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    // Setup curl options
    ResponseBuffer response = {NULL, 0};

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    char auth_header[512];
    snprintf(auth_header, 512, "Authorization: Bearer %s", client->api_key);
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, client->endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    // Execute request
    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "Error: CURL request failed: %s\n", curl_easy_strerror(res));
        free(response.data);
        response.data = NULL;
    }
    else
    {
        // Parse response to extract message content
        cJSON *response_json = cJSON_Parse(response.data);
        if (response_json != NULL)
        {
            cJSON *choices = cJSON_GetObjectItem(response_json, "choices");
            if (choices != NULL && cJSON_GetArraySize(choices) > 0)
            {
                cJSON *first_choice = cJSON_GetArrayItem(choices, 0);
                cJSON *message_obj = cJSON_GetObjectItem(first_choice, "message");
                cJSON *content = cJSON_GetObjectItem(message_obj, "content");

                if (content != NULL && content->valuestring != NULL)
                {
                    char *result = malloc(strlen(content->valuestring) + 1);
                    strcpy(result, content->valuestring);
                    free(response.data);
                    response.data = result;
                }
            }
            cJSON_Delete(response_json);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_str);

    return response.data;
}

// Send request to Claude API
static char *ai_call_claude(AIClient *client, const char *prompt)
{
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        return NULL;
    }

    // Prepare JSON payload for Claude
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "model", client->model_name);
    cJSON_AddNumberToObject(root, "max_tokens", 2000);

    cJSON *messages = cJSON_CreateArray();
    cJSON *message = cJSON_CreateObject();
    cJSON_AddStringToObject(message, "role", "user");
    cJSON_AddStringToObject(message, "content", prompt);
    cJSON_AddItemToArray(messages, message);

    cJSON_AddItemToObject(root, "messages", messages);

    char *json_str = cJSON_Print(root);
    cJSON_Delete(root);

    ResponseBuffer response = {NULL, 0};

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, "anthropic-version: 2023-06-01");

    char auth_header[512];
    snprintf(auth_header, 512, "x-api-key: %s", client->api_key);
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, client->endpoint);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_str);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, response_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&response);

    CURLcode res = curl_easy_perform(curl);

    if (res != CURLE_OK)
    {
        fprintf(stderr, "Error: CURL request failed: %s\n", curl_easy_strerror(res));
        free(response.data);
        response.data = NULL;
    }
    else
    {
        cJSON *response_json = cJSON_Parse(response.data);
        if (response_json != NULL)
        {
            cJSON *content_array = cJSON_GetObjectItem(response_json, "content");
            if (content_array != NULL && cJSON_GetArraySize(content_array) > 0)
            {
                cJSON *first_content = cJSON_GetArrayItem(content_array, 0);
                cJSON *text = cJSON_GetObjectItem(first_content, "text");

                if (text != NULL && text->valuestring != NULL)
                {
                    char *result = malloc(strlen(text->valuestring) + 1);
                    strcpy(result, text->valuestring);
                    free(response.data);
                    response.data = result;
                }
            }
            cJSON_Delete(response_json);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json_str);

    return response.data;
}

char *ai_analyze_vulnerabilities(AIClient *client, const char *prompt)
{
    if (client == NULL || prompt == NULL)
    {
        return NULL;
    }

    switch (client->model_type)
    {
    case AI_MODEL_OPENAI:
    case AI_MODEL_COPILOT:
        return ai_call_openai(client, prompt);

    case AI_MODEL_CLAUDE:
        return ai_call_claude(client, prompt);

    default:
        return NULL;
    }
}

void ai_free_client(AIClient *client)
{
    if (client == NULL)
    {
        return;
    }

    if (client->api_key != NULL)
    {
        free(client->api_key);
    }
    if (client->model_name != NULL)
    {
        free(client->model_name);
    }
    if (client->endpoint != NULL)
    {
        free(client->endpoint);
    }

    free(client);
}
