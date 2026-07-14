using System.Net.Http.Json;
using System.Text.Json.Serialization;
using LD.Ai.Security.Api;
using Microsoft.Extensions.Options;

public sealed class LocalLlmClient(HttpClient http, IOptions<OllamaOptions> options)
    : ITextGenerationClient
{
    public async Task<string> GenerateAsync(string prompt, CancellationToken ct = default)
    {
        var settings = options.Value;
        settings.Validate();

        var response = await http.PostAsJsonAsync(
            $"{settings.BaseUrl.TrimEnd('/')}/api/generate",
            new
            {
                model = settings.Model,
                prompt,
                stream = false
            },
            ct);

        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<OllamaResponse>(cancellationToken: ct);

        return body?.Response?.Trim() ?? string.Empty;
    }

    private sealed class OllamaResponse
    {
        [JsonPropertyName("response")]
        public string Response { get; set; } = string.Empty;
    }
}