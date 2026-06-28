using System.Net.Http.Json;
using System.Text.Json.Serialization;

public sealed class LocalLlmClient(HttpClient http, IConfiguration config)
{
    public async Task<string> GenerateAsync(string prompt, CancellationToken ct = default)
    {
        var baseUrl = config["Ollama:BaseUrl"] ?? "http://localhost:11434";
        var model = config["Ollama:Model"] ?? "llama3.1";

        var response = await http.PostAsJsonAsync(
            $"{baseUrl}/api/generate",
            new
            {
                model,
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