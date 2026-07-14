namespace LD.Ai.Security.Api;

public sealed class GraphOptions
{
    public string TenantId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecret { get; set; } = string.Empty;
    public string SharePointHost { get; set; } = string.Empty;
    public string SitePath { get; set; } = string.Empty;
    public string LibraryName { get; set; } = string.Empty;
    public string? FolderPath { get; set; }

    public void Validate()
    {
        Require(TenantId, $"{nameof(GraphOptions)}:{nameof(TenantId)}");
        Require(ClientId, $"{nameof(GraphOptions)}:{nameof(ClientId)}");
        Require(ClientSecret, $"{nameof(GraphOptions)}:{nameof(ClientSecret)}");
        Require(SharePointHost, $"{nameof(GraphOptions)}:{nameof(SharePointHost)}");
        Require(SitePath, $"{nameof(GraphOptions)}:{nameof(SitePath)}");
        Require(LibraryName, $"{nameof(GraphOptions)}:{nameof(LibraryName)}");
    }

    private static void Require(string value, string key)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException($"Missing required configuration value '{key}'.");
        }
    }
}

public sealed class OllamaOptions
{
    public string BaseUrl { get; set; } = "http://localhost:11434";
    public string Model { get; set; } = "llama3.1";

    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(BaseUrl))
        {
            throw new InvalidOperationException($"Missing required configuration value '{nameof(OllamaOptions)}:{nameof(BaseUrl)}'.");
        }

        if (string.IsNullOrWhiteSpace(Model))
        {
            throw new InvalidOperationException($"Missing required configuration value '{nameof(OllamaOptions)}:{nameof(Model)}'.");
        }
    }
}
