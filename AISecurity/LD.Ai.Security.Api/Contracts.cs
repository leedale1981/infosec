namespace LD.Ai.Security.Api;

public interface IDocumentRetriever
{
    Task<IReadOnlyList<RetrievedDocument>> RetrieveAsync(string question, CancellationToken ct = default);
}

public interface IRetrievalScorer
{
    int Score(string question, string content, string name);
}

public interface IPromptInjectionScanner
{
    bool LooksSuspicious(string text);
}

public interface IFileTextExtractor
{
    bool CanExtract(string fileName);
    Task<string> ExtractAsync(Stream stream, CancellationToken ct);
}

public interface IDocumentTextExtractor
{
    bool CanExtract(string fileName);
    Task<string> ExtractAsync(string fileName, Stream stream, CancellationToken ct);
}

public interface ITextGenerationClient
{
    Task<string> GenerateAsync(string prompt, CancellationToken ct = default);
}

public interface IRagPromptBuilder
{
    string Mode { get; }
    string Build(string question, IReadOnlyList<RetrievedDocument> documents, IReadOnlyList<RetrievedDocument>? excludedDocuments = null);
}

public interface IRagQueryService
{
    Task<RagResponse> AskVulnerableAsync(string question, CancellationToken ct = default);
    Task<RagResponse> AskHardenedAsync(string question, CancellationToken ct = default);
    Task<ScannedResponse> AskScannedAsync(string question, CancellationToken ct = default);
}
