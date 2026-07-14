namespace LD.Ai.Security.Api;

public sealed class RagQueryService(
    IDocumentRetriever retriever,
    IEnumerable<IRagPromptBuilder> promptBuilders,
    ITextGenerationClient llmClient)
    : IRagQueryService
{
    private readonly IReadOnlyDictionary<string, IRagPromptBuilder> _promptBuilders = promptBuilders
        .ToDictionary(builder => builder.Mode, StringComparer.OrdinalIgnoreCase);

    public async Task<RagResponse> AskVulnerableAsync(string question, CancellationToken ct = default)
    {
        return await AskAsync(RagModes.Vulnerable, question, ct);
    }

    public async Task<RagResponse> AskHardenedAsync(string question, CancellationToken ct = default)
    {
        return await AskAsync(RagModes.Hardened, question, ct);
    }

    public async Task<ScannedResponse> AskScannedAsync(string question, CancellationToken ct = default)
    {
        var docs = await retriever.RetrieveAsync(question, ct);
        var suspiciousDocs = docs.Where(d => d.LooksSuspicious).ToList();
        var safeDocs = docs.Where(d => !d.LooksSuspicious).ToList();

        if (suspiciousDocs.Count > 0 && safeDocs.Count == 0)
        {
            return new ScannedResponse(
                RagModes.Scanned,
                question,
                true,
                "All retrieved documents looked suspicious.",
                suspiciousDocs.Select(d => d.Name).ToList(),
                null,
                null);
        }

        var prompt = GetPromptBuilder(RagModes.Scanned)
            .Build(question, safeDocs, suspiciousDocs);

        var answer = await llmClient.GenerateAsync(prompt, ct);

        return new ScannedResponse(
            RagModes.Scanned,
            question,
            false,
            null,
            suspiciousDocs.Select(d => d.Name).ToList(),
            CreateSummary(docs),
            answer);
    }

    private async Task<RagResponse> AskAsync(string mode, string question, CancellationToken ct)
    {
        var docs = await retriever.RetrieveAsync(question, ct);
        var prompt = GetPromptBuilder(mode).Build(question, docs);
        var answer = await llmClient.GenerateAsync(prompt, ct);

        return new RagResponse(
            mode,
            question,
            CreateSummary(docs),
            answer);
    }

    private IRagPromptBuilder GetPromptBuilder(string mode)
    {
        if (_promptBuilders.TryGetValue(mode, out var builder))
        {
            return builder;
        }

        throw new InvalidOperationException($"No prompt builder is registered for mode '{mode}'.");
    }

    private static IReadOnlyList<RetrievedDocumentSummary> CreateSummary(IReadOnlyList<RetrievedDocument> docs)
    {
        return docs
            .Select(d => new RetrievedDocumentSummary(d.Name, d.Score, d.LooksSuspicious))
            .ToList();
    }
}
