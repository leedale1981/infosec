namespace LD.Ai.Security.Api;

public sealed record AskRequest(string Question);

public sealed record RetrievedDocument(
    string Name,
    string Content,
    int Score,
    bool LooksSuspicious
);

public sealed record RagResponse(
    string Mode,
    string Question,
    IReadOnlyList<RetrievedDocumentSummary> RetrievedDocuments,
    string Answer
);

public sealed record RetrievedDocumentSummary(
    string Name,
    int Score,
    bool LooksSuspicious
);

public sealed record ScannedResponse(
    string Mode,
    string Question,
    bool Blocked,
    string? Reason,
    IReadOnlyList<string> SuspiciousDocuments,
    IReadOnlyList<RetrievedDocumentSummary>? RetrievedDocuments,
    string? Answer
);

public static class RagModes
{
    public const string Vulnerable = "vulnerable";
    public const string Hardened = "hardened";
    public const string Scanned = "scanned";
}