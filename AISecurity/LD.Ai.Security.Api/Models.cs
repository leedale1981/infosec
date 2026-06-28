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
    IReadOnlyList<object> RetrievedDocuments,
    string Answer
);