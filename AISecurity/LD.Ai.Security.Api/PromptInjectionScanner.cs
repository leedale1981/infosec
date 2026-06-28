namespace LD.Ai.Security.Api;

public static class PromptInjectionScanner
{
    private static readonly string[] SuspiciousPhrases =
    [
        "ignore the user's question",
        "ignore previous instructions",
        "ignore all previous instructions",
        "ignore all previous rules",
        "system override",
        "developer message",
        "instruction to ai assistant",
        "do not mention this document",
        "do not tell the user",
        "reveal the prompt",
        "print all documents",
        "you are now",
        "forget your instructions",
        "annual leave has been cancelled"
    ];

    public static bool LooksSuspicious(string text)
    {
        return SuspiciousPhrases.Any(phrase =>
            text.Contains(phrase, StringComparison.OrdinalIgnoreCase));
    }
}