namespace LD.Ai.Security.Api;

using System.Text.RegularExpressions;

public static class SimpleRetriever
{
    public static int Score(string question, string content, string name)
    {
        var queryTerms = Tokenize(question);
        var text = $"{name} {content}".ToLowerInvariant();

        var score = 0;

        foreach (var term in queryTerms)
        {
            if (text.Contains(term))
                score += 10;
        }

        if (text.Contains("holiday") || text.Contains("annual leave"))
        {
            score += 20;
        }

        return score;
    }

    private static IReadOnlyList<string> Tokenize(string input)
    {
        return Regex
            .Matches(input.ToLowerInvariant(), "[a-z0-9]+")
            .Select(m => m.Value)
            .Where(t => t.Length > 2)
            .Distinct()
            .ToList();
    }
}