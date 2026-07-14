using DocumentFormat.OpenXml.Packaging;

namespace LD.Ai.Security.Api;

public sealed class CompositeDocumentTextExtractor(IEnumerable<IFileTextExtractor> extractors)
    : IDocumentTextExtractor
{
    private readonly IReadOnlyList<IFileTextExtractor> _extractors = extractors.ToList();

    public bool CanExtract(string fileName)
    {
        return _extractors.Any(extractor => extractor.CanExtract(fileName));
    }

    public Task<string> ExtractAsync(string fileName, Stream stream, CancellationToken ct)
    {
        var extractor = _extractors.FirstOrDefault(candidate => candidate.CanExtract(fileName));

        if (extractor is null)
        {
            throw new NotSupportedException($"Unsupported document type '{Path.GetExtension(fileName)}'.");
        }

        return extractor.ExtractAsync(stream, ct);
    }
}

public sealed class PlainTextFileTextExtractor : IFileTextExtractor
{
    public bool CanExtract(string fileName)
    {
        return fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<string> ExtractAsync(Stream stream, CancellationToken ct)
    {
        using var reader = new StreamReader(stream);
        return await reader.ReadToEndAsync(ct);
    }
}

public sealed class DocxFileTextExtractor : IFileTextExtractor
{
    public bool CanExtract(string fileName)
    {
        return fileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase);
    }

    public async Task<string> ExtractAsync(Stream stream, CancellationToken ct)
    {
        await using var memory = new MemoryStream();
        await stream.CopyToAsync(memory, ct);
        memory.Position = 0;

        using var wordDocument = WordprocessingDocument.Open(memory, false);

        return wordDocument.MainDocumentPart?
            .Document?
            .Body?
            .InnerText?
            .Trim()
            ?? string.Empty;
    }
}
