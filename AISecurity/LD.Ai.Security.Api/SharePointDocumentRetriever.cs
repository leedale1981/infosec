namespace LD.Ai.Security.Api;

using Azure.Identity;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Graph;
using Microsoft.Graph.Models;

public sealed class SharePointDocumentRetriever
{
    private readonly GraphServiceClient _graph;
    private readonly IConfiguration _config;
    private readonly ILogger<SharePointDocumentRetriever> _logger;

    public SharePointDocumentRetriever(
        IConfiguration config,
        ILogger<SharePointDocumentRetriever> logger)
    {
        _config = config;
        _logger = logger;

        var tenantId = config["Graph:TenantId"];
        var clientId = config["Graph:ClientId"];
        var clientSecret = config["Graph:ClientSecret"];

        if (string.IsNullOrWhiteSpace(tenantId) ||
            string.IsNullOrWhiteSpace(clientId) ||
            string.IsNullOrWhiteSpace(clientSecret))
        {
            throw new InvalidOperationException(
                "Graph configuration is missing. Check Graph:TenantId, Graph:ClientId, and Graph:ClientSecret.");
        }

        var credential = new ClientSecretCredential(
            tenantId,
            clientId,
            clientSecret);

        _graph = new GraphServiceClient(
            credential,
            ["https://graph.microsoft.com/.default"]);
    }

    public async Task<IReadOnlyList<RetrievedDocument>> RetrieveAsync(
        string question,
        CancellationToken ct = default)
    {
        var host = RequireConfig("Graph:SharePointHost");
        var sitePath = RequireConfig("Graph:SitePath");
        var libraryName = RequireConfig("Graph:LibraryName");

        // Can be blank because your files currently sit directly in Policy Documents.
        var folderPath = _config["Graph:FolderPath"]?.Trim();

        _logger.LogInformation(
            "Resolving SharePoint site. Host={Host}, SitePath={SitePath}, Library={LibraryName}, Folder={FolderPath}",
            host,
            sitePath,
            libraryName,
            string.IsNullOrWhiteSpace(folderPath) ? "<library root>" : folderPath);

        var site = await _graph
            .Sites[$"{host}:{sitePath}"]
            .GetAsync(cancellationToken: ct);

        if (site?.Id is null)
        {
            throw new InvalidOperationException(
                $"Could not resolve SharePoint site '{host}{sitePath}'.");
        }

        _logger.LogInformation(
            "Resolved SharePoint site. SiteId={SiteId}, Name={SiteName}",
            site.Id,
            site.DisplayName);

        var drivesResponse = await _graph
            .Sites[site.Id]
            .Drives
            .GetAsync(cancellationToken: ct);

        var drives = drivesResponse?.Value ?? [];

        _logger.LogInformation(
            "Found {DriveCount} document libraries on site '{SiteName}'.",
            drives.Count,
            site.DisplayName);

        foreach (var candidate in drives)
        {
            _logger.LogInformation(
                "Available library: Name={DriveName}, Id={DriveId}",
                candidate.Name,
                candidate.Id);
        }

        var drive = drives.FirstOrDefault(d =>
            string.Equals(
                d.Name,
                libraryName,
                StringComparison.OrdinalIgnoreCase));

        if (drive?.Id is null)
        {
            var availableLibraries = string.Join(
                ", ",
                drives
                    .Where(d => !string.IsNullOrWhiteSpace(d.Name))
                    .Select(d => $"'{d.Name}'"));

            throw new InvalidOperationException(
                $"Could not find SharePoint document library '{libraryName}'. " +
                $"Available libraries: {availableLibraries}");
        }

        _logger.LogInformation(
            "Using SharePoint library. Name={DriveName}, Id={DriveId}",
            drive.Name,
            drive.Id);

        var items = await GetFilesFromConfiguredLocationAsync(
            drive.Id,
            drive.Name ?? libraryName,
            folderPath,
            ct);

        var docs = new List<RetrievedDocument>();

        foreach (var item in items)
        {
            if (item.Id is null || item.Name is null || item.File is null)
            {
                continue;
            }

            if (!IsSupportedFile(item.Name))
            {
                _logger.LogDebug(
                    "Skipping unsupported file type: {FileName}",
                    item.Name);

                continue;
            }

            try
            {
                await using var stream = await _graph
                    .Drives[drive.Id]
                    .Items[item.Id]
                    .Content
                    .GetAsync(cancellationToken: ct);

                if (stream is null)
                {
                    _logger.LogWarning(
                        "No content stream returned for SharePoint file {FileName} ({ItemId}).",
                        item.Name,
                        item.Id);

                    continue;
                }

                var content = await ExtractTextAsync(item.Name, stream, ct);

                if (string.IsNullOrWhiteSpace(content))
                {
                    _logger.LogWarning(
                        "No readable text was extracted from {FileName}.",
                        item.Name);

                    continue;
                }

                var score = SimpleRetriever.Score(question, content, item.Name);
                var suspicious = PromptInjectionScanner.LooksSuspicious(content);

                docs.Add(new RetrievedDocument(
                    item.Name,
                    content,
                    score,
                    suspicious));

                _logger.LogInformation(
                    "Retrieved {FileName}. Score={Score}, Suspicious={Suspicious}, Characters={Characters}",
                    item.Name,
                    score,
                    suspicious,
                    content.Length);
            }
            catch (Exception ex)
            {
                _logger.LogError(
                    ex,
                    "Failed to download or extract text from SharePoint file {FileName} ({ItemId}).",
                    item.Name,
                    item.Id);
            }
        }

        return docs
            .OrderByDescending(d => d.Score)
            .ThenBy(d => d.Name)
            .Take(4)
            .ToList();
    }

    private async Task<IReadOnlyList<DriveItem>> GetFilesFromConfiguredLocationAsync(
        string driveId,
        string libraryName,
        string? folderPath,
        CancellationToken ct)
    {
        DriveItemCollectionResponse? response;

        if (string.IsNullOrWhiteSpace(folderPath))
        {
            _logger.LogInformation(
                "Listing files from root of SharePoint library '{LibraryName}'.",
                libraryName);

            response = await _graph
                .Drives[driveId]
                .Items["root"]
                .Children
                .GetAsync(cancellationToken: ct);
        }
        else
        {
            _logger.LogInformation(
                "Resolving folder '{FolderPath}' inside SharePoint library '{LibraryName}'.",
                folderPath,
                libraryName);

            var folder = await _graph
                .Drives[driveId]
                .Items["root"]
                .ItemWithPath(folderPath)
                .GetAsync(cancellationToken: ct);

            if (folder?.Id is null)
            {
                throw new InvalidOperationException(
                    $"Could not find folder '{folderPath}' in SharePoint library '{libraryName}'. " +
                    "FolderPath must be relative to the document-library root.");
            }

            if (folder.Folder is null)
            {
                throw new InvalidOperationException(
                    $"The path '{folderPath}' exists in SharePoint library '{libraryName}', " +
                    "but it is a file rather than a folder.");
            }

            response = await _graph
                .Drives[driveId]
                .Items[folder.Id]
                .Children
                .GetAsync(cancellationToken: ct);
        }

        var files = new List<DriveItem>();

        while (response is not null)
        {
            files.AddRange(response.Value ?? []);

            if (string.IsNullOrWhiteSpace(response.OdataNextLink))
            {
                break;
            }

            response = await _graph
                .Drives[driveId]
                .Items["root"]
                .Children
                .WithUrl(response.OdataNextLink)
                .GetAsync(cancellationToken: ct);
        }

        _logger.LogInformation(
            "Found {ItemCount} items in configured SharePoint location.",
            files.Count);

        return files;
    }

    private static bool IsSupportedFile(string fileName)
    {
        return fileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
               fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase);
    }

    private static async Task<string> ExtractTextAsync(
        string fileName,
        Stream stream,
        CancellationToken ct)
    {
        if (fileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase) ||
            fileName.EndsWith(".md", StringComparison.OrdinalIgnoreCase))
        {
            using var reader = new StreamReader(stream);
            return await reader.ReadToEndAsync(ct);
        }

        if (fileName.EndsWith(".docx", StringComparison.OrdinalIgnoreCase))
        {
            await using var memory = new MemoryStream();

            await stream.CopyToAsync(memory, ct);
            memory.Position = 0;

            using var wordDocument = WordprocessingDocument.Open(
                memory,
                false);

            return wordDocument.MainDocumentPart?
                .Document?
                .Body?
                .InnerText
                ?.Trim()
                ?? string.Empty;
        }

        throw new NotSupportedException(
            $"Unsupported document type '{Path.GetExtension(fileName)}'.");
    }

    private string RequireConfig(string key)
    {
        var value = _config[key]?.Trim();

        if (string.IsNullOrWhiteSpace(value))
        {
            throw new InvalidOperationException(
                $"Missing required configuration value '{key}'.");
        }

        return value;
    }
}