namespace LD.Ai.Security.Api;

using Azure.Identity;
using DocumentFormat.OpenXml.Packaging;
using Microsoft.Extensions.Options;
using Microsoft.Graph;
using Microsoft.Graph.Models;
using Microsoft.Kiota.Abstractions;

public sealed class SharePointDocumentRetriever : IDocumentRetriever
{
    private readonly GraphServiceClient _graph;
    private readonly GraphOptions _options;
    private readonly IDocumentTextExtractor _textExtractor;
    private readonly IRetrievalScorer _scorer;
    private readonly IPromptInjectionScanner _scanner;
    private readonly ILogger<SharePointDocumentRetriever> _logger;

    public SharePointDocumentRetriever(
        IOptions<GraphOptions> graphOptions,
        IDocumentTextExtractor textExtractor,
        IRetrievalScorer scorer,
        IPromptInjectionScanner scanner,
        ILogger<SharePointDocumentRetriever> logger)
    {
        _options = graphOptions.Value;
        _options.Validate();

        _textExtractor = textExtractor;
        _scorer = scorer;
        _scanner = scanner;
        _logger = logger;

        var credential = new ClientSecretCredential(
            _options.TenantId,
            _options.ClientId,
            _options.ClientSecret);

        _graph = new GraphServiceClient(
            credential,
            ["https://graph.microsoft.com/.default"]);
    }

    public async Task<IReadOnlyList<RetrievedDocument>> RetrieveAsync(string question, CancellationToken ct = default)
    {
        var site = await ResolveSiteAsync(ct);
        var drive = await ResolveDriveAsync(site.Id!, ct);
        var items = await GetFilesFromConfiguredLocationAsync(drive.Id!, drive.Name ?? _options.LibraryName, _options.FolderPath, ct);

        var docs = new List<RetrievedDocument>();

        foreach (var item in items.Where(IsCandidateFile))
        {
            var document = await TryCreateDocumentAsync(item, drive.Id!, question, ct);
            if (document is not null)
            {
                docs.Add(document);
            }
        }

        return docs
            .OrderByDescending(d => d.Score)
            .ThenBy(d => d.Name)
            .Take(4)
            .ToList();
    }

    private async Task<Site> ResolveSiteAsync(CancellationToken ct)
    {
        _logger.LogInformation(
            "Resolving SharePoint site. Host={Host}, SitePath={SitePath}, Library={LibraryName}, Folder={FolderPath}",
            _options.SharePointHost,
            _options.SitePath,
            _options.LibraryName,
            string.IsNullOrWhiteSpace(_options.FolderPath) ? "<library root>" : _options.FolderPath);

        var site = await _graph
            .Sites[$"{_options.SharePointHost}:{_options.SitePath}"]
            .GetAsync(cancellationToken: ct);

        if (site?.Id is null)
        {
            throw new InvalidOperationException($"Could not resolve SharePoint site '{_options.SharePointHost}{_options.SitePath}'.");
        }

        _logger.LogInformation("Resolved SharePoint site. SiteId={SiteId}, Name={SiteName}", site.Id, site.DisplayName);
        return site;
    }

    private async Task<Drive> ResolveDriveAsync(string siteId, CancellationToken ct)
    {
        var drivesResponse = await _graph
            .Sites[siteId]
            .Drives
            .GetAsync(cancellationToken: ct);

        var drives = drivesResponse?.Value ?? [];

        _logger.LogInformation("Found {DriveCount} document libraries on site.", drives.Count);

        foreach (var candidate in drives)
        {
            _logger.LogInformation("Available library: Name={DriveName}, Id={DriveId}", candidate.Name, candidate.Id);
        }

        var drive = drives.FirstOrDefault(d =>
            string.Equals(d.Name, _options.LibraryName, StringComparison.OrdinalIgnoreCase));

        if (drive?.Id is null)
        {
            var availableLibraries = string.Join(
                ", ",
                drives.Where(d => !string.IsNullOrWhiteSpace(d.Name)).Select(d => $"'{d.Name}'"));

            throw new InvalidOperationException(
                $"Could not find SharePoint document library '{_options.LibraryName}'. Available libraries: {availableLibraries}");
        }

        _logger.LogInformation("Using SharePoint library. Name={DriveName}, Id={DriveId}", drive.Name, drive.Id);
        return drive;
    }

    private async Task<IReadOnlyList<DriveItem>> GetFilesFromConfiguredLocationAsync(
        string driveId,
        string libraryName,
        string? folderPath,
        CancellationToken ct)
    {
        var response = string.IsNullOrWhiteSpace(folderPath)
            ? await ListLibraryRootAsync(driveId, libraryName, ct)
            : await ListFolderAsync(driveId, libraryName, folderPath, ct);

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

        _logger.LogInformation("Found {ItemCount} items in configured SharePoint location.", files.Count);
        return files;
    }

    private async Task<DriveItemCollectionResponse?> ListLibraryRootAsync(string driveId, string libraryName, CancellationToken ct)
    {
        _logger.LogInformation("Listing files from root of SharePoint library '{LibraryName}'.", libraryName);

        return await _graph
            .Drives[driveId]
            .Items["root"]
            .Children
            .GetAsync(cancellationToken: ct);
    }

    private async Task<DriveItemCollectionResponse?> ListFolderAsync(string driveId, string libraryName, string folderPath, CancellationToken ct)
    {
        _logger.LogInformation("Resolving folder '{FolderPath}' inside SharePoint library '{LibraryName}'.", folderPath, libraryName);

        var folder = await _graph
            .Drives[driveId]
            .Items["root"]
            .ItemWithPath(folderPath)
            .GetAsync(cancellationToken: ct);

        if (folder?.Id is null)
        {
            throw new InvalidOperationException(
                $"Could not find folder '{folderPath}' in SharePoint library '{libraryName}'. FolderPath must be relative to the document-library root.");
        }

        if (folder.Folder is null)
        {
            throw new InvalidOperationException(
                $"The path '{folderPath}' exists in SharePoint library '{libraryName}', but it is a file rather than a folder.");
        }

        return await _graph
            .Drives[driveId]
            .Items[folder.Id]
            .Children
            .GetAsync(cancellationToken: ct);
    }

    private bool IsCandidateFile(DriveItem item)
    {
        if (item.Id is null || item.Name is null || item.File is null)
        {
            return false;
        }

        if (_textExtractor.CanExtract(item.Name))
        {
            return true;
        }

        _logger.LogDebug("Skipping unsupported file type: {FileName}", item.Name);
        return false;
    }

    private async Task<RetrievedDocument?> TryCreateDocumentAsync(
        DriveItem item,
        string driveId,
        string question,
        CancellationToken ct)
    {
        try
        {
            var content = await DownloadAndExtractContentAsync(driveId, item, ct);
            if (string.IsNullOrWhiteSpace(content))
            {
                _logger.LogWarning("No readable text was extracted from {FileName}.", item.Name);
                return null;
            }

            var score = _scorer.Score(question, content, item.Name!);
            var suspicious = _scanner.LooksSuspicious(content);

            _logger.LogInformation(
                "Retrieved {FileName}. Score={Score}, Suspicious={Suspicious}, Characters={Characters}",
                item.Name,
                score,
                suspicious,
                content.Length);

            return new RetrievedDocument(item.Name!, content, score, suspicious);
        }
        catch (ApiException ex)
        {
            _logger.LogError(ex, "Graph API failed while processing {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
        catch (HttpRequestException ex)
        {
            _logger.LogError(ex, "Network failed while processing {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
        catch (IOException ex)
        {
            _logger.LogError(ex, "I/O failed while processing {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
        catch (OpenXmlPackageException ex)
        {
            _logger.LogError(ex, "DOCX parsing failed for {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
        catch (InvalidDataException ex)
        {
            _logger.LogError(ex, "Invalid file data for {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
        catch (InvalidOperationException ex)
        {
            _logger.LogError(ex, "Unexpected document state for {FileName} ({ItemId}).", item.Name, item.Id);
            return null;
        }
    }

    private async Task<string> DownloadAndExtractContentAsync(string driveId, DriveItem item, CancellationToken ct)
    {
        await using var stream = await _graph
            .Drives[driveId]
            .Items[item.Id!]
            .Content
            .GetAsync(cancellationToken: ct);

        if (stream is null)
        {
            throw new InvalidOperationException(
                $"No content stream returned for SharePoint file '{item.Name}' ({item.Id}).");
        }

        return await _textExtractor.ExtractAsync(item.Name!, stream, ct);
    }
}
