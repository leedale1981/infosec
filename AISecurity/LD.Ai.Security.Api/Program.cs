using LD.Ai.Security.Api;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.Configure<GraphOptions>(builder.Configuration.GetSection("Graph"));
builder.Services.Configure<OllamaOptions>(builder.Configuration.GetSection("Ollama"));

builder.Services.AddSingleton<IRetrievalScorer, KeywordRetrievalScorer>();
builder.Services.AddSingleton<IPromptInjectionScanner, PhrasePromptInjectionScanner>();
builder.Services.AddSingleton<IFileTextExtractor, PlainTextFileTextExtractor>();
builder.Services.AddSingleton<IFileTextExtractor, DocxFileTextExtractor>();
builder.Services.AddSingleton<IDocumentTextExtractor, CompositeDocumentTextExtractor>();
builder.Services.AddSingleton<IDocumentRetriever, SharePointDocumentRetriever>();
builder.Services.AddSingleton<IRagPromptBuilder, VulnerablePromptBuilder>();
builder.Services.AddSingleton<IRagPromptBuilder, HardenedPromptBuilder>();
builder.Services.AddSingleton<IRagPromptBuilder, ScannedPromptBuilder>();
builder.Services.AddSingleton<IRagQueryService, RagQueryService>();
builder.Services.AddHttpClient<ITextGenerationClient, LocalLlmClient>();

var app = builder.Build();

app.UseSwagger();
app.UseSwaggerUI();

app.MapPost("/ask-vulnerable", async (
    AskRequest request,
    IRagQueryService ragService,
    CancellationToken ct) =>
{
    var response = await ragService.AskVulnerableAsync(request.Question, ct);
    return Results.Ok(response);
});

app.MapPost("/ask-hardened", async (
    AskRequest request,
    IRagQueryService ragService,
    CancellationToken ct) =>
{
    var response = await ragService.AskHardenedAsync(request.Question, ct);
    return Results.Ok(response);
});

app.MapPost("/ask-scanned", async (
    AskRequest request,
    IRagQueryService ragService,
    CancellationToken ct) =>
{
    var response = await ragService.AskScannedAsync(request.Question, ct);
    return Results.Ok(response);
});

app.Run();
