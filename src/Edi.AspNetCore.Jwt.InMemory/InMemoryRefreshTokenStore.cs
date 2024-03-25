using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Edi.AspNetCore.Jwt.InMemory;

public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    private readonly ILogger<InMemoryRefreshTokenStore> _logger;

    public InMemoryRefreshTokenStore(ILogger<InMemoryRefreshTokenStore> logger)
    {
        _logger = logger;
    }

    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; set; } = new();

    public Task AddOrUpdate(string key, RefreshToken token)
    {
        RefreshTokens.AddOrUpdate(key, token, (_, _) => token);

        _logger.LogDebug($"Refresh token added or updated for key: {key}");
        return Task.CompletedTask;
    }

    public Task<RefreshToken> Get(string key)
    {
        RefreshTokens.TryGetValue(key, out var token);

        _logger.LogDebug($"Refresh token retrieved for key: {key}");
        return Task.FromResult(token);
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time)
    {
        var tokens = RefreshTokens.Where(x => x.Value.ExpireAt < time).ToList();
        return Task.FromResult(tokens);
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string identifier)
    {
        var tokens = RefreshTokens.Where(x => x.Value.Identifier == identifier).ToList();
        return Task.FromResult(tokens);
    }

    public Task Remove(string key)
    {
        RefreshTokens.TryRemove(key, out _);

        _logger.LogDebug($"Refresh token removed for key: {key}");
        return Task.CompletedTask;
    }
}