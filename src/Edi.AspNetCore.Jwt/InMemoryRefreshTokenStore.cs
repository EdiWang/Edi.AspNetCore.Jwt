using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;

namespace Edi.AspNetCore.Jwt;

public class InMemoryRefreshTokenStore(ILogger<InMemoryRefreshTokenStore> logger) : IRefreshTokenStore
{
    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; set; } = new();

    public Task AddOrUpdate(string key, RefreshToken token)
    {
        RefreshTokens.AddOrUpdate(key, token, (_, _) => token);

        logger.LogTrace($"Refresh token added or updated for key: {key}");
        return Task.CompletedTask;
    }

    public Task<RefreshToken> Get(string key)
    {
        RefreshTokens.TryGetValue(key, out var token);

        logger.LogTrace($"Refresh token retrieved for key: {key}");
        return Task.FromResult(token);
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time)
    {
        var tokens = RefreshTokens.Where(x => x.Value.ExpireAt < time).ToList();
        return Task.FromResult(tokens);
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string userIdentifier)
    {
        var tokens = RefreshTokens.Where(x => x.Value.UserIdentifier == userIdentifier).ToList();
        return Task.FromResult(tokens);
    }

    public Task Remove(string key)
    {
        RefreshTokens.TryRemove(key, out _);

        logger.LogTrace($"Refresh token removed for key: {key}");
        return Task.CompletedTask;
    }

    public Task Clear()
    {
        RefreshTokens.Clear();

        logger.LogTrace("Refresh tokens cleared");
        return Task.CompletedTask;
    }
}