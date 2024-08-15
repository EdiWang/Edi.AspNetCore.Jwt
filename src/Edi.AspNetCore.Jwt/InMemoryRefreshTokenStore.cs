using Microsoft.Extensions.Logging;
using System.Collections.Concurrent;

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

    public Task<RefreshToken> Get(string token)
    {
        var item = RefreshTokens.FirstOrDefault(p => p.Value.TokenString == token);
        return Task.FromResult(item.Value);
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

    public Task RemoveNonLatestTokens(string userIdentifier)
    {
        var tokens = RefreshTokens.Where(x => x.Value.UserIdentifier == userIdentifier).ToList();
        if (tokens.Count > 1)
        {
            var nonLatestTokens = tokens.OrderByDescending(x => x.Value.ExpireAt).Skip(1).ToList();
            foreach (var token in nonLatestTokens)
            {
                RefreshTokens.TryRemove(token.Key, out _);
            }
        }

        logger.LogTrace($"Non-latest refresh tokens removed for user identifier: {userIdentifier}");
        return Task.CompletedTask;
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