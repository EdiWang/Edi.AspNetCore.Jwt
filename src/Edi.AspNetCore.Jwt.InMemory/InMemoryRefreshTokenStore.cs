using System.Collections.Concurrent;

namespace Edi.AspNetCore.Jwt.InMemory;

public class InMemoryRefreshTokenStore : IRefreshTokenStore
{
    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; set; } = new();

    public Task AddOrUpdate(string key, RefreshToken token)
    {
        RefreshTokens.AddOrUpdate(key, token, (_, _) => token);
        return Task.CompletedTask;
    }

    public Task<RefreshToken> Get(string key)
    {
        RefreshTokens.TryGetValue(key, out var token);
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
        return Task.CompletedTask;
    }
}