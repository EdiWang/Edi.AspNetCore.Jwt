using System.Collections.Concurrent;

namespace Edi.AspNetCore.Jwt;

public interface IRefreshTokenStore
{
    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get; set; }

    public Task AddOrUpdate(string key, RefreshToken token);

    public Task<RefreshToken> Get(string key);

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time);

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string identifier);

    public Task Remove(string key);
}