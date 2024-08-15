namespace Edi.AspNetCore.Jwt;

public interface IRefreshTokenStore
{
    public Task AddOrUpdate(string key, RefreshToken token);

    public Task<RefreshToken> Get(string key);

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time);

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string userIdentifier);

    public Task RemoveNonLatestTokens(string userIdentifier);

    public Task Remove(string key);

    public Task Clear();
}