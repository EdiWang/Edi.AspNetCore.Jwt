using Edi.AspNetCore.Jwt.InMemory;
using NUnit.Framework;

namespace Edi.AspNetCore.Jwt.Tests;

[TestFixture]
public class InMemoryRefreshTokenStoreTests
{
    private readonly InMemoryRefreshTokenStore _tokenStore = new();

    [Test]
    public async Task AddOrUpdate_Should_AddOrUpdateToken()
    {
        var key = "tokenKey";
        var token = new RefreshToken();

        await _tokenStore.AddOrUpdate(key, token);

        Assert.That(_tokenStore.RefreshTokens.ContainsKey(key), Is.True);
        Assert.That(token, Is.EqualTo(_tokenStore.RefreshTokens[key]));
    }

    [Test]
    public async Task Get_Should_ReturnToken()
    {
        var key = "tokenKey";
        var token = new RefreshToken();
        _tokenStore.RefreshTokens[key] = token;

        var result = await _tokenStore.Get(key);

        Assert.That(token, Is.EqualTo(result));
    }

    [Test]
    public async Task Remove_Should_RemoveToken()
    {
        var key = "tokenKey";
        var token = new RefreshToken();
        _tokenStore.RefreshTokens[key] = token;

        await _tokenStore.Remove(key);

        Assert.That(_tokenStore.RefreshTokens.ContainsKey(key), Is.False);
    }
}