using Microsoft.Extensions.Logging;
using Moq;

namespace Edi.AspNetCore.Jwt.Tests;

public class InMemoryRefreshTokenStoreTests
{
    private readonly Mock<ILogger<InMemoryRefreshTokenStore>> _mockLogger;
    private readonly InMemoryRefreshTokenStore _refreshTokenStore;
    private readonly DateTime _utcNow = new(2030, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    public InMemoryRefreshTokenStoreTests()
    {
        _mockLogger = new Mock<ILogger<InMemoryRefreshTokenStore>>();
        _refreshTokenStore = new InMemoryRefreshTokenStore(_mockLogger.Object);
    }

    [Fact]
    public void Constructor_ShouldInitializeEmptyRefreshTokensDictionary()
    {
        // Act
        var store = new InMemoryRefreshTokenStore(_mockLogger.Object);

        // Assert
        Assert.NotNull(store.RefreshTokens);
        Assert.Empty(store.RefreshTokens);
    }

    [Fact]
    public async Task AddOrUpdate_WithNewKey_ShouldAddToken()
    {
        // Arrange
        var key = "test-key";
        var token = new RefreshToken
        {
            UserIdentifier = "user123",
            TokenString = "token123",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "test-info"
        };

        // Act
        await _refreshTokenStore.AddOrUpdate(key, token);

        // Assert
        Assert.Single(_refreshTokenStore.RefreshTokens);
        Assert.True(_refreshTokenStore.RefreshTokens.ContainsKey(key));
        Assert.Equal(token, _refreshTokenStore.RefreshTokens[key]);
    }

    [Fact]
    public async Task AddOrUpdate_WithExistingKey_ShouldUpdateToken()
    {
        // Arrange
        var key = "test-key";
        var originalToken = new RefreshToken
        {
            UserIdentifier = "user123",
            TokenString = "token123",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "original-info"
        };
        var updatedToken = new RefreshToken
        {
            UserIdentifier = "user456",
            TokenString = "token456",
            ExpireAt = _utcNow.AddMinutes(60),
            AdditionalInfo = "updated-info"
        };

        await _refreshTokenStore.AddOrUpdate(key, originalToken);

        // Act
        await _refreshTokenStore.AddOrUpdate(key, updatedToken);

        // Assert
        Assert.Single(_refreshTokenStore.RefreshTokens);
        Assert.Equal(updatedToken, _refreshTokenStore.RefreshTokens[key]);
        Assert.Equal("user456", _refreshTokenStore.RefreshTokens[key].UserIdentifier);
        Assert.Equal("updated-info", _refreshTokenStore.RefreshTokens[key].AdditionalInfo);
    }

    [Fact]
    public async Task Get_WithExistingToken_ShouldReturnToken()
    {
        // Arrange
        var key = "test-key";
        var tokenString = "token123";
        var token = new RefreshToken
        {
            UserIdentifier = "user123",
            TokenString = tokenString,
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "test-info"
        };
        await _refreshTokenStore.AddOrUpdate(key, token);

        // Act
        var result = await _refreshTokenStore.Get(tokenString);

        // Assert
        Assert.Equal(token, result);
    }

    [Fact]
    public async Task Get_WithNonExistingToken_ShouldReturnNull()
    {
        // Arrange
        var nonExistingToken = "non-existing-token";

        // Act
        var result = await _refreshTokenStore.Get(nonExistingToken);

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task Get_WithMultipleTokens_ShouldReturnCorrectToken()
    {
        // Arrange
        var token1 = new RefreshToken
        {
            UserIdentifier = "user1",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info1"
        };
        var token2 = new RefreshToken
        {
            UserIdentifier = "user2",
            TokenString = "token2",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info2"
        };

        await _refreshTokenStore.AddOrUpdate("key1", token1);
        await _refreshTokenStore.AddOrUpdate("key2", token2);

        // Act
        var result = await _refreshTokenStore.Get("token2");

        // Assert
        Assert.Equal(token2, result);
        Assert.Equal("user2", result.UserIdentifier);
    }

    [Fact]
    public async Task GetTokensBefore_WithExpiredTokens_ShouldReturnExpiredTokens()
    {
        // Arrange
        var expiredToken1 = new RefreshToken
        {
            UserIdentifier = "user1",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(-10),
            AdditionalInfo = "expired1"
        };
        var expiredToken2 = new RefreshToken
        {
            UserIdentifier = "user2",
            TokenString = "token2",
            ExpireAt = _utcNow.AddMinutes(-5),
            AdditionalInfo = "expired2"
        };
        var validToken = new RefreshToken
        {
            UserIdentifier = "user3",
            TokenString = "token3",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "valid"
        };

        await _refreshTokenStore.AddOrUpdate("key1", expiredToken1);
        await _refreshTokenStore.AddOrUpdate("key2", expiredToken2);
        await _refreshTokenStore.AddOrUpdate("key3", validToken);

        // Act
        var result = await _refreshTokenStore.GetTokensBefore(_utcNow);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Contains(result, x => x.Key == "key1" && x.Value == expiredToken1);
        Assert.Contains(result, x => x.Key == "key2" && x.Value == expiredToken2);
        Assert.DoesNotContain(result, x => x.Key == "key3");
    }

    [Fact]
    public async Task GetTokensBefore_WithNoExpiredTokens_ShouldReturnEmptyList()
    {
        // Arrange
        var validToken = new RefreshToken
        {
            UserIdentifier = "user1",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "valid"
        };
        await _refreshTokenStore.AddOrUpdate("key1", validToken);

        // Act
        var result = await _refreshTokenStore.GetTokensBefore(_utcNow);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task GetTokensByIdentifier_WithMatchingTokens_ShouldReturnUserTokens()
    {
        // Arrange
        var userIdentifier = "user123";
        var userToken1 = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info1"
        };
        var userToken2 = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token2",
            ExpireAt = _utcNow.AddMinutes(60),
            AdditionalInfo = "info2"
        };
        var otherUserToken = new RefreshToken
        {
            UserIdentifier = "other-user",
            TokenString = "token3",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "other-info"
        };

        await _refreshTokenStore.AddOrUpdate("key1", userToken1);
        await _refreshTokenStore.AddOrUpdate("key2", userToken2);
        await _refreshTokenStore.AddOrUpdate("key3", otherUserToken);

        // Act
        var result = await _refreshTokenStore.GetTokensByIdentifier(userIdentifier);

        // Assert
        Assert.Equal(2, result.Count);
        Assert.Contains(result, x => x.Value == userToken1);
        Assert.Contains(result, x => x.Value == userToken2);
        Assert.DoesNotContain(result, x => x.Value == otherUserToken);
    }

    [Fact]
    public async Task GetTokensByIdentifier_WithNoMatchingTokens_ShouldReturnEmptyList()
    {
        // Arrange
        var userIdentifier = "non-existing-user";
        var token = new RefreshToken
        {
            UserIdentifier = "other-user",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info"
        };
        await _refreshTokenStore.AddOrUpdate("key1", token);

        // Act
        var result = await _refreshTokenStore.GetTokensByIdentifier(userIdentifier);

        // Assert
        Assert.Empty(result);
    }

    [Fact]
    public async Task RemoveNonLatestTokens_WithMultipleTokens_ShouldRemoveNonLatestTokens()
    {
        // Arrange
        var userIdentifier = "user123";
        var oldestToken = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(10),
            AdditionalInfo = "oldest"
        };
        var middleToken = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token2",
            ExpireAt = _utcNow.AddMinutes(20),
            AdditionalInfo = "middle"
        };
        var latestToken = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token3",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "latest"
        };

        await _refreshTokenStore.AddOrUpdate("key1", oldestToken);
        await _refreshTokenStore.AddOrUpdate("key2", middleToken);
        await _refreshTokenStore.AddOrUpdate("key3", latestToken);

        // Act
        await _refreshTokenStore.RemoveNonLatestTokens(userIdentifier);

        // Assert
        Assert.Single(_refreshTokenStore.RefreshTokens);
        Assert.True(_refreshTokenStore.RefreshTokens.ContainsKey("key3"));
        Assert.Equal(latestToken, _refreshTokenStore.RefreshTokens["key3"]);
        Assert.False(_refreshTokenStore.RefreshTokens.ContainsKey("key1"));
        Assert.False(_refreshTokenStore.RefreshTokens.ContainsKey("key2"));
    }

    [Fact]
    public async Task RemoveNonLatestTokens_WithSingleToken_ShouldNotRemoveToken()
    {
        // Arrange
        var userIdentifier = "user123";
        var token = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "single"
        };
        await _refreshTokenStore.AddOrUpdate("key1", token);

        // Act
        await _refreshTokenStore.RemoveNonLatestTokens(userIdentifier);

        // Assert
        Assert.Single(_refreshTokenStore.RefreshTokens);
        Assert.True(_refreshTokenStore.RefreshTokens.ContainsKey("key1"));
    }

    [Fact]
    public async Task RemoveNonLatestTokens_WithNoTokensForUser_ShouldNotThrow()
    {
        // Arrange
        var userIdentifier = "non-existing-user";
        var otherUserToken = new RefreshToken
        {
            UserIdentifier = "other-user",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "other"
        };
        await _refreshTokenStore.AddOrUpdate("key1", otherUserToken);

        // Act & Assert
        await _refreshTokenStore.RemoveNonLatestTokens(userIdentifier);
        Assert.Single(_refreshTokenStore.RefreshTokens);
    }

    [Fact]
    public async Task Remove_WithExistingKey_ShouldRemoveToken()
    {
        // Arrange
        var key = "test-key";
        var token = new RefreshToken
        {
            UserIdentifier = "user123",
            TokenString = "token123",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "test-info"
        };
        await _refreshTokenStore.AddOrUpdate(key, token);

        // Act
        await _refreshTokenStore.Remove(key);

        // Assert
        Assert.Empty(_refreshTokenStore.RefreshTokens);
        Assert.False(_refreshTokenStore.RefreshTokens.ContainsKey(key));
    }

    [Fact]
    public async Task Remove_WithNonExistingKey_ShouldNotThrow()
    {
        // Arrange
        var nonExistingKey = "non-existing-key";
        var token = new RefreshToken
        {
            UserIdentifier = "user123",
            TokenString = "token123",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "test-info"
        };
        await _refreshTokenStore.AddOrUpdate("existing-key", token);

        // Act & Assert
        await _refreshTokenStore.Remove(nonExistingKey);
        Assert.Single(_refreshTokenStore.RefreshTokens);
    }

    [Fact]
    public async Task Clear_WithMultipleTokens_ShouldRemoveAllTokens()
    {
        // Arrange
        var token1 = new RefreshToken
        {
            UserIdentifier = "user1",
            TokenString = "token1",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info1"
        };
        var token2 = new RefreshToken
        {
            UserIdentifier = "user2",
            TokenString = "token2",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "info2"
        };

        await _refreshTokenStore.AddOrUpdate("key1", token1);
        await _refreshTokenStore.AddOrUpdate("key2", token2);

        // Act
        await _refreshTokenStore.Clear();

        // Assert
        Assert.Empty(_refreshTokenStore.RefreshTokens);
    }

    [Fact]
    public async Task Clear_WithEmptyStore_ShouldNotThrow()
    {
        // Act & Assert
        await _refreshTokenStore.Clear();
        Assert.Empty(_refreshTokenStore.RefreshTokens);
    }

    [Fact]
    public async Task ConcurrentOperations_ShouldBeThreadSafe()
    {
        // Arrange
        var tasks = new List<Task>();
        var tokenCount = 100;

        // Act - Add tokens concurrently
        for (int i = 0; i < tokenCount; i++)
        {
            var index = i;
            tasks.Add(Task.Run(async () =>
            {
                var token = new RefreshToken
                {
                    UserIdentifier = $"user{index}",
                    TokenString = $"token{index}",
                    ExpireAt = _utcNow.AddMinutes(30),
                    AdditionalInfo = $"info{index}"
                };
                await _refreshTokenStore.AddOrUpdate($"key{index}", token);
            }, TestContext.Current.CancellationToken));
        }

        await Task.WhenAll(tasks);

        // Assert
        Assert.Equal(tokenCount, _refreshTokenStore.RefreshTokens.Count);
    }

    [Fact]
    public async Task AllMethods_ShouldLogAppropriateMessages()
    {
        // Arrange
        var key = "test-key";
        var userIdentifier = "user123";
        var token = new RefreshToken
        {
            UserIdentifier = userIdentifier,
            TokenString = "token123",
            ExpireAt = _utcNow.AddMinutes(30),
            AdditionalInfo = "test-info"
        };

        // Act
        await _refreshTokenStore.AddOrUpdate(key, token);
        await _refreshTokenStore.RemoveNonLatestTokens(userIdentifier);
        await _refreshTokenStore.Remove(key);
        await _refreshTokenStore.Clear();

        // Assert - Verify logging calls were made
        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains($"Refresh token added or updated for key: {key}")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains($"Non-latest refresh tokens removed for user identifier: {userIdentifier}")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains($"Refresh token removed for key: {key}")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);

        _mockLogger.Verify(
            x => x.Log(
                LogLevel.Trace,
                It.IsAny<EventId>(),
                It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("Refresh tokens cleared")),
                It.IsAny<Exception>(),
                It.IsAny<Func<It.IsAnyType, Exception, string>>()),
            Times.Once);
    }
}