using Microsoft.Extensions.Logging;
using Moq;

namespace Edi.AspNetCore.Jwt.Tests;

[TestClass]
public class InMemoryRefreshTokenStoreTests
{
    private Mock<ILogger<InMemoryRefreshTokenStore>> _mockLogger;
    private InMemoryRefreshTokenStore _refreshTokenStore;
    private readonly DateTime _utcNow = new(2030, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [TestInitialize]
    public void Setup()
    {
        _mockLogger = new Mock<ILogger<InMemoryRefreshTokenStore>>();
        _refreshTokenStore = new InMemoryRefreshTokenStore(_mockLogger.Object);
    }

    [TestMethod]
    public void Constructor_ShouldInitializeEmptyRefreshTokensDictionary()
    {
        // Act
        var store = new InMemoryRefreshTokenStore(_mockLogger.Object);

        // Assert
        Assert.IsNotNull(store.RefreshTokens);
        Assert.AreEqual(0, store.RefreshTokens.Count);
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
        Assert.IsTrue(_refreshTokenStore.RefreshTokens.ContainsKey(key));
        Assert.AreEqual(token, _refreshTokenStore.RefreshTokens[key]);
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
        Assert.AreEqual(updatedToken, _refreshTokenStore.RefreshTokens[key]);
        Assert.AreEqual("user456", _refreshTokenStore.RefreshTokens[key].UserIdentifier);
        Assert.AreEqual("updated-info", _refreshTokenStore.RefreshTokens[key].AdditionalInfo);
    }

    [TestMethod]
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
        Assert.AreEqual(token, result);
    }

    [TestMethod]
    public async Task Get_WithNonExistingToken_ShouldReturnNull()
    {
        // Arrange
        var nonExistingToken = "non-existing-token";

        // Act
        var result = await _refreshTokenStore.Get(nonExistingToken);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
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
        Assert.AreEqual(token2, result);
        Assert.AreEqual("user2", result.UserIdentifier);
    }

    [TestMethod]
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
        Assert.AreEqual(2, result.Count);
        Assert.IsTrue(result.Any(x => x.Key == "key1" && x.Value == expiredToken1));
        Assert.IsTrue(result.Any(x => x.Key == "key2" && x.Value == expiredToken2));
        Assert.IsFalse(result.Any(x => x.Key == "key3"));
    }

    [TestMethod]
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
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
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
        Assert.AreEqual(2, result.Count);
        Assert.IsTrue(result.Any(x => x.Value == userToken1));
        Assert.IsTrue(result.Any(x => x.Value == userToken2));
        Assert.IsFalse(result.Any(x => x.Value == otherUserToken));
    }

    [TestMethod]
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
        Assert.AreEqual(0, result.Count);
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
        Assert.IsTrue(_refreshTokenStore.RefreshTokens.ContainsKey("key3"));
        Assert.AreEqual(latestToken, _refreshTokenStore.RefreshTokens["key3"]);
        Assert.IsFalse(_refreshTokenStore.RefreshTokens.ContainsKey("key1"));
        Assert.IsFalse(_refreshTokenStore.RefreshTokens.ContainsKey("key2"));
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
        Assert.IsTrue(_refreshTokenStore.RefreshTokens.ContainsKey("key1"));
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
    }

    [TestMethod]
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
        Assert.AreEqual(0, _refreshTokenStore.RefreshTokens.Count);
        Assert.IsFalse(_refreshTokenStore.RefreshTokens.ContainsKey(key));
    }

    [TestMethod]
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
        Assert.AreEqual(1, _refreshTokenStore.RefreshTokens.Count);
    }

    [TestMethod]
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
        Assert.AreEqual(0, _refreshTokenStore.RefreshTokens.Count);
    }

    [TestMethod]
    public async Task Clear_WithEmptyStore_ShouldNotThrow()
    {
        // Act & Assert
        await _refreshTokenStore.Clear();
        Assert.AreEqual(0, _refreshTokenStore.RefreshTokens.Count);
    }

    [TestMethod]
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
            }));
        }

        await Task.WhenAll(tasks);

        // Assert
        Assert.AreEqual(tokenCount, _refreshTokenStore.RefreshTokens.Count);
    }

    [TestMethod]
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