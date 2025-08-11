using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using Moq;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Edi.AspNetCore.Jwt.Tests;

[TestClass]
public class DefaultJwtAuthManagerTests
{
    private Mock<IRefreshTokenStore> _mockRefreshTokenStore;
    private Mock<ILogger<DefaultJwtAuthManager>> _mockLogger;
    private JwtTokenConfig _jwtTokenConfig;
    private DefaultJwtAuthManager _jwtAuthManager;
    private readonly DateTime _utcNow = new(2030, 1, 1, 12, 0, 0, DateTimeKind.Utc);

    [TestInitialize]
    public void Setup()
    {
        _mockRefreshTokenStore = new Mock<IRefreshTokenStore>();
        _mockLogger = new Mock<ILogger<DefaultJwtAuthManager>>();
        _jwtTokenConfig = new JwtTokenConfig
        {
            Secret = "this-is-a-very-long-secret-key-for-testing-purposes-12345",
            Issuer = "test-issuer",
            Audience = "test-audience",
            AccessTokenExpiration = 15,
            RefreshTokenExpiration = 60
        };
        _jwtAuthManager = new DefaultJwtAuthManager(_jwtTokenConfig, _mockRefreshTokenStore.Object, _mockLogger.Object);
    }

    [TestMethod]
    public void Constructor_ShouldInitializeProperties()
    {
        // Arrange & Act
        var manager = new DefaultJwtAuthManager(_jwtTokenConfig, _mockRefreshTokenStore.Object, _mockLogger.Object);

        // Assert
        Assert.AreEqual(_jwtTokenConfig, manager.JwtTokenConfig);
    }

    [TestMethod]
    public async Task GetAdditionalInfo_WithValidRefreshToken_ShouldReturnAdditionalInfo()
    {
        // Arrange
        var refreshToken = "test-refresh-token";
        var expectedAdditionalInfo = "test-additional-info";
        var mockRefreshTokenData = new RefreshToken
        {
            UserIdentifier = "test-user",
            TokenString = refreshToken,
            AdditionalInfo = expectedAdditionalInfo,
            ExpireAt = _utcNow.AddMinutes(30)
        };
        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken))
            .ReturnsAsync(mockRefreshTokenData);

        // Act
        var result = await _jwtAuthManager.GetAdditionalInfo(refreshToken);

        // Assert
        Assert.AreEqual(expectedAdditionalInfo, result);
    }

    [TestMethod]
    public async Task GetAdditionalInfo_WithInvalidRefreshToken_ShouldReturnNull()
    {
        // Arrange
        var refreshToken = "invalid-refresh-token";
        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken))
            .ReturnsAsync((RefreshToken)null);

        // Act
        var result = await _jwtAuthManager.GetAdditionalInfo(refreshToken);

        // Assert
        Assert.IsNull(result);
    }

    [TestMethod]
    public async Task RemoveExpiredRefreshTokens_ShouldRemoveExpiredTokens()
    {
        // Arrange
        var expiredTokens = new List<KeyValuePair<string, RefreshToken>>
        {
            new("key1", new RefreshToken { UserIdentifier = "user1", ExpireAt = _utcNow.AddMinutes(-10) }),
            new("key2", new RefreshToken { UserIdentifier = "user2", ExpireAt = _utcNow.AddMinutes(-5) })
        };
        _mockRefreshTokenStore.Setup(x => x.GetTokensBefore(_utcNow))
            .ReturnsAsync(expiredTokens);

        // Act
        await _jwtAuthManager.RemoveExpiredRefreshTokens(_utcNow);

        // Assert
        _mockRefreshTokenStore.Verify(x => x.Remove("key1"), Times.Once);
        _mockRefreshTokenStore.Verify(x => x.Remove("key2"), Times.Once);
    }

    [TestMethod]
    public async Task RemoveRefreshToken_ShouldRemoveAllTokensForIdentifier()
    {
        // Arrange
        var identifier = "test-user";
        var userTokens = new List<KeyValuePair<string, RefreshToken>>
        {
            new("key1", new RefreshToken { UserIdentifier = identifier }),
            new("key2", new RefreshToken { UserIdentifier = identifier })
        };
        _mockRefreshTokenStore.Setup(x => x.GetTokensByIdentifier(identifier))
            .ReturnsAsync(userTokens);

        // Act
        await _jwtAuthManager.RemoveRefreshToken(identifier);

        // Assert
        _mockRefreshTokenStore.Verify(x => x.Remove("key1"), Times.Once);
        _mockRefreshTokenStore.Verify(x => x.Remove("key2"), Times.Once);
    }

    [TestMethod]
    public async Task RemoveNotLatestRefreshTokens_ShouldCallRefreshTokenStore()
    {
        // Arrange
        var userIdentifier = "test-user";

        // Act
        await _jwtAuthManager.RemoveNotLatestRefreshTokens(userIdentifier);

        // Assert
        _mockRefreshTokenStore.Verify(x => x.RemoveNonLatestTokens(userIdentifier), Times.Once);
    }

    [TestMethod]
    public async Task GenerateTokens_WithValidParameters_ShouldReturnJwtAuthResult()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claims = new[]
        {
            new Claim(ClaimTypes.Name, "Test User"),
            new Claim(ClaimTypes.Email, "test@example.com")
        };
        var additionalInfo = "test-info";

        // Act
        var result = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow, additionalInfo);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsNotNull(result.AccessToken);
        Assert.IsNotNull(result.RefreshToken);
        Assert.AreEqual(userIdentifier, result.RefreshToken.UserIdentifier);
        Assert.AreEqual(additionalInfo, result.RefreshToken.AdditionalInfo);
        Assert.AreEqual(_utcNow.AddMinutes(_jwtTokenConfig.RefreshTokenExpiration), result.RefreshToken.ExpireAt);
        
        _mockRefreshTokenStore.Verify(x => x.AddOrUpdate(It.IsAny<string>(), It.IsAny<RefreshToken>()), Times.Once);
    }

    [TestMethod]
    public async Task GenerateTokens_WithAudienceClaim_ShouldNotAddAudienceToToken()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Aud, "custom-audience"),
            new Claim(ClaimTypes.Name, "Test User")
        };

        // Act
        var result = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow);

        // Assert
        Assert.IsNotNull(result.AccessToken);
        var handler = new JwtSecurityTokenHandler();
        var token = handler.ReadJwtToken(result.AccessToken);
        Assert.AreEqual("custom-audience", token.Audiences.FirstOrDefault());
    }

    [TestMethod]
    public void DecodeJwtToken_WithNullToken_ShouldThrowSecurityTokenException()
    {
        // Act & Assert
        Assert.ThrowsExactly<SecurityTokenException>(() => _jwtAuthManager.DecodeJwtToken(null));
    }

    [TestMethod]
    public void DecodeJwtToken_WithEmptyToken_ShouldThrowSecurityTokenException()
    {
        // Act & Assert
        Assert.ThrowsExactly<SecurityTokenException>(() => _jwtAuthManager.DecodeJwtToken(""));
    }

    [TestMethod]
    public void DecodeJwtToken_WithInvalidToken_ShouldThrowSecurityTokenMalformedException()
    {
        // Act & Assert
        Assert.ThrowsExactly<SecurityTokenMalformedException>(() => _jwtAuthManager.DecodeJwtToken("invalid-token"));
    }

    [TestMethod]
    public async Task Refresh_WithValidTokens_ShouldReturnRefreshTokenResult()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claimName = "UserId";
        var claims = new[]
        {
            new Claim(claimName, userIdentifier),
            new Claim(ClaimTypes.Name, "Test User")
        };
        
        var originalTokens = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow);
        var refreshToken = originalTokens.RefreshToken;
        var accessToken = originalTokens.AccessToken;

        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken.TokenString))
            .ReturnsAsync(refreshToken);

        // Act
        var result = await _jwtAuthManager.Refresh(refreshToken.TokenString, accessToken, claimName, _utcNow);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsNotNull(result.AccessToken);
        Assert.IsNotNull(result.RefreshToken);
        Assert.IsNotNull(result.ClaimsPrincipal);
        Assert.AreEqual(userIdentifier, result.ClaimsPrincipal.FindFirst(claimName)?.Value);
    }

    [TestMethod]
    public async Task Refresh_WithExpiredAccessToken_ShouldStillWork()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claimName = "UserId";
        var claims = new[]
        {
            new Claim(claimName, userIdentifier),
            new Claim(ClaimTypes.Name, "Test User")
        };
        
        var pastTime = _utcNow.AddMinutes(-30);
        var originalTokens = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, pastTime);
        var refreshToken = originalTokens.RefreshToken;
        var accessToken = originalTokens.AccessToken;

        refreshToken.ExpireAt = _utcNow.AddMinutes(30); // Refresh token still valid

        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken.TokenString))
            .ReturnsAsync(refreshToken);

        // Act
        var result = await _jwtAuthManager.Refresh(refreshToken.TokenString, accessToken, claimName, _utcNow);

        // Assert
        Assert.IsNotNull(result);
        Assert.IsNotNull(result.AccessToken);
        Assert.IsNotNull(result.RefreshToken);
        Assert.IsNotNull(result.ClaimsPrincipal);
    }

    [TestMethod]
    public async Task Refresh_WithInvalidRefreshToken_ShouldThrowSecurityTokenException()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claimName = "UserId";
        var claims = new[] { new Claim(claimName, userIdentifier) };
        var originalTokens = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow);
        var accessToken = originalTokens.AccessToken;

        _mockRefreshTokenStore.Setup(x => x.Get(It.IsAny<string>()))
            .ReturnsAsync((RefreshToken)null);

        // Act & Assert
        await Assert.ThrowsExactlyAsync<SecurityTokenException>(() => 
            _jwtAuthManager.Refresh("invalid-refresh-token", accessToken, claimName, _utcNow));
    }

    [TestMethod]
    public async Task Refresh_WithExpiredRefreshToken_ShouldThrowSecurityTokenException()
    {
        // Arrange
        var userIdentifier = "test-user";
        var claimName = "UserId";
        var claims = new[] { new Claim(claimName, userIdentifier) };
        var originalTokens = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow);
        var refreshToken = originalTokens.RefreshToken;
        var accessToken = originalTokens.AccessToken;

        refreshToken.ExpireAt = _utcNow.AddMinutes(-10); // Expired refresh token

        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken.TokenString))
            .ReturnsAsync(refreshToken);

        // Act & Assert
        await Assert.ThrowsExactlyAsync<SecurityTokenException>(() => 
            _jwtAuthManager.Refresh(refreshToken.TokenString, accessToken, claimName, _utcNow));
    }

    [TestMethod]
    public async Task Refresh_WithMismatchedUserIdentifier_ShouldThrowSecurityTokenException()
    {
        // Arrange
        var userIdentifier = "test-user";
        var differentUserIdentifier = "different-user";
        var claimName = "UserId";
        var claims = new[] { new Claim(claimName, userIdentifier) };
        var originalTokens = await _jwtAuthManager.GenerateTokens(userIdentifier, claims, _utcNow);
        var refreshToken = originalTokens.RefreshToken;
        var accessToken = originalTokens.AccessToken;

        refreshToken.UserIdentifier = differentUserIdentifier; // Different user

        _mockRefreshTokenStore.Setup(x => x.Get(refreshToken.TokenString))
            .ReturnsAsync(refreshToken);

        // Act & Assert
        await Assert.ThrowsExactlyAsync<SecurityTokenException>(() => 
            _jwtAuthManager.Refresh(refreshToken.TokenString, accessToken, claimName, _utcNow));
    }
}