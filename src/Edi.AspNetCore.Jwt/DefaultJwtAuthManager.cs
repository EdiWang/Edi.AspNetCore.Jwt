using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace Edi.AspNetCore.Jwt;

public class DefaultJwtAuthManager : IJwtAuthManager
{
    public JwtTokenConfig JwtTokenConfig { get; }

    private readonly IRefreshTokenStore _refreshTokenStore;
    private readonly byte[] _secret;

    public DefaultJwtAuthManager(JwtTokenConfig jwtTokenConfig, IRefreshTokenStore refreshTokenStore)
    {
        JwtTokenConfig = jwtTokenConfig;
        _refreshTokenStore = refreshTokenStore;
        _secret = Encoding.ASCII.GetBytes(jwtTokenConfig.Secret);
    }

    public async Task RemoveExpiredRefreshTokens(DateTime utcNow)
    {
        var expiredTokens = await _refreshTokenStore.GetTokensBefore(utcNow);
        foreach (var expiredToken in expiredTokens)
        {
            await _refreshTokenStore.Remove(expiredToken.Key);
        }
    }

    public async Task RemoveRefreshToken(string identifier)
    {
        var refreshTokens = await _refreshTokenStore.GetTokensByIdentifier(identifier);
        foreach (var refreshToken in refreshTokens)
        {
            await _refreshTokenStore.Remove(refreshToken.Key);
        }
    }

    public async Task<JwtAuthResult> GenerateTokens(string identifier, Claim[] claims, DateTime utcNow)
    {
        var shouldAddAudienceClaim = string.IsNullOrWhiteSpace(claims?.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Aud)?.Value);
        var jwtToken = new JwtSecurityToken(
            JwtTokenConfig.Issuer,
            shouldAddAudienceClaim ? JwtTokenConfig.Audience : string.Empty,
            claims,
            expires: utcNow.AddMinutes(JwtTokenConfig.AccessTokenExpiration),
            signingCredentials: new(new SymmetricSecurityKey(_secret), "HS256"));
        var accessToken = new JwtSecurityTokenHandler().WriteToken(jwtToken);

        var refreshToken = new RefreshToken
        {
            Identifier = identifier,
            TokenString = GenerateRefreshTokenString(),
            ExpireAt = utcNow.AddMinutes(JwtTokenConfig.RefreshTokenExpiration)
        };

        await _refreshTokenStore.AddOrUpdate(refreshToken.TokenString, refreshToken);

        return new()
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken
        };
    }

    public async Task<RefreshTokenResult> Refresh(string refreshToken, string accessToken, string claimName, DateTime utcNow)
    {
        ClaimsPrincipal principal = null;

        try
        {
            var (principal2, jwtToken) = DecodeJwtToken(accessToken);
            if (jwtToken == null || !jwtToken.Header.Alg.Equals("HS256"))
            {
                throw new SecurityTokenException("Invalid token");
            }

            principal = principal2;
        }
        catch (SecurityTokenExpiredException)
        {
            principal = GetPrincipalFromExpiredToken(accessToken);
        }

        var identifier = principal.Claims.First(p => p.Type == claimName).Value;
        var existingRefreshToken = await _refreshTokenStore.Get(refreshToken);

        if (null == existingRefreshToken)
        {
            throw new SecurityTokenException("Invalid token");
        }
        if (existingRefreshToken.Identifier != identifier || existingRefreshToken.ExpireAt < utcNow)
        {
            throw new SecurityTokenException("Invalid token");
        }

        var tokens = await GenerateTokens(identifier, principal.Claims.ToArray(), utcNow);

        return new()
        {
            ClaimsPrincipal = principal,
            AccessToken = tokens.AccessToken,
            RefreshToken = tokens.RefreshToken
        };
    }

    public (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new SecurityTokenException("Invalid token");
        }

        var principal = new JwtSecurityTokenHandler()
            .ValidateToken(token,
                new()
                {
                    ValidateIssuer = true,
                    ValidIssuer = JwtTokenConfig.Issuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(_secret),
                    ValidAudience = JwtTokenConfig.Audience,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                },
                out var validatedToken);
        return (principal, validatedToken as JwtSecurityToken);
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(_secret),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }

    private static string GenerateRefreshTokenString()
    {
        var randomNumber = new byte[32];
        using var randomNumberGenerator = RandomNumberGenerator.Create();
        randomNumberGenerator.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}