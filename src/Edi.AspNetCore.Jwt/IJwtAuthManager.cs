using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Edi.AspNetCore.Jwt;

public interface IJwtAuthManager
{
    public JwtTokenConfig JwtTokenConfig { get; }
    Task<JwtAuthResult> GenerateTokens(string userIdentifier, Claim[] claims, DateTime utcNow, string additionalInfo = null);
    Task<RefreshTokenResult> Refresh(string refreshToken, string accessToken, string claimName, DateTime utcNow);
    Task RemoveExpiredRefreshTokens(DateTime utcNow);
    Task RemoveRefreshToken(string identifier);
    Task RemoveNotLatestRefreshTokens(string userIdentifier);
    (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);
}
