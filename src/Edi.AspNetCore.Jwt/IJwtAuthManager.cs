using System.Collections.Immutable;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Edi.AspNetCore.Jwt;

public interface IJwtAuthManager
{
    public JwtTokenConfig JwtTokenConfig { get; }
    IImmutableDictionary<string, RefreshToken> UsersRefreshTokensReadOnlyDictionary { get; }
    JwtAuthResult GenerateTokens(string identifier, Claim[] claims, DateTime utcNow);
    RefreshTokenResult Refresh(string refreshToken, string accessToken, string claimName, DateTime utcNow);
    void RemoveExpiredRefreshTokens(DateTime utcNow);
    void RemoveRefreshToken(string identifier);
    (ClaimsPrincipal, JwtSecurityToken) DecodeJwtToken(string token);
}
