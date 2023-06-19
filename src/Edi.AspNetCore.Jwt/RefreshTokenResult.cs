using System.Security.Claims;
using System.Text.Json.Serialization;

namespace Edi.AspNetCore.Jwt;

public class RefreshTokenResult
{
    public string AccessToken { get; set; }

    [JsonIgnore]
    public RefreshToken RefreshToken { get; set; }

    [JsonIgnore]
    public ClaimsPrincipal ClaimsPrincipal { get; set; }
}