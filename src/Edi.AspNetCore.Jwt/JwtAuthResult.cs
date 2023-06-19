namespace Edi.AspNetCore.Jwt;

public class JwtAuthResult
{
    public string AccessToken { get; set; }

    public RefreshToken RefreshToken { get; set; }
}