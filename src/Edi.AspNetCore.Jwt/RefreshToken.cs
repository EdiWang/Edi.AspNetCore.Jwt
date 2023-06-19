namespace Edi.AspNetCore.Jwt;

public record RefreshToken
{
    public string Identifier { get; set; }

    public string TokenString { get; set; }

    public DateTime ExpireAt { get; set; }
}