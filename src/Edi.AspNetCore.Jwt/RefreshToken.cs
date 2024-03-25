namespace Edi.AspNetCore.Jwt;

public record RefreshToken
{
    public Guid Id { get; set; }

    public string UserIdentifier { get; set; }

    public string TokenString { get; set; }

    public DateTime ExpireAt { get; set; }
}