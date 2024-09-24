namespace Edi.AspNetCore.Jwt;

public record RefreshToken
{
    public string UserIdentifier { get; set; }

    public string TokenString { get; set; }

    public DateTime ExpireAt { get; set; }

    public string AdditionalInfo { get; set; }
}