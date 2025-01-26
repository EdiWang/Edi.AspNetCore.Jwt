# Edi.AspNetCore.Jwt

[![.NET Build and Pack](https://github.com/EdiWang/Edi.AspNetCore.Jwt/actions/workflows/dotnet.yml/badge.svg)](https://github.com/EdiWang/Edi.AspNetCore.Jwt/actions/workflows/dotnet.yml)

A very basic JWT authentication library for quickly integrating JWT authentication in ASP.NET Core applications.

## Install

```powershell
dotnet add package Edi.AspNetCore.Jwt
```

For SQL Server token storage, also

```powershell
dotnet add package Edi.AspNetCore.Jwt.SqlServer
```

## Usage

### ASP.NET Core

#### `Program.cs`

```csharp
builder.Services.AddJwtAuth<DefaultJwtAuthManager>(builder.Configuration)
                .AddInMemoryRefreshTokenStore(); 
                // For SQL Server token storage, also 
                // .AddSqlServerRefreshTokenStore("DefaultConnection");
```

#### `appsettings.json`

```json
"JWTConfig": {
  "Secret": "b9e942ac-dd01-4523-9e0e-21f4f642fe74",
  "Issuer": "edi.wang",
  "Audience": "edi",
  "AccessTokenExpiration": 20,
  "RefreshTokenExpiration": 480
}
```

For SQL Server token storage, also

```json
"ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=work996;Trusted_Connection=True;"
}
```

#### DI

```csharp
private readonly IJwtAuthManager _jwtAuthManager;

public AccountController(IJwtAuthManager jwtAuthManager)
{
    _jwtAuthManager = jwtAuthManager;
}
```

#### Sign In

```csharp
var claims = new List<Claim>
    {
        new("UserId", user.Id.ToString()),
        new(ClaimTypes.Name, user.DisplayName),
        new(ClaimTypes.Email, request.Email),
    };
claims.AddRange(user.Roles.Select(role => (Claim)new(ClaimTypes.Role, role.ShortCode)));

var jwtResult = _jwtAuthManager.GenerateTokens(request.Email, claims.ToArray(), DateTime.UtcNow);

SetRefreshTokenCookie(jwtResult.RefreshToken.TokenString);

return Ok(new LoginResult
{
    AccessToken = jwtResult.AccessToken.TokenString
});
```

```csharp
private void SetRefreshTokenCookie(string token)
{
    var cookieOptions = new CookieOptions
    {
        Secure = true,
        SameSite = SameSiteMode.None,
        HttpOnly = true,
        Expires = DateTime.UtcNow.AddMinutes(_jwtAuthManager.JwtTokenConfig.RefreshTokenExpiration)
    };
    Response.Cookies.Append("refreshToken", token, cookieOptions);
}
```

#### Refresh Token

```csharp
var refreshToken = Request.Cookies["refreshToken"];

var hasAuthHeader = Request.Headers.TryGetValue("Authorization", out var authHeaderValue);
if (!hasAuthHeader) return Unauthorized("No Authorization header");

var parseAuthHeader = AuthenticationHeaderValue.TryParse(authHeaderValue, out var accessToken);
if (!parseAuthHeader) return Unauthorized("Unable to parse Authorization header");

var jwtResult = _jwtAuthManager.Refresh(refreshToken, accessToken.Parameter, ClaimTypes.Email, DateTime.UtcNow);

SetRefreshTokenCookie(jwtResult.RefreshToken.TokenString);

return Ok(jwtResult);
```

#### Sign Out

```csharp
var email = User.FindFirst(p => p.Type == ClaimTypes.Email)?.Value;
_jwtAuthManager.RemoveRefreshToken(email);
```
