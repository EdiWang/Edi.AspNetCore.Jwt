# Edi.AspNetCore.Jwt

[![.NET Build and Pack](https://github.com/EdiWang/Edi.AspNetCore.Jwt/actions/workflows/dotnet.yml/badge.svg)](https://github.com/EdiWang/Edi.AspNetCore.Jwt/actions/workflows/dotnet.yml)

JWT authentication library for my own

## Install from NuGet

```powershell
dotnet add package Edi.AspNetCore.Jwt --version 0.9.4-beta.5
dotnet add package Edi.AspNetCore.Jwt.InMemory --version 0.9.4-beta.5
```

```powershell
NuGet\Install-Package Edi.AspNetCore.Jwt --version 0.9.4-beta.5
NuGet\Install-Package Edi.AspNetCore.Jwt.InMemory --version 0.9.4-beta.5
```

```xml
<PackageReference Include="Edi.AspNetCore.Jwt" Version="0.9.5-beta.5" />
<PackageReference Include="Edi.AspNetCore.Jwt.InMemory" Version="0.9.5-beta.5" />
```

## Usage

### ASP.NET Core

#### `Program.cs`

```csharp
builder.Services.AddJwtAuth<DefaultJwtAuthManager>(builder.Configuration)
                .AddInMemoryRefreshTokenStore();
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

## 免责申明

此项目(Edi.AspNetCore.Jwt)及其配套组件均为免费开源的产品，仅用于学习交流，并且不直接向中国提供服务，中国用户请于下载后立即删除。

任何中国境内的组织及个人不得使用此项目(Edi.AspNetCore.Jwt)及其配套组件构建任何形式的面向中国境内用户的网站或服务。

不可用于任何违反中华人民共和国(含台湾省)或使用者所在地区法律法规的用途。

因为作者即本人仅完成代码的开发和开源活动(开源即任何人都可以下载使用)，从未参与用户的任何运营和盈利活动。

且不知晓用户后续将程序源代码用于何种用途，故用户使用过程中所带来的任何法律责任即由用户自己承担。

[《开源软件有漏洞，作者需要负责吗？是的！》](https://go.edi.wang/aka/os251)