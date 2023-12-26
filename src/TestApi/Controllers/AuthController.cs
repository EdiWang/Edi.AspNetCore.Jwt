using System.Net.Http.Headers;
using System.Security.Claims;
using Edi.AspNetCore.Jwt;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace TestApi.Controllers;

[ApiController]
[Authorize]
[Route("api/[controller]")]
public class AuthController(IJwtAuthManager jwtAuthManager) : ControllerBase
{
    [AllowAnonymous]
    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(LoginResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> Login([FromBody] LoginRequest request)
    {
        if (request.Password != "123456")
        {
            return Unauthorized("Invalid credential, the correct password is: 123456");
        }

        var claims = new List<Claim>
        {
            new("UserId", Guid.Empty.ToString()),
            new(ClaimTypes.Name, "Edi"),
            new(ClaimTypes.Email, request.Email),
            new("CustomValue", "test")
        };

        var jwtResult = await jwtAuthManager.GenerateTokens(request.Email, claims.ToArray(), DateTime.UtcNow);

        SetRefreshTokenCookie(jwtResult.RefreshToken.TokenString);

        return Ok(new LoginResult
        {
            UserId = Guid.Empty,
            Email = request.Email,
            AccessToken = jwtResult.AccessToken
        });
    }

    [AllowAnonymous]
    [HttpPost("refresh-token")]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(typeof(LoginResult), StatusCodes.Status200OK)]
    public async Task<IActionResult> RefreshToken()
    {
        try
        {
            var refreshToken = Request.Cookies["refreshToken"];
            if (string.IsNullOrWhiteSpace(refreshToken)) return Unauthorized("Empty refreshToken");

            var hasAuthHeader = Request.Headers.TryGetValue("Authorization", out var authHeaderValue);
            if (!hasAuthHeader) return Unauthorized("No Authorization header");

            var parseAuthHeader = AuthenticationHeaderValue.TryParse(authHeaderValue, out var accessToken);
            if (!parseAuthHeader) return Unauthorized("Unable to parse Authorization header");

            //var accessToken = await HttpContext.GetTokenAsync("Bearer", "access_token");
            var jwtResult = await jwtAuthManager.Refresh(refreshToken, accessToken.Parameter, ClaimTypes.Email, DateTime.UtcNow);

            SetRefreshTokenCookie(jwtResult.RefreshToken.TokenString);

            return Ok(jwtResult);
        }
        catch (SecurityTokenException e)
        {
            return Unauthorized(e.Message); // return 401 so that the client side can redirect the user to login page
        }
    }

    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    public async Task<IActionResult> Logout()
    {
        // optionally "revoke" JWT token on the server side --> add the current token to a block-list
        // https://github.com/auth0/node-jsonwebtoken/issues/375

        var email = User.FindFirst(p => p.Type == ClaimTypes.Email)?.Value;
        await jwtAuthManager.RemoveRefreshToken(email);

        return Ok();
    }

    private void SetRefreshTokenCookie(string token)
    {
        var cookieOptions = new CookieOptions
        {
            Secure = true,
            SameSite = SameSiteMode.None,
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddMinutes(jwtAuthManager.JwtTokenConfig.RefreshTokenExpiration)
        };
        Response.Cookies.Append("refreshToken", token, cookieOptions);
    }
}

public class LoginRequest
{
    public string Email { get; set; }

    public string Password { get; set; }
}

public class LoginResult
{
    public Guid UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public string AccessToken { get; set; }
}