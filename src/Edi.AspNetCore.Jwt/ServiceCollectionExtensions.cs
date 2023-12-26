using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Edi.AspNetCore.Jwt;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddJwtAuth<T>(this IServiceCollection services, IConfiguration configuration) where T : class, IJwtAuthManager
    {
        var jwtTokenConfig = configuration.GetSection("JWTConfig").Get<JwtTokenConfig>();

        services.AddSingleton(jwtTokenConfig)
            .AddAuthentication(x =>
            {
                x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddJwtBearer(x =>
            {
                x.RequireHttpsMetadata = true;
                x.SaveToken = true;
                x.TokenValidationParameters = new()
                {
                    ValidateIssuer = true,
                    ValidIssuer = jwtTokenConfig.Issuer,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(jwtTokenConfig.Secret)),
                    ValidAudience = jwtTokenConfig.Audience,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ClockSkew = TimeSpan.FromMinutes(1)
                };
            });

        services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();

        services.AddSingleton<IJwtAuthManager, T>()
                .AddHostedService<JwtRefreshTokenCache>();

        return services;
    }
}