using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Edi.AspNetCore.Jwt;

public class JwtAuthServiceCollectionBuilder
{
    public IServiceCollection Services { get; set; }

    public JwtAuthServiceCollectionBuilder(IServiceCollection services) => Services = services;

    public IServiceCollection AddRefreshTokenStore<TImplementation>() where TImplementation : class, IRefreshTokenStore
    {
        return Services.AddSingleton<IRefreshTokenStore, TImplementation>();
    }
}

public static class ServiceCollectionExtensions
{
    public static JwtAuthServiceCollectionBuilder AddJwtAuth<T>(this IServiceCollection services, IConfiguration configuration) where T : class, IJwtAuthManager
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

        services.AddSingleton<IJwtAuthManager, T>()
                .AddHostedService<JwtRefreshTokenCache>();

        return new(services);
    }
}