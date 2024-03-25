using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.Jwt.SqlServer;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSqlServerRefreshTokenStore(this JwtAuthServiceCollectionBuilder builder)
    {
        var services = builder.AddRefreshTokenStore<SqlServerRefreshTokenStore>();
        return services;
    }
}