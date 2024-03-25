using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.Jwt.SqlServer;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSqlServerRefreshTokenStore(this JwtAuthServiceCollectionBuilder builder, string connectionStringKey)
    {
        var connectionString = builder.Configuration.GetConnectionString(connectionStringKey);
        var services = builder.Services.AddScoped<IRefreshTokenStore>(p => new SqlServerRefreshTokenStore(connectionString));

        return services;
    }
}