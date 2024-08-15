using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.Jwt.SqlServer;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddSqlServerRefreshTokenStore(this JwtAuthServiceCollectionBuilder builder, string connectionStringKey)
    {
        var connectionString = builder.Configuration.GetConnectionString(connectionStringKey);
        var services = builder.Services.AddTransient<IRefreshTokenStore>(p => new SqlServerRefreshTokenStore(connectionString));

        using var connection = new SqlConnection(connectionString);
        connection.Open();
        EnsureRefreshTokenTableCreated(connection);

        return services;
    }

    private static void EnsureRefreshTokenTableCreated(SqlConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = @"
            IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'RefreshTokens')
            BEGIN
                CREATE TABLE RefreshTokens
                (
                    Id VARCHAR(64) PRIMARY KEY NOT NULL,
                    UserIdentifier NVARCHAR(450) NOT NULL,
                    TokenString NVARCHAR(MAX) NOT NULL,
                    ExpireAt DATETIME NOT NULL
                )
            END";
        command.ExecuteNonQuery();
    }
}