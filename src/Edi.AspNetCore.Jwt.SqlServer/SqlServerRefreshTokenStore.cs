using Microsoft.Data.SqlClient;
using System.Collections.Concurrent;
using System.Data;

namespace Edi.AspNetCore.Jwt.SqlServer;

public class SqlServerRefreshTokenStore(string connectionString) : IRefreshTokenStore, IDisposable
{
    private readonly IDbConnection _connection = new SqlConnection(connectionString);

    public Task AddOrUpdate(string key, RefreshToken token)
    {
        throw new NotImplementedException();
    }

    public Task<RefreshToken> Get(string key)
    {
        throw new NotImplementedException();
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time)
    {
        throw new NotImplementedException();
    }

    public Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string identifier)
    {
        throw new NotImplementedException();
    }

    public Task Remove(string key)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        _connection?.Dispose();
    }

    private void EnsureRefreshTokenTableCreated()
    {
        using var command = _connection.CreateCommand();
        command.CommandText = @"
            IF NOT EXISTS (SELECT 1 FROM sys.tables WHERE name = 'RefreshTokens')
            BEGIN
                CREATE TABLE RefreshTokens
                (
                    Id UNIQUEIDENTIFIER PRIMARY KEY NOT NULL,
                    Identifier NVARCHAR(450) NOT NULL,
                    TokenString NVARCHAR(MAX) PRIMARY KEY NOT NULL,
                    ExpireAt DATETIME NOT NULL
                )
            END";
        command.ExecuteNonQuery();
    }
}