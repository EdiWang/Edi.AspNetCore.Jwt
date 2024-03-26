using Microsoft.Data.SqlClient;
using System.Data;

namespace Edi.AspNetCore.Jwt.SqlServer;

public class SqlServerRefreshTokenStore(string connectionString) : IRefreshTokenStore, IDisposable
{
    private readonly SqlConnection _connection = new(connectionString);

    public async Task AddOrUpdate(string key, RefreshToken token)
    {
        EnsureRefreshTokenTableCreated();

        await using var command = _connection.CreateCommand();
        command.CommandText = @"
            MERGE INTO RefreshTokens AS target
            USING (SELECT @Id, @UserIdentifier, @TokenString, @ExpireAt) AS source (Id, UserIdentifier, TokenString, ExpireAt)
            ON target.Id = source.Id
            WHEN MATCHED THEN
                UPDATE SET TokenString = source.TokenString, ExpireAt = source.ExpireAt
            WHEN NOT MATCHED THEN
                INSERT (Id, UserIdentifier, TokenString, ExpireAt)
                VALUES (source.Id, source.UserIdentifier, source.TokenString, source.ExpireAt);";

        command.AddParameter("@Id", DbType.String, key);
        command.AddParameter("@UserIdentifier", DbType.String, token.UserIdentifier);
        command.AddParameter("@TokenString", DbType.String, token.TokenString);
        command.AddParameter("@ExpireAt", DbType.DateTime, token.ExpireAt);

        await command.ExecuteNonQueryAsync();
    }

    public async Task<RefreshToken> Get(string key)
    {
        EnsureRefreshTokenTableCreated();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT UserIdentifier, TokenString, ExpireAt FROM RefreshTokens WHERE Id = @Id";
        command.AddParameter("@Id", DbType.String, key);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return new RefreshToken
        {
            UserIdentifier = reader.GetString(0),
            TokenString = reader.GetString(1),
            ExpireAt = reader.GetDateTime(2)
        };
    }

    public async Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time)
    {
        EnsureRefreshTokenTableCreated();

        var tokens = new List<KeyValuePair<string, RefreshToken>>();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Id, UserIdentifier, TokenString, ExpireAt FROM RefreshTokens WHERE ExpireAt < @ExpireAt";
        command.AddParameter("@ExpireAt", DbType.DateTime, time);
        await command.ExecuteNonQueryAsync();

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            tokens.Add(new KeyValuePair<string, RefreshToken>(
                reader.GetString(0),
                new RefreshToken
                {
                    UserIdentifier = reader.GetString(1),
                    TokenString = reader.GetString(2),
                    ExpireAt = reader.GetDateTime(3)
                }));
        }

        return tokens;
    }

    public async Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string userIdentifier)
    {
        EnsureRefreshTokenTableCreated();

        var tokens = new List<KeyValuePair<string, RefreshToken>>();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Id, TokenString, ExpireAt FROM RefreshTokens WHERE UserIdentifier = @UserIdentifier";
        command.AddParameter("@UserIdentifier", DbType.String, userIdentifier);
        await command.ExecuteNonQueryAsync();

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            tokens.Add(new KeyValuePair<string, RefreshToken>(
                               reader.GetString(0),
                               new RefreshToken
                               {
                                   UserIdentifier = userIdentifier,
                                   TokenString = reader.GetString(1),
                                   ExpireAt = reader.GetDateTime(2)
                               }));
        }

        return tokens;
    }

    public async Task Remove(string key)
    {
        EnsureRefreshTokenTableCreated();

        await using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM RefreshTokens WHERE Id = @Id";
        command.AddParameter("@Id", DbType.String, key);

        await command.ExecuteNonQueryAsync();
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
                    Id VARCHAR(64) PRIMARY KEY NOT NULL,
                    UserIdentifier NVARCHAR(450) NOT NULL,
                    TokenString NVARCHAR(MAX) NOT NULL,
                    ExpireAt DATETIME NOT NULL
                )
            END";
        command.ExecuteNonQuery();
    }
}

public static class DbCommandExtensionMethods
{
    public static void AddParameter(this IDbCommand command, string name, DbType type, object value)
    {
        var parameter = command.CreateParameter();
        parameter.ParameterName = name;
        parameter.DbType = type;
        parameter.Value = value;
        command.Parameters.Add(parameter);
    }
}