using Microsoft.Data.SqlClient;
using System.Data;

namespace Edi.AspNetCore.Jwt.SqlServer;

public class SqlServerRefreshTokenStore(string connectionString) : IRefreshTokenStore, IDisposable
{
    private readonly SqlConnection _connection = new(connectionString);

    public async Task AddOrUpdate(string key, RefreshToken token)
    {
        await OpenConnectionAsync();

        await using var command = _connection.CreateCommand();
        command.CommandText = @"
            MERGE INTO RefreshTokens AS target
            USING (SELECT @Id, @UserIdentifier, @TokenString, @ExpireAt, @AdditionalInfo) AS source (Id, UserIdentifier, TokenString, ExpireAt, AdditionalInfo)
            ON target.Id = source.Id
            WHEN MATCHED THEN
                UPDATE SET TokenString = source.TokenString, ExpireAt = source.ExpireAt, AdditionalInfo = source.AdditionalInfo
            WHEN NOT MATCHED THEN
                INSERT (Id, UserIdentifier, TokenString, ExpireAt, AdditionalInfo)
                VALUES (source.Id, source.UserIdentifier, source.TokenString, source.ExpireAt, source.AdditionalInfo);";

        command.AddParameter("@Id", DbType.String, key);
        command.AddParameter("@UserIdentifier", DbType.String, token.UserIdentifier);
        command.AddParameter("@TokenString", DbType.String, token.TokenString);
        command.AddParameter("@ExpireAt", DbType.DateTime, token.ExpireAt);
        command.AddParameter("@AdditionalInfo", DbType.String, token.AdditionalInfo);

        await command.ExecuteNonQueryAsync();
    }

    public async Task<RefreshToken> Get(string token)
    {
        await OpenConnectionAsync();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT UserIdentifier, TokenString, ExpireAt, AdditionalInfo FROM RefreshTokens WHERE TokenString = @TokenString";
        command.AddParameter("@TokenString", DbType.String, token);

        await using var reader = await command.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return null;
        }

        return new()
        {
            UserIdentifier = reader.GetString(0),
            TokenString = reader.GetString(1),
            ExpireAt = reader.GetDateTime(2),
            AdditionalInfo = reader.GetString(3)
        };
    }

    public async Task<List<KeyValuePair<string, RefreshToken>>> GetTokensBefore(DateTime time)
    {
        await OpenConnectionAsync();

        var tokens = new List<KeyValuePair<string, RefreshToken>>();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Id, UserIdentifier, TokenString, ExpireAt, AdditionalInfo FROM RefreshTokens WHERE ExpireAt < @ExpireAt";
        command.AddParameter("@ExpireAt", DbType.DateTime, time);
        await command.ExecuteNonQueryAsync();

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            tokens.Add(new(
                reader.GetString(0),
                new()
                {
                    UserIdentifier = reader.GetString(1),
                    TokenString = reader.GetString(2),
                    ExpireAt = reader.GetDateTime(3),
                    AdditionalInfo = reader.GetString(4)
                }));
        }

        return tokens;
    }

    public async Task<List<KeyValuePair<string, RefreshToken>>> GetTokensByIdentifier(string userIdentifier)
    {
        await OpenConnectionAsync();

        var tokens = new List<KeyValuePair<string, RefreshToken>>();

        await using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Id, TokenString, ExpireAt, AdditionalInfo FROM RefreshTokens WHERE UserIdentifier = @UserIdentifier";
        command.AddParameter("@UserIdentifier", DbType.String, userIdentifier);

        await using var reader = await command.ExecuteReaderAsync();
        while (await reader.ReadAsync())
        {
            tokens.Add(new(
                               reader.GetString(0),
                               new()
                               {
                                   UserIdentifier = userIdentifier,
                                   TokenString = reader.GetString(1),
                                   ExpireAt = reader.GetDateTime(2),
                                   AdditionalInfo = reader.GetString(3)
                               }));
        }

        return tokens;
    }

    public async Task RemoveNonLatestTokens(string userIdentifier)
    {
        await OpenConnectionAsync();

        await using var command = _connection.CreateCommand();
        command.CommandText = @"
            WITH LatestTokens AS (
                SELECT Id, ROW_NUMBER() OVER (PARTITION BY UserIdentifier ORDER BY ExpireAt DESC) AS RowNumber
                FROM RefreshTokens
                WHERE UserIdentifier = @UserIdentifier
            )
            DELETE FROM LatestTokens WHERE RowNumber > 1;";

        command.AddParameter("@UserIdentifier", DbType.String, userIdentifier);

        await command.ExecuteNonQueryAsync();
    }

    public async Task Remove(string key)
    {
        await OpenConnectionAsync();

        await using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM RefreshTokens WHERE Id = @Id";
        command.AddParameter("@Id", DbType.String, key);

        await command.ExecuteNonQueryAsync();
    }

    public async Task Clear()
    {
        await OpenConnectionAsync();

        await using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM RefreshTokens";

        await command.ExecuteNonQueryAsync();
    }

    public void Dispose()
    {
        _connection?.Close();
        _connection?.Dispose();
    }

    private async Task OpenConnectionAsync()
    {
        if (_connection.State != ConnectionState.Open)
        {
            await _connection.OpenAsync();
        }
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