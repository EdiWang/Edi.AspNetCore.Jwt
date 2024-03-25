using Microsoft.Data.SqlClient;
using System.Collections.Concurrent;
using System.Data;

namespace Edi.AspNetCore.Jwt.SqlServer;

public class SqlServerRefreshTokenStore : IRefreshTokenStore, IDisposable
{
    private readonly string _connectionString;
    private readonly IDbConnection _connection;

    public SqlServerRefreshTokenStore(string connectionString)
    {
        _connectionString = connectionString;
        _connection = new SqlConnection(_connectionString);
    }

    public ConcurrentDictionary<string, RefreshToken> RefreshTokens { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }

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
}