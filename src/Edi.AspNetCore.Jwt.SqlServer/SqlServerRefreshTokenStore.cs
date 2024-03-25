using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Edi.AspNetCore.Jwt.SqlServer;

public class SqlServerRefreshTokenStore : IRefreshTokenStore
{
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
}