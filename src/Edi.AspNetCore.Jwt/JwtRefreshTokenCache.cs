using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Edi.AspNetCore.Jwt;

public class JwtRefreshTokenCache(IJwtAuthManager jwtAuthManager, ILogger<JwtRefreshTokenCache> logger) : IHostedService, IDisposable
{
    private Timer _timer;

    public Task StartAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Starting refresh token cache.");

        _timer = new(DoWork, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
        return Task.CompletedTask;
    }

    private void DoWork(object state)
    {
        jwtAuthManager.RemoveExpiredRefreshTokens(DateTime.UtcNow);
    }

    public Task StopAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Stopping refresh token cache.");

        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose() => _timer?.Dispose();
}