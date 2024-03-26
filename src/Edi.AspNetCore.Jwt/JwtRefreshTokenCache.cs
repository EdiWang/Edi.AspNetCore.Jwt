using Microsoft.Extensions.Hosting;

namespace Edi.AspNetCore.Jwt;

public class JwtRefreshTokenCache(IJwtAuthManager jwtAuthManager) : IHostedService, IDisposable
{
    private Timer _timer;

    public Task StartAsync(CancellationToken stoppingToken)
    {
        _timer = new(DoWork, null, TimeSpan.Zero, TimeSpan.FromMinutes(1));
        return Task.CompletedTask;
    }

    private void DoWork(object state)
    {
        jwtAuthManager.RemoveExpiredRefreshTokens(DateTime.UtcNow);
    }

    public Task StopAsync(CancellationToken stoppingToken)
    {
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose() => _timer?.Dispose();
}