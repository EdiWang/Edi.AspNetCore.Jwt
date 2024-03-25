using Microsoft.Extensions.DependencyInjection;

namespace Edi.AspNetCore.Jwt.InMemory;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddInMemoryRefreshTokenStore(this JwtAuthServiceCollectionBuilder builder)
    {
        var services = builder.Services.AddSingleton<IRefreshTokenStore, InMemoryRefreshTokenStore>();
        return services;
    }
}