# Copilot Instructions

## Project Overview

This repository contains a small JWT authentication library for ASP.NET Core.

- Main package: `src/Edi.AspNetCore.Jwt`
- SQL Server refresh token provider: `src/Edi.AspNetCore.Jwt.SqlServer`
- Unit tests: `src/Edi.AspNetCore.Jwt.Tests`
- Manual sample API: `src/TestApi`
- Solution file: `src/Edi.AspNetCore.Jwt.slnx`

The public API is intentionally compact. Prefer focused changes that preserve the current usage pattern:

```csharp
builder.Services.AddJwtAuth<DefaultJwtAuthManager>(builder.Configuration)
                .AddInMemoryRefreshTokenStore();
```

## Build and Test

Run commands from the `src` directory unless a task explicitly says otherwise.

```powershell
dotnet build --configuration Release
dotnet test --configuration Release
dotnet pack --configuration Release -o nupkg
```

The GitHub Actions workflow uses .NET `10.0.x` and runs build, test, and pack from `./src`.

## Target Frameworks and Packaging

- Projects target `net10.0`.
- `ImplicitUsings` are enabled.
- Library projects set `GeneratePackageOnBuild` to `true`.
- Keep NuGet package metadata consistent between the main package and the SQL Server provider.
- In `Edi.AspNetCore.Jwt.SqlServer`, keep the existing Debug/Release dependency pattern: Debug uses a project reference to the main package, Release uses the published `Edi.AspNetCore.Jwt` package.

## Coding Style

- Follow the existing C# style: file-scoped namespaces, primary constructors where already used, expression-bodied members for short methods, and object initializers.
- Keep code simple and dependency-light. This library should stay easy to consume in ASP.NET Core apps.
- Prefer async APIs for token store operations because `IRefreshTokenStore` is asynchronous.
- Use `DateTime.UtcNow` or an injected/test-provided UTC timestamp for token expiration logic. Tests should use fixed UTC dates for deterministic behavior.
- Do not enable nullable reference types or introduce broad formatting-only churn unless specifically requested.
- Add comments only when they clarify non-obvious behavior. Avoid restating the code.

## JWT and Security Behavior

- Preserve validation behavior unless the task explicitly changes authentication semantics:
  - issuer validation enabled
  - audience validation enabled
  - signing key validation enabled
  - lifetime validation enabled for normal decoding
  - one-minute clock skew
  - HMAC SHA-256 signing
- Refresh token strings must remain cryptographically random. Use `RandomNumberGenerator` or an equivalent cryptographic API.
- Do not log secrets, access tokens, refresh token strings, connection strings, or other credentials.
- Keep refresh token cleanup behavior compatible with `JwtRefreshTokenCache`, which removes expired tokens periodically through `IJwtAuthManager.RemoveExpiredRefreshTokens`.

## Refresh Token Stores

- `IRefreshTokenStore` is the shared contract. Any new store should implement the same behavior as the in-memory and SQL Server stores.
- `InMemoryRefreshTokenStore` uses `ConcurrentDictionary<string, RefreshToken>` and is suitable for tests and simple development scenarios.
- `SqlServerRefreshTokenStore` owns SQL Server persistence and uses parameterized commands. Do not build SQL by concatenating user-provided values.
- If changing the SQL Server schema, update creation logic in `AddSqlServerRefreshTokenStore` and consider backward compatibility for existing tables.

## Tests

- Tests use xUnit v3 and Moq.
- Add or update tests in `src/Edi.AspNetCore.Jwt.Tests` for behavioral changes in token generation, refresh, cleanup, or stores.
- Prefer clear Arrange/Act/Assert tests matching the existing naming style, for example `Method_WithCondition_ShouldExpectedResult`.
- Use fixed UTC timestamps in tests instead of the live clock.
- For public API changes, include tests that exercise the consumer-facing behavior rather than only implementation details.

## Sample API and Documentation

- Keep `src/TestApi` as a lightweight manual verification sample.
- Update `README.md` when consumer setup, configuration keys, public APIs, or package installation steps change.
- The expected configuration section is `JWTConfig` with `Secret`, `Issuer`, `Audience`, `AccessTokenExpiration`, and `RefreshTokenExpiration`.

## Public API Compatibility

- Treat `IJwtAuthManager`, `IRefreshTokenStore`, `JwtTokenConfig`, `RefreshToken`, `JwtAuthResult`, and extension methods as public package surface.
- Avoid breaking method signatures, configuration names, package IDs, namespaces, or common DI registration flows unless explicitly requested.
- When adding new features, prefer additive APIs and preserve existing behavior for current consumers.