using Edi.AspNetCore.Jwt;
using Edi.AspNetCore.Jwt.InMemory;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddJwtAuth<DefaultJwtAuthManager>(builder.Configuration).AddInMemoryRefreshTokenStore();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
