using Edi.AspNetCore.Jwt;
//using Edi.AspNetCore.Jwt.SqlServer;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddJwtAuth<DefaultJwtAuthManager>(builder.Configuration)
                //.AddSqlServerRefreshTokenStore("DefaultConnection");
                .AddInMemoryRefreshTokenStore();

var app = builder.Build();

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
