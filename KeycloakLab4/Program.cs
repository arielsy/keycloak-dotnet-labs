using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.Authority = "http://localhost:8081/realms/myrealm";
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = "http://localhost:8081/realms/myrealm",
            ValidateAudience         = false,
            ValidateLifetime         = true,   // ← the star of this lab: rejects expired tokens
            ValidateIssuerSigningKey = true,
            ClockSkew                = TimeSpan.Zero   // ← default is 5 min; zero so a 60s token dies at 60s
        };
        options.RequireHttpsMetadata = false;
        // Make the auth pipeline visible in the server console
        options.Events = new JwtBearerEvents
        {
            OnTokenValidated       = ctx => { Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [auth] ✅ token validated"); return Task.CompletedTask; },
            OnAuthenticationFailed = ctx => { Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [auth] ❌ failed: {ctx.Exception.Message}"); return Task.CompletedTask; },
            OnChallenge            = ctx => { Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [auth] 🚪 challenge → about to return 401"); return Task.CompletedTask; }
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Public — no token needed
app.MapGet("/public", () =>
    Results.Ok(new { message = "Public endpoint. No token needed." }));

// Protected — any valid (non-expired) token. Returns 401 once the access token expires.
app.MapGet("/protected", (ClaimsPrincipal user) =>
    Results.Ok(new { message = $"Hello {user.FindFirst("preferred_username")?.Value}. Token still valid." }))
    .RequireAuthorization();

// Lifecycle view — surface the token's timeline so expiry is visible, not abstract.
app.MapGet("/token-info", (ClaimsPrincipal user) =>
{
    long iat = long.Parse(user.FindFirst("iat")!.Value);
    long exp = long.Parse(user.FindFirst("exp")!.Value);
    var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] [/token-info] user={user.FindFirst("preferred_username")?.Value} remaining={exp - now}s");
    return Results.Ok(new
    {
        issuedAt         = DateTimeOffset.FromUnixTimeSeconds(iat).ToString("u"),
        expiresAt        = DateTimeOffset.FromUnixTimeSeconds(exp).ToString("u"),
        lifetimeSeconds  = exp - iat,
        remainingSeconds = exp - now
    });
}).RequireAuthorization();

app.Run();
