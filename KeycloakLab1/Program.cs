using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        // Keycloak OIDC metadata endpoint — .NET fetches JWKS from here automatically
        options.Authority = "http://localhost:8081/realms/myrealm";

        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer           = true,
            ValidIssuer              = "http://localhost:8081/realms/myrealm",
            ValidateAudience         = true,   // public client — no client_secret, no aud claim
            ValidAudiences   = new[] { "my-webapp"},
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true     // .NET auto-fetches RS256 public key via JWKS
        };

        // Allow HTTP for local dev (Keycloak not on HTTPS here)
        options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Public endpoint — no token needed
app.MapGet("/public", () => Results.Ok(new { message = "This is public. No token needed." }));

// Protected endpoint — valid JWT required
app.MapGet("/protected", (ClaimsPrincipal user) =>
{
    var username = user.FindFirst("preferred_username")?.Value ?? "unknown";
    var roles    = user.FindAll("realm_access")
                       .Select(c => c.Value)
                       .ToList();

    // Keycloak puts realm roles inside a nested JSON claim — let's surface the raw claims too
    var allClaims = user.Claims.Select(c => new { c.Type, c.Value }).ToList();

    return Results.Ok(new
    {
        message  = $"Hello, {username}! Your token is valid.",
        username,
        allClaims
    });
})
.RequireAuthorization();

app.Run();