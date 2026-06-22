using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.Text.Json;

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
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true
        };
        options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AnalystOnly", policy =>
        //policy.RequireClaim("realm_access_roles", "analyst"));
        policy.RequireRole("analyst"));
});

builder.Services.AddTransient<IClaimsTransformation, KeycloakRolesClaimsTransformer>();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Public — no token needed
app.MapGet("/public", () => Results.Ok(new { message = "Public endpoint. No token needed." }));

// Protected — any valid JWT
app.MapGet("/protected", (ClaimsPrincipal user) =>
    Results.Ok(new { message = $"Hello {user.FindFirst("preferred_username")?.Value}. You have a valid token." }))
    .RequireAuthorization();

// Role-protected — only users with the 'analyst' role
app.MapGet("/analyst", (ClaimsPrincipal user) =>
    Results.Ok(new { message = $"Hello {user.FindFirst("preferred_username")?.Value}. You are an analyst." }))
    .RequireAuthorization("AnalystOnly");

app.Run();

public class KeycloakRolesClaimsTransformer : IClaimsTransformation
{
    public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        var identity = (ClaimsIdentity)principal.Identity!;
        var realmAccess = principal.FindFirst("realm_access")?.Value;
        if (realmAccess != null)
        {
            var parsed = JsonDocument.Parse(realmAccess);
            if (parsed.RootElement.TryGetProperty("roles", out var roles))
            {
                foreach (var role in roles.EnumerateArray())
                    identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString()!));
            }
        }
        return Task.FromResult(principal);
    }
}