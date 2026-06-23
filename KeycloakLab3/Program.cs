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
            ValidateAudience         = true,
            ValidAudiences           = ["lab3-service"],
            ValidateLifetime         = true,
            ValidateIssuerSigningKey = true
        };
        options.RequireHttpsMetadata = false;
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("ReportsRead", policy =>
        policy.RequireAssertion(ctx => HasScope(ctx.User, "reports:read")));

    options.AddPolicy("ReportsWrite", policy =>
        policy.RequireAssertion(ctx => HasScope(ctx.User, "reports:write")));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Public — no token needed
app.MapGet("/public", () =>
    Results.Ok(new { message = "Public endpoint. No token needed." }));

// Protected — any valid JWT (any scope)
app.MapGet("/protected", (ClaimsPrincipal user) =>
    Results.Ok(new { message = $"Hello service '{user.FindFirst("sub")?.Value}'. You have a valid token." }))
    .RequireAuthorization();

// Scope-protected — requires reports:read
app.MapGet("/reports", (ClaimsPrincipal user) =>
    Results.Ok(new { message = "Reports data. You have the 'reports:read' scope." }))
    .RequireAuthorization("ReportsRead");

// Scope-protected — requires reports:write
app.MapPost("/reports", (ClaimsPrincipal user) =>
    Results.Ok(new { message = "Report created. You have the 'reports:write' scope." }))
    .RequireAuthorization("ReportsWrite");

app.Run();

// Keycloak sends 'scope' as a single space-separated string,
// so we split it and check membership.
static bool HasScope(System.Security.Claims.ClaimsPrincipal user, string scope)
{
    var raw = user.FindFirst("scope")?.Value;
    return raw is not null && raw.Split(' ').Contains(scope);
}
