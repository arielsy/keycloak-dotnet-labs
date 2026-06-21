# OAuth 2.0 / OIDC Hands-On Labs — Keycloak + .NET 8 + Kong

> A hands-on, incremental exploration of authentication and authorization.
> Each lab is a small, runnable project that exposes one piece of the OAuth 2.0 / OpenID Connect machinery — the stuff that normally happens invisibly behind "Sign in with Google."
>
> **Stack:** Keycloak (Authorization Server) · ASP.NET Core .NET 8 Minimal API (Resource Server) · Postman (Client) · Kong (API Gateway).

---

## Why this repo exists

Authentication and authorization are the foundation of every real system — and the best way to understand them is to build them, not just read about them.

This repo is a working reference implementation, assembled lab by lab. Each lab isolates one concept (the auth-code flow, roles, machine-to-machine auth, token lifecycle, gateway-level auth) so it can be *seen* in action rather than taken on faith. The end state is something to return to whenever I need to implement or reason about OAuth in a real project.

---

## Mental model — the three roles

Every flow in this repo is some combination of three actors. Keep this picture in mind and nothing gets confusing:

| Role | OAuth term | In these labs |
|------|------------|---------------|
| Who proves identity / issues tokens | **Authorization Server (AS)** | Keycloak |
| Who holds the protected data | **Resource Server (RS)** | .NET Minimal API |
| Who wants access on a user's behalf | **Client** | Postman (later: a real app / Kong) |

> The Authorization Server issues a signed token. The Resource Server validates that token's signature — it never has to call the AS per-request; it fetches the public keys once via **JWKS**. The Client just carries the token between them.

---

## Repository structure

```
keycloak-dotnet-labs/
├── README.md                      ← this file
├── .gitignore                     ← dotnet new gitignore
├── lab1-pkce-auth-code/           ← ✅ done
│   ├── README.md
│   └── KeycloakLab1/
├── lab2-role-authorization/
├── lab3-client-credentials/
├── lab4-claims-transformation/
├── lab5-refresh-tokens/
└── lab6-kong-gateway/             ← Kong sits in front of everything
    ├── docker-compose.yml
    └── kong.yml
```

---

## Prerequisites

- **Docker** (Keycloak + Kong run as containers)
- **.NET 8 SDK** — verify with `dotnet --version` (must report `8.x`)
- **Postman** (or any HTTP client)
- A code editor

> **Hard-won note from Lab 1:** when adding NuGet packages on an SDK that *also* has newer runtimes available, NuGet may resolve a package version for the wrong target framework. Always pin: `dotnet add package <name> --version 8.0.x`. (Lab 1 broke because `JwtBearer 10.x` was pulled into a `net8.0` project.)

---

## Lab status overview

| Lab | Topic | OAuth flow / concept | Status | Why it matters |
|-----|-------|----------------------|--------|----------------|
| 1 | PKCE + Authorization Code | User login, the canonical browser flow | ✅ Done | The flow behind every "Sign in with X" |
| 2 | Role-Based Authorization | `RequireRole`, policies | ⬜ Next | Every system needs to restrict who can do what |
| 3 | Client Credentials | Machine-to-machine (no user) | ⬜ | The correct pattern for service-to-service calls |
| 4 | Claims Transformation | Mapping `realm_access.roles` → .NET roles | ⬜ | Fixes the real gotcha Lab 1 exposes |
| 5 | Refresh Tokens | Token lifecycle, expiry, introspection | ⬜ | Production token management |
| 6 | Kong API Gateway | Gateway-level auth offload | ⬜ | Centralizing cross-cutting concerns at the edge |

---

## Lab 1 — Authorization Code + PKCE ✅

**Goal:** A full Authorization Code + PKCE flow working end-to-end between Keycloak and a .NET Minimal API.

### What I built
- A Keycloak realm (`myrealm`) with a **public client** (`my-webapp`, PKCE enforced).
- A test user (`testuser`) with a realm role (`analyst`).
- A .NET 8 Minimal API with `AddJwtBearer` pointing at Keycloak.
- A `/protected` endpoint that requires a valid JWT.

### Setup (the commands that actually worked)

```bash
# 1. Keycloak
docker run -d --name keycloak -p 8081:8080 \
  -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:24.0.3 start-dev

# 2. .NET project (run dotnet commands from INSIDE the project folder, not its parent)
mkdir -p keycloak-dotnet-labs && cd keycloak-dotnet-labs
dotnet new webapi -minimal -n KeycloakLab1 --no-openapi
cd KeycloakLab1
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer --version 8.0.15
dotnet restore
dotnet run
```

> In Keycloak 24+, enable **Require PKCE** directly on the client's *Capability config* screen — it enforces `S256` automatically, so the old "Advanced tab → Code Challenge Method" step is no longer needed.

### Key configuration in `Program.cs`

```csharp
.AddJwtBearer(options =>
{
    options.Authority = "http://localhost:8081/realms/myrealm";   // .NET auto-fetches JWKS from here
    options.RequireHttpsMetadata = false;                          // local dev only
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer           = true,
        ValidIssuer              = "http://localhost:8081/realms/myrealm",
        ValidateAudience         = false,   // public client → no aud
        ValidateLifetime         = true,
        ValidateIssuerSigningKey = true     // RS256 signature checked against Keycloak's public key
    };
});
```

### Concepts that finally clicked

**1. PKCE: `S256` vs `plain`.**
`S256` sends `BASE64URL(SHA256(verifier))` as the challenge; `plain` sends the raw verifier. With `plain`, anyone who intercepts the authorization request gets the verifier and can steal the token. With `S256` they only get an irreversible hash. **Always use `S256`** — `plain` exists only for devices that physically can't run SHA-256.

**2. The two tokens are NOT the same thing.**
The flow produces two completely different values:

```
Authorization Code   →  short, opaque, single-use, ~60s lifetime
                        (Keycloak format: code.session.clientSession, 3 dot-separated parts)
                        delivered in the browser redirect URL: .../callback?code=XXXX

         ↓ exchanged at the /token endpoint (code + code_verifier)

Access Token (JWT)   →  the long eyJhbGci... string
                        carried as: Authorization: Bearer <JWT>
                        this is the ONLY thing the .NET API ever sees
```

The Authorization Code is the claim ticket; the JWT is the meal you trade it for. The code never reaches the Resource Server.

**3. The JWT vs the decoded claims.**
The raw `eyJhbGci...` token (3 parts: header.payload.signature) is the JWT. `jwt.io` just *decodes* it visually (and trusts whatever you paste). The .NET API *decodes **and** cryptographically validates* it via JWKS before trusting a single claim — which is why a `200 OK` from `/protected` is a stronger statement than `jwt.io` showing the same payload.

**4. The flow, manually.**
Doing the flow by hand (building the `/auth` URL in the browser, copying the `code` from the redirect, POSTing it to `/token`) reveals exactly what a real app does in milliseconds and invisibly. Same flow as "Sign in with Google" — server-side apps, SPAs, and mobile apps just read the code from the redirect and exchange it before the user ever notices.

---

## Lab 2 — Role-Based Authorization ⬜ (next)

**Goal:** Restrict an endpoint to users who hold the `analyst` role.

**What to implement**
```csharp
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AnalystOnly", policy => policy.RequireRole("analyst"));
});

app.MapGet("/analyst-only", () => "You are an analyst.")
   .RequireAuthorization("AnalystOnly");
```

**What you'll discover:** this *won't work out of the box*. Keycloak puts realm roles inside a nested JSON claim (`realm_access.roles`), not in the flat `role` claim .NET's `RequireRole` looks for. That failure is the bridge into Lab 4.

**Concepts:** policy-based vs role-based authorization · `[Authorize]` vs `.RequireAuthorization()` · where Keycloak stores roles (`realm_access` for realm roles, `resource_access` for client roles).

---

## Lab 3 — Client Credentials (machine-to-machine) ⬜

> The correct OAuth flow for service-to-service authentication, where no user is involved — common in any multi-service system.

**Goal:** Service A authenticates as *itself* (not as a user) to call Service B.

```
Service A ──(client_id + client_secret)──▶ Keycloak ──(JWT)──▶ Service A
Service A ──(Authorization: Bearer JWT)──▶ Service B  ──validates via JWKS──▶ ✅
```

**What to configure in Keycloak**
- A **confidential** client (`Client authentication = On`) with **Service accounts roles** enabled.
- Assign service-account roles to that client.

**Token request (no browser, no user):**
```bash
curl -X POST http://localhost:8081/realms/myrealm/protocol/openid-connect/token \
  -d "grant_type=client_credentials" \
  -d "client_id=service-a" \
  -d "client_secret=<secret>"
```

**Key idea:** each service authenticates as its own identity rather than impersonating a user — the correct pattern for machine-to-machine in OAuth 2.0.

---

## Lab 4 — Claims Transformation ⬜

**Goal:** Make Keycloak's nested `realm_access.roles` actually work with .NET's `[Authorize(Roles = ...)]` and `RequireRole`.

**The problem (seen directly in Lab 1):** the token comes back with
```json
"realm_access": { "roles": ["analyst", "default-roles-myrealm", "offline_access", "uma_authorization"] }
```
.NET sees this as a single string claim, not as individual role claims — so role checks silently fail.

**The fix — flatten the roles on token validation:**
```csharp
options.Events = new JwtBearerEvents
{
    OnTokenValidated = context =>
    {
        var identity = (ClaimsIdentity)context.Principal!.Identity!;
        var realmAccess = context.Principal.FindFirst("realm_access")?.Value;
        if (realmAccess is not null)
        {
            using var doc = JsonDocument.Parse(realmAccess);
            if (doc.RootElement.TryGetProperty("roles", out var roles))
                foreach (var role in roles.EnumerateArray())
                    identity.AddClaim(new Claim(ClaimTypes.Role, role.GetString()!));
        }
        return Task.CompletedTask;
    }
};
```

**Concepts:** the .NET claims pipeline · `ClaimsIdentity` / `ClaimsPrincipal` · why provider claim shapes rarely match framework defaults · custom `RoleClaimType`.

---

## Lab 5 — Refresh Tokens & Token Lifecycle ⬜

**Goal:** Understand the full lifecycle of a token — issue, use, expire, refresh, revoke.

**What to explore**
- The `refresh_token` returned alongside the access token in Lab 1.
- Exchanging a refresh token for a fresh access token (`grant_type=refresh_token`).
- Token expiry tuning in Keycloak (Realm settings → Tokens).
- **Token introspection** — the AS endpoint that answers "is this token still valid?" for opaque/online validation, vs offline JWKS signature validation.

**Concepts:** access vs refresh vs ID token · short-lived access + long-lived refresh as a security pattern · offline validation (JWKS, fast, no AS call) vs online validation (introspection, can detect revocation) and the trade-off between them.

---

## Lab 6 — Kong API Gateway in front of the .NET API ⬜

> Moves cross-cutting concerns — routing, rate limiting, and eventually **authentication itself** — out of the service and onto the gateway.

### Why a gateway at all

In a multi-service system you don't want every service re-implementing token validation, rate limiting, CORS, and logging. A gateway centralizes those concerns at the edge:

```
                         ┌─────────────────────────────┐
   Client ──────────────▶│   Kong API Gateway          │
   (Bearer JWT)          │   • routing                 │
                         │   • rate limiting           │
                         │   • CORS                    │
                         │   • (Stage B) JWT validation│
                         └──────────────┬──────────────┘
                                        │ forwards valid requests
                                        ▼
                              .NET Minimal API (RS)
                                        ▲
                                        │ JWKS (RS256 public keys)
                              Keycloak (AS)
```

### The Kong reality check (read before you start)

The plugin landscape, so you don't hit a wall:

- **Kong's *official* OpenID Connect plugin is Enterprise-only** (closed source). It does full discovery, the relying-party auth-code flow, and introspection out of the box — but it's a paid feature.
- **Kong OSS (free) ships a bundled `jwt` plugin** that validates HS256/**RS256** JWTs. It works with Keycloak tokens, but you must register Keycloak's realm public key manually as a consumer credential. No automatic key rotation.
- **For full JWKS auto-discovery on OSS**, there's an actively maintained community plugin (`telekom-digioss/kong-plugin-jwt-keycloak`, successor to the older archived `gbbirkisson` repo) that fetches keys from Keycloak's `.well-known` + `/certs` endpoints and can check roles/scopes — but it requires baking a custom Kong image.

So the lab has three stages of increasing realism. Start at A.

### Stage A — Kong as a reverse proxy (fully OSS, runnable today)

Run Kong **DB-less** with a declarative config. No auth yet — just prove routing + rate limiting + CORS work in front of the .NET API.

`lab6-kong-gateway/docker-compose.yml`
```yaml
services:
  kong:
    image: kong:3.7
    environment:
      KONG_DATABASE: "off"
      KONG_DECLARATIVE_CONFIG: /kong/kong.yml
      KONG_PROXY_LISTEN: "0.0.0.0:8000"
      KONG_ADMIN_LISTEN: "0.0.0.0:8001"
    volumes:
      - ./kong.yml:/kong/kong.yml:ro
    ports:
      - "8000:8000"   # proxy  (clients hit this)
      - "8001:8001"   # admin API
```

`lab6-kong-gateway/kong.yml`
```yaml
_format_version: "3.0"

services:
  - name: dotnet-api
    url: http://host.docker.internal:5000   # Mac: reaches the .NET API on the host
    routes:
      - name: api-route
        paths:
          - /api
        strip_path: true
    plugins:
      - name: rate-limiting
        config:
          minute: 20
          policy: local
      - name: cors
```

> Make the .NET API listen on `0.0.0.0`, not just `localhost`, or Kong (in its container) can't reach it:
> `dotnet run --urls "http://0.0.0.0:5000"`

Test: `curl http://localhost:8000/api/public` should now hit your `/public` endpoint *through Kong*, and the 21st request in a minute should return `429 Too Many Requests`.

### Stage B — Gateway-level JWT validation with a static key (still OSS)

Now Kong rejects requests without a valid Keycloak token **before** they ever reach the .NET service.

1. **Get Keycloak's realm public key:** Admin Console → *Realm settings → Keys → RS256 row → Public key*. Wrap the base64 in PEM headers:
   ```
   -----BEGIN PUBLIC KEY-----
   MIIBIjANBgkqhkiG9w0BAQ...
   -----END PUBLIC KEY-----
   ```
2. **Add the `jwt` plugin + a consumer** holding that key. The consumer's `key` **must equal the token's `iss`**:

```yaml
plugins:
  - name: jwt          # add under the dotnet-api service

consumers:
  - username: keycloak
    jwt_secrets:
      - key: "http://localhost:8081/realms/myrealm"   # must match the iss claim exactly
        algorithm: RS256
        rsa_public_key: |
          -----BEGIN PUBLIC KEY-----
          MIIBIjANBgkqhkiG9w0BAQ...
          -----END PUBLIC KEY-----
        secret: "dummy"   # required dummy value for RS algorithms in declarative config
```

Test: a request **without** a Bearer token → `401` from Kong. **With** a valid Keycloak JWT → forwarded to the .NET API → `200`.

> Trade-off: a static key means you must update Kong by hand whenever Keycloak rotates signing keys. That's the motivation for Stage C.

### Stage C — JWKS auto-discovery (stretch, production-grade)

Swap the static key for the community `jwt-keycloak` plugin so Kong pulls public keys from Keycloak's JWKS endpoint automatically (handles key rotation) and can enforce roles/scopes at the edge. Requires building a custom Kong image with the plugin (`KONG_PLUGINS=bundled,jwt-keycloak`). Document the Dockerfile and config here once Stage B is solid.

### The architectural decision this lab teaches

**Where should authentication live — at each service, or at the gateway?**

| | Auth at each service (Labs 1–5) | Auth at the gateway (Lab 6) |
|--|--------------------------------|------------------------------|
| Who validates the token | Every service, independently | Kong, once, at the edge |
| Duplication | Each service re-implements validation | Centralized, single policy |
| Failure surface | Distributed | Gateway is a critical chokepoint |
| Typical use | Small systems, internal trust | Larger systems, centralized policy |

The mature answer most teams converge on: **authentication at the gateway** (validate the token once at the edge), **fine-grained authorization in the service** (domain-specific role/permission logic stays where the domain knowledge is). The gateway can still do coarse-grained authz (require a scope/role to reach a route); the service decides what that role is actually allowed to *do*. The token is still forwarded downstream so services can read claims.

It's the same kind of centralize-vs-distribute, single-chokepoint-vs-duplication trade-off that shows up all over distributed-systems design.

---

## How this repo is built

- One lab at a time, fully runnable before moving on.
- Each lab gets its own folder + a short `README.md` (goal, setup, what to observe).
- Committed incrementally, so the history reflects the actual learning process rather than one big dump at the end.

## Commit conventions (Conventional Commits)

```
feat: scaffold Lab1 Keycloak + .NET Minimal API
feat: validate RS256 JWT via JWKS in Lab1
docs: add Lab1 README with PKCE flow notes
feat: add Lab2 role-based authorization policy
fix: flatten realm_access.roles into .NET role claims (Lab4)
feat: add Lab6 Kong reverse proxy with rate limiting
```

## Don't forget

```bash
dotnet new gitignore   # before the first push — keeps bin/ and obj/ out of the repo
```

---

## Quick reference / glossary

| Term | One-line meaning |
|------|------------------|
| **OAuth 2.0** | Authorization framework — delegated access via tokens |
| **OIDC** | Identity layer on top of OAuth 2.0 (adds the ID token + user info) |
| **Authorization Server (AS)** | Issues tokens — here, Keycloak |
| **Resource Server (RS)** | Holds protected data, validates tokens — here, the .NET API |
| **PKCE** | Proof Key for Code Exchange — protects the auth-code flow from interception (`S256`) |
| **Authorization Code** | Short-lived, single-use ticket delivered in the redirect URL |
| **Access Token (JWT)** | The signed `eyJ...` token carried in the `Authorization: Bearer` header |
| **Refresh Token** | Long-lived token used to obtain new access tokens |
| **JWKS** | JSON Web Key Set — the AS's public keys, used to verify token signatures offline |
| **Client Credentials** | Machine-to-machine flow — a service authenticates as itself, no user |
| **Realm (Keycloak)** | An isolated tenant of users, clients, roles |
| **realm_access / resource_access** | Where Keycloak stores realm roles / client roles in the token |
| **API Gateway** | Edge component centralizing routing, rate limiting, auth — here, Kong |

## References

- Keycloak docs — https://www.keycloak.org/documentation
- ASP.NET Core JWT bearer auth — https://learn.microsoft.com/aspnet/core/security/authentication
- Kong Gateway plugins (Plugin Hub) — https://developer.konghq.com/plugins/
- Kong bundled JWT plugin — https://developer.konghq.com/plugins/jwt/
- Community JWKS plugin for Keycloak — https://github.com/telekom-digioss/kong-plugin-jwt-keycloak
- RFC 7636 (PKCE) · RFC 7519 (JWT) · RFC 6749 (OAuth 2.0)
