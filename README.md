# OAuth 2.0 / OIDC Hands-On Labs — Keycloak + .NET 8 + Kong

I'm building this lab series to learn authentication and authorization in depth
and use it as a future reference. These concepts are at the core of digital
security, and the best way to understand them is to build them, not just read
about them.

**Stack:** Keycloak · ASP.NET Core .NET 8 Minimal API · Postman · Kong

---

## Lab 1 — Authorization Code + PKCE ✅

**Goal:** Work through a real Authorization Code + PKCE flow end-to-end to
understand what actually happens behind every "Sign in with X" button.

### What I built
- A Keycloak realm with a public client (PKCE enforced)
- A test user with a realm role (`analyst`)
- A .NET 8 Minimal API that validates JWTs issued by Keycloak
- A `/protected` endpoint that requires a valid token

### What clicked
The terminology was the hardest part — not because the concepts are complex,
but because the names point at the spec, not at what things actually do.

PKCE is the clearest example. The name "Proof Key for Code Exchange" made more
sense once I stopped reading it as a technical label and started reading it as
a guarantee: *the app that starts the flow is the same one that finishes it.*

### What broke
The `redirect_uri` in the authorization URL must match **exactly** what is
registered in Keycloak's client settings — including the protocol (`http` vs
`https`). Keycloak rejects anything that doesn't match, which is a security
feature, not a bug: without this check, an attacker could redirect the
authorization code to their own server.

---

## Lab 2 — Role-Based Authorization ✅

**Goal:** Restrict API endpoints to specific roles, so a valid token isn't
enough — the user also needs the right permission.

### What I built
- An `analyst` realm role in Keycloak, assigned to one user but not the other
- A .NET 8 Minimal API with three endpoints: `/public`, `/protected`, and `/analyst`
- A claims transformer that flattens Keycloak's nested role structure into
  standard .NET role claims
- Policy-based authorization using `RequireRole("analyst")`

### What clicked
JWTs are **stateless** — the API never calls Keycloak on each request. On
startup, .NET fetches Keycloak's public key from the JWKS endpoint and caches
it. Every incoming token is verified locally using that key. No round-trip
to Keycloak needed.

The JWKS endpoint is intentionally public. The security comes from the fact
that only Keycloak holds the **private key** used to sign tokens — the public
key can only verify, never forge.

### What broke
Keycloak puts realm roles in a nested JSON structure inside the token:

```json
{
  "realm_access": {
    "roles": ["analyst"]
  }
}
```

.NET's auth system expects flat claims, not nested JSON — so `RequireRole`
returned 403 for everyone, including the analyst user. The fix was a custom
`IClaimsTransformation` that reads the nested structure on each request and
adds each role as a standard `ClaimTypes.Role` claim. This is something you'll
hit in every real Keycloak + .NET project.

---

## Lab 3 — Client Credentials + Scope-Based Authorization ✅

**Goal:** Authenticate a *service* instead of a user (machine-to-machine), and
authorize endpoints by **scope** rather than role. This is the pattern behind
backend services calling each other with no human in the loop.

### What I built
- A confidential Keycloak client (`lab3-service`) with **Service accounts**
  enabled — this turns on the `client_credentials` grant
- Two custom client scopes: `reports:read` and `reports:write`
- A .NET 8 Minimal API with `/public`, `/protected`, `GET /reports`
  (needs `reports:read`) and `POST /reports` (needs `reports:write`)
- Scope-based policies using `RequireAssertion` to check the `scope` claim

### What clicked
With `client_credentials` there's **no user and no browser redirect** — the
service POSTs its `client_id` + `client_secret` straight to the token endpoint
and gets an access token back. The token's `sub` is the service account, not a
person (`preferred_username` is `service-account-lab3-service`).

The mental model that stuck: **roles describe *who you are*, scopes describe
*what this token is allowed to do*.** For M2M, scopes are the natural fit.

I also finally internalized the difference between the two failure codes:
- **401 Unauthorized** → "I don't know who you are" (bad/missing/expired token)
- **403 Forbidden** → "I know who you are, but you can't do this" (missing scope)

### What broke
This lab broke in three different places — each one taught something:

1. **Scope not in the token.** Requesting `scope=reports:read reports:write`
   wasn't enough. The custom scopes had to (a) exist as client scopes, (b) be
   assigned to `lab3-service`, and (c) have **Include in token scope** turned on.
   Without that last toggle, the scope name silently never reaches the token.

2. **403 even with the right scope.** Keycloak sends `scope` as a **single
   space-separated string** (`"reports:read profile email reports:write"`), not
   as separate claims. So `RequireClaim("scope", "reports:read")` does an exact
   match against the *whole* string and always fails. The fix was a
   `RequireAssertion` that splits the string and checks membership:

   ```csharp
   static bool HasScope(ClaimsPrincipal user, string scope)
   {
       var raw = user.FindFirst("scope")?.Value;
       return raw is not null && raw.Split(' ').Contains(scope);
   }
   ```

3. **Audience.** The token's `aud` was `["lab3-service", "account"]`, so the API
   has to validate against an audience that's actually present — otherwise every
   call is 401 before scopes even matter.

### Postman gotcha
Postman's secret scanner flagged the JWT as a "Supabase Service Role API Key"
(false positive — same `eyJ...` format) and tried to move it into the Vault. That
left the `{{access_token}}` variable empty, so requests went out as `Bearer ` and
returned 401. Overriding the secret protection kept the token usable. Also worth
remembering: these tokens live only **5 minutes** (`expires_in: 300`), so a stale
copy-pasted token is its own source of 401s.

---

## Lab 4 — Refresh Tokens & Token Lifecycle ✅

**Goal:** The Resource Server verifies tokens offline using Keycloak's public keys (from the JWKS endpoint), so a revocation isn't detected there — it has to wait until the token expires. The solution is to use a pair of tokens — a short-lived access token and a long-lived refresh token — which avoids re-authenticating every time the access token expires.

### What I built
- I enabled a Direct Access Grant (password grant) for testing purposes — in a real-world scenario it should be Authorization Code + PKCE. In this lab I needed a faster way to test the refresh token, and the focus isn't on how the user obtains the token (that was Lab 1).
- Set the Access Token Lifespan to 60s so the expiry is observable within the lab.
- Endpoint `/token-info` reads `exp`, compares it to the current time, and returns how many seconds the token has left. It always returns 200 — an expired token never reaches it, because the auth middleware rejects that with 401 first.
- Added console logging through `JwtBearerEvents` (with timestamps) so I can watch the auth pipeline live: ✅ validated on a good token vs. ❌ expired → 🚪 401 challenge on a stale one.

### What clicked
- The pattern of dividing into two separate tokens is deliberate — — it limits the exposure window. You can't kill an access token mid-life here, but revoking the refresh token stops access as soon as the current short-lived token expires. The access token is validated offline, so there's no call to Keycloak on every request — that's faster, but the trade-off is no immediate revocation if a breach occurs: you have to wait out the token's lifetime.
- Offline (JWKS) is the fast, stateless way but it's blind to revocation until expiry; online validation calls Keycloak's introspection endpoint on every request, so it catches a revoked token immediately — the trade-off being a round-trip each time.

### What broke
Had to fix the **5-minute tolerance** that `ClockSkew` adds by default on top of the configured lifespan (5 min + 1 min = 6 min). Setting `ClockSkew = TimeSpan.Zero` did the trick, so the 60s I set in Keycloak is actually honored. **Why it exists:** the default tolerates small clock differences between Keycloak and the API. Zero is fine for a lab, but in production you'd keep a small skew (≈30s–2min) so minor clock drift doesn't reject valid tokens.

### Postman gotcha
My Post-response script saved the tokens with `pm.collectionVariables.set`, but I'd defined the variables in the **environment** ("Lab 4 Local"). Those are two different **scopes**, and the empty environment variable shadowed the one the script set — so `{{access_token}}` went out blank and `/protected` returned 401. Fix: point the script at the same scope I was reading from (`pm.environment.set`), so the tokens are shared across the requests in the collection.

*More labs coming as I work through them.*
