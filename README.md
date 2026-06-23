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

*More labs coming as I work through them.*
