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

*More labs coming as I work through them.*
