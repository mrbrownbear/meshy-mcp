# Meshy MCP for Vercel by Laraibrabbani.net 

I saw that a lot of people were struggling with Meshy MCP so I created one for everyone. Have a great day ahead.

Deploy the official Meshy MCP tool set as a stateless Streamable HTTP service with OAuth 2.0, PKCE, dynamic OAuth client registration and per-user Meshy API access.

This project uses the published `@meshy-ai/meshy-mcp-server` package, pinned to version `0.6.1`, rather than maintaining a divergent copy of Meshy's tools. The original project is at https://github.com/meshy-dev/meshy-mcp-server and is licensed under MIT.

## Deploy

1. Create a GitHub repository, commit this project's files and connect it to a new Vercel project with the root directory set to the repository root.
2. Set `OAUTH_ISSUER` to the exact stable production origin, such as `https://your-production-domain.example`. Do not include `/mcp` or a trailing slash.
3. Set `OAUTH_SECRET` to at least 32 cryptographically random bytes. To create it locally, run `node -e "console.log(require('node:crypto').randomBytes(48).toString('base64url'))"`. Copy the output into a Vercel encrypted environment variable. Changing it disconnects all users and invalidates registered clients.
4. Set `OAUTH_ALLOWED_REDIRECT_HOSTS=chatgpt.com` for ChatGPT callbacks. To add other MCP clients, specify additional verified HTTPS callback hosts separated by commas.
5. Optionally set `OAUTH_CLIENT_ID` and `OAUTH_REDIRECT_URIS` for a predefined public OAuth client. The default is Dynamic Client Registration, and no client secret is needed for public PKCE clients.
6. Redeploy after setting environment variables.

Do not set a shared `MESHY_API_KEY` for public hosting. Each user enters their own Meshy key on the OAuth authorization page. Access and refresh tokens encrypt the key using your server's `OAUTH_SECRET`.

## Endpoints

* `/health`: public status and build version.
* `/.well-known/oauth-protected-resource`: OAuth protected resource discovery.
* `/.well-known/oauth-authorization-server`: OAuth authorization server discovery.
* `/register`: OAuth 2.0 dynamic public client registration.
* `/authorize`: OAuth consent and Meshy credential verification.
* `/token`: PKCE authorization code and refresh token exchange.
* `/mcp`: authenticated stateless MCP Streamable HTTP endpoint.

## Connecting ChatGPT

Add a custom MCP server using your HTTPS address with `/mcp` appended. Select OAuth. ChatGPT will discover the OAuth endpoints and dynamically register a public client. During authorization, enter your own Meshy API key from https://www.meshy.ai/settings/api. Test with `meshy_check_balance` before running credit-consuming tools.

The authorization server issues AES-256-GCM encrypted bearer and refresh tokens; it does not create user accounts or maintain a credential database. Access tokens expire after one hour; refresh tokens after 14 days. Changing `OAUTH_SECRET` revokes every issued token at once. Individual token revocation is not available in this stateless implementation.

## Local checks

`npm test` runs OAuth crypto, callback validation, client registration and configuration tests without Meshy credentials. `npm run check` checks syntax and runs the test suite. The full MCP runtime needs npm dependencies installed and a running deployment to test the transport.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `OAUTH_ISSUER` | Yes | Canonical HTTPS origin of this service |
| `OAUTH_SECRET` | Yes | Random secret at least 32 bytes for encryption and OAuth client signatures |
| `OAUTH_ALLOWED_REDIRECT_HOSTS` | No | HTTPS callback host allowlist, defaults to `chatgpt.com` |
| `OAUTH_CLIENT_ID` | No | Preconfigured public OAuth client identifier |
| `OAUTH_REDIRECT_URIS` | With static client ID | Comma-separated allowed callback URIs |
| `MESHY_API_HOST` | No | Meshy API origin, defaults to `https://api.meshy.ai` |

## License

MIT. Meshy is a separate service and its API usage, licensing, rates and billing terms apply.
