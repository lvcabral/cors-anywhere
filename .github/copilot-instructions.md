# CORS Anywhere - AI Coding Agent Instructions

## Project Overview
CORS Anywhere is a NodeJS reverse proxy that adds CORS headers to proxied HTTP requests. The URL to proxy is extracted from the request path, validated, and proxied with appropriate CORS headers. This is a library package designed to be embedded in Node.js applications.

## Architecture

### Core Components
- **[lib/cors-anywhere.js](../lib/cors-anywhere.js)**: Main library exporting `createServer(options)`. Contains all proxy logic, URL parsing, validation, and request handling. The module is ~463 lines and handles the entire request/response lifecycle.
- **[server.js](../server.js)**: Example/reference server implementation showing production configuration with environment-based settings (HOST, PORT, rate limiting, origin lists).
- **[lib/rate-limit.js](../lib/rate-limit.js)**: Rate limiting module configured via `CORSANYWHERE_RATELIMIT` env var. Returns a `checkRateLimit` function that tracks requests per origin using an in-memory hash cleared on intervals.
- **[lib/regexp-top-level-domain.js](../lib/regexp-top-level-domain.js)**: TLD validation regex for hostname verification.

### Request Flow
1. **URL Parsing**: Request path is parsed by `parseURL()` - protocol is optional (defaults to http/https based on port 443). Supports formats like `/http://example.com`, `/example.com`, `/example.com:443`.
2. **Validation**: Hostname validated via TLD regex or IP check (`isValidHostName()`). Special paths like `/favicon.ico`, `/robots.txt` return 404 unless prefixed with `http://`.
3. **Security Checks**: Origin whitelist/blacklist, required headers (`requireHeader` option), rate limiting via `checkRateLimit`.
4. **Proxy Request**: Uses `http-proxy` (v1.18.1) with a custom buffer hack to intercept `proxyReq.on('response')` for redirect handling and header manipulation.
5. **Response Handling**: `onProxyResponse()` handles redirects (301/302/303 internally, up to `maxRedirects`), strips cookies, adds CORS headers via `withCORS()`, and sets `x-request-url` and `x-final-url` headers.

## Key Patterns & Conventions

### Configuration Pattern
All server options are passed to `createServer(options)`. The server uses a **middleware-style callback system** for extensibility:
- `handleInitialRequest(req, res, parsedURL)` - Early request interception (return true to handle, false to continue)
- `checkRateLimit(origin)` - Return error message string to reject, void to allow
- `getProxyForUrl(url)` - Return proxy URL for chained proxying, void for direct connection

### State Management
Request state is stored in `req.corsAnywhereRequestState` object containing:
- `location` - Parsed destination URL
- `getProxyForUrl` - Function reference
- `proxyBaseUrl` - Base URL of CORS API endpoint
- `maxRedirects` - Maximum redirect count (default 5)
- `redirectCount_` - Internal redirect counter
- `corsMaxAge` - CORS preflight cache duration

### HTTP-Proxy Integration
The code uses an unconventional pattern to intercept http-proxy's response handling (see [lib/cors-anywhere.js#L87-L101](../lib/cors-anywhere.js#L87-L101)). It overrides `proxyReq.on()` to wrap the response listener, enabling redirect handling and header modification before the response reaches the client.

### Header Manipulation
- **Removed headers**: Configured via `removeHeaders` array (cookies stripped by default in `onProxyResponse()`)
- **Set headers**: Applied via `setHeaders` object after removal
- **CORS headers**: Always include `access-control-allow-origin: *`, `access-control-expose-headers`, and mirror preflight request headers

## Development Workflows

### Testing
```bash
npm test                # Run mocha tests (137 tests passing)
npm run test-coverage   # nyc coverage for test.js and test-ratelimit.js  
npm run lint            # ESLint validation
```

**Test Status:** All 137 tests passing (includes security, functionality, memory, and rate-limit tests)  
**Node.js Compatibility:**
- **Library code:** v0.10.0 to v22.x (ES5 syntax for maximum compatibility)
- **Development/testing:** v14.0.0+ required (modern test dependencies like mocha v10.7.3)
- **Last tested:** December 2025 on Node v22.20.0

Tests use `supertest` for HTTP assertions and `nock` v13 for mocking external requests. Test structure:
- Create server with `createServer(options)` in `before()` hook
- Use dynamic port via `.listen(0).address().port`
- Custom helpers: `.expectJSON()`, `.expectNoHeader()` (see [test/test.js#L15-L29](../test/test.js#L15-L29))

**Note on nock v13:** Reply functions must return `[status, body, headers]` array format (breaking change from v8)

### Environment Variables
Production configuration is typically environment-driven (see [server.js](../server.js)):
- `HOST` / `PORT` - Server binding
- `CORSANYWHERE_BLACKLIST` / `CORSANYWHERE_WHITELIST` - Comma-separated origin lists
- `CORSANYWHERE_RATELIMIT` - Format: `<max> <minutes> [whitelisted hosts]` (e.g., `1 5 example.com`)

### Local Development
```bash
node server.js          # Start with default settings (0.0.0.0:8080)
# Test: curl http://localhost:8080/http://example.com
```

## Common Implementation Patterns

### Creating a Server
Always call `.listen()` on the returned server object:
```javascript
var cors_proxy = require('cors-anywhere');
cors_proxy.createServer({
  originWhitelist: ['https://allowed.com'],
  requireHeader: ['origin', 'x-requested-with'],
  removeHeaders: ['cookie'],
  redirectSameOrigin: true,
  httpProxyOptions: { xfwd: false }
}).listen(8080, '0.0.0.0');
```

### Custom Rate Limiting
The `checkRateLimit` function receives origin string, returns error message or void:
```javascript
checkRateLimit: function(origin) {
  if (isBlocked(origin)) return 'Custom block message';
  // Return nothing to allow
}
```

### Request Interception
Use `handleInitialRequest` for logging, custom routing, or blocking:
```javascript
handleInitialRequest: function(req, res, parsedURL) {
  console.log('Request to:', parsedURL?.href);
  return false; // Continue processing
}
```

## Critical Implementation Details

### URL Parsing Edge Cases
- Protocol defaults: No port = `http://`, port 443 = `https://`
- Regex pattern in `parseURL()` handles protocol-less URLs like `example.com`
- Invalid formats return `null` causing 404 with "Invalid URI" message

### Redirect Handling
- Only 301/302/303 are handled internally (preserving GET method)
- 307/308 pass through to client (rare, method-preserving redirects)
- Redirect headers set for debugging: `X-CORS-Redirect-1`, `X-CORS-Redirect-2`, etc.

### Proxy Error Handling
The proxy's error event handler checks `res.headersSent` and `res.writableEnded` (Node 13+) to avoid writing headers after streaming starts. Always returns 404 with CORS headers on proxy errors.

## Dependencies & Constraints
- **http-proxy 1.18.1**: Upgraded from 1.11.1 (December 2025) to fix high-severity DoS vulnerability (CVE-2024-21501). All tests passing with new version. The custom buffer hack (lines 87-101 in cors-anywhere.js) remains compatible. Note: v1.18.1 automatically adds `x-forwarded-host` header.
- **Node.js ≥0.10.0**: Ancient support retained for library compatibility. Code uses ES5 syntax (no arrow functions, let/const, or modern APIs). **Note:** Development/testing requires Node.js ≥14.0.0 due to modern test dependencies.
- **No browser-side code**: Pure server-side proxy (demo.html is client example only)
- **Modern test dependencies (as of Dec 2025)**: 
  - mocha v10.7.3 (was v3.4.2) - requires Node ≥14.0.0
  - nock v13.5.5 (was v8.2.1 - breaking changes in reply format)
  - supertest v7.0.0 (was v2.0.1)
  - eslint v8.57.0 (was v2.2.0)
  - nyc v17.1.0 (replaced istanbul v0.4.2)
  - lolex v6.0.0 (was v1.5.0)
  - **coveralls removed** (had critical vulnerabilities in transitive deps form-data/tough-cookie, only used for CI coverage reporting)
- **Security Status:** Zero npm audit vulnerabilities (as of December 2025)

## Security Model & Production Hardening

### Built-in Security
- **Cookie stripping**: Automatic removal of `set-cookie`/`set-cookie2` headers in `onProxyResponse()` prevents credential leakage
- **Origin control**: Use `originWhitelist` (allowlist) over `originBlacklist` (blocklist) for production - empty whitelist = open proxy
- **Required headers**: `requireHeader: ['origin', 'x-requested-with']` prevents direct browser navigation abuse

### Production Considerations
```javascript
// Recommended production config
cors_proxy.createServer({
  originWhitelist: ['https://your-app.com'],           // Lock down origins
  requireHeader: ['origin', 'x-requested-with'],       // Block direct access
  removeHeaders: ['cookie', 'cookie2', 'authorization'], // Strip sensitive headers
  checkRateLimit: rateLimitFunction,                   // Essential for public instances
  redirectSameOrigin: true,                            // Reduce server load
  httpProxyOptions: { xfwd: false }                    // Control forwarded headers
});
```

### Open Proxy Risks
Without proper configuration, CORS Anywhere can be abused as an open proxy for:
- Anonymous browsing / IP hiding
- Bypassing corporate firewalls
- DDoS amplification

**Always restrict access** in production via origin whitelisting or authentication middleware in `handleInitialRequest`.

## Extension Examples

### Custom Help Text
```javascript
createServer({
  helpFile: __dirname + '/custom-help.html'  // Shown at GET /
})
```

### Logging & Monitoring
```javascript
handleInitialRequest: function(req, res, location) {
  console.log('[%s] %s -> %s', 
    req.headers.origin || 'direct', 
    req.method, 
    location?.href || req.url
  );
  return false; // Continue processing
}
```

### Response Transformation
See [test/test-examples.js](../test/test-examples.js) for patterns:
- Streaming transformation (modify chunks as they arrive)
- Buffered transformation (collect full response, then modify)
- Use `res.write` and `res.end` overrides to intercept response data

### Custom Validation
```javascript
handleInitialRequest: function(req, res, location) {
  if (location && location.hostname.endsWith('.internal')) {
    res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
    res.end('Internal domains are blocked');
    return true; // Stop processing
  }
  return false;
}
```

## Testing Philosophy
- Test both library (`createServer`) and example server patterns
- Mock external HTTP requests with `nock` v13 (note: reply functions return arrays)
- Verify CORS headers on all responses (success and error cases)
- Test edge cases: invalid URLs, rate limits, origin restrictions, redirects
- **Security tests:** Comprehensive suite in [test/test-security.js](../test/test-security.js) validates cookie stripping, authorization header removal, origin control, and combined protections
- **All tests pass on Node v22:** 137 passing tests covering functionality, security, memory usage, and rate limiting

See [test/test-examples.js](../test/test-examples.js) for advanced usage patterns including HTTPS servers and custom proxy chaining.
