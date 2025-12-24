# Security Considerations for CORS Anywhere

## Overview
CORS Anywhere can pose security risks if not properly configured. This document outlines security best practices and the built-in security features.

**Testing Status:** All 137 tests passing, including comprehensive security test suite  
**Node.js Compatibility:** Tested from v0.10.0 to v22.20.0  
**Dependencies:** Zero npm audit vulnerabilities (as of December 2025)  
**Last Updated:** December 2025

## Built-in Security Features

### 1. Automatic Cookie Stripping
**Implementation**: [lib/cors-anywhere.js#L214-L215](../lib/cors-anywhere.js#L214-L215)

The proxy automatically removes `Set-Cookie` and `Set-Cookie2` headers from all proxied responses to prevent credential leakage.

```javascript
// In onProxyResponse()
delete proxyRes.headers['set-cookie'];
delete proxyRes.headers['set-cookie2'];
```

### 2. Origin Control (Whitelist/Blacklist)
**Recommended**: Use `originWhitelist` (allowlist) instead of `originBlacklist` (blocklist) for production.

```javascript
// Recommended production configuration
cors_proxy.createServer({
  originWhitelist: ['https://your-app.com'],  // Only allow your app
  // originBlacklist: [],  // Don't use - easy to bypass
});
```

**Warning**: An empty `originWhitelist` array allows ALL origins, creating an open proxy!

### 3. Required Headers
Prevents direct browser navigation and automated abuse by requiring specific headers:

```javascript
cors_proxy.createServer({
  requireHeader: ['origin', 'x-requested-with'],
});
```

This blocks:
- Direct browser URL navigation (no headers present)
- Simple curl/wget requests
- Basic scraping tools

### 4. Request Header Stripping
Remove sensitive headers that should not be proxied:

```javascript
cors_proxy.createServer({
  removeHeaders: ['cookie', 'cookie2', 'authorization'],
});
```

### 5. Rate Limiting
**Implementation**: [lib/rate-limit.js](../lib/rate-limit.js)

Configure via `CORSANYWHERE_RATELIMIT` environment variable:

```bash
# Format: <max_requests> <period_minutes> [whitelisted_hosts]
export CORSANYWHERE_RATELIMIT="60 60 trusted.example.com"  # 60 req/hour except trusted.example.com
```

## Security Risks

### Open Proxy Abuse
Without proper configuration, CORS Anywhere becomes an **open proxy** that can be abused for:

1. **Anonymous Browsing**: Users hide their IP address by routing traffic through your server
2. **Firewall Bypass**: Circumvent corporate or institutional network restrictions  
3. **DDoS Amplification**: Your server becomes an unwitting participant in attacks
4. **Legal Liability**: Your server's IP associated with malicious activity

### Attack Vectors

#### 1. Credential Theft
**Mitigated by**: Automatic cookie stripping + `removeHeaders`

Without header stripping, an attacker could:
```javascript
// Attacker's malicious site
fetch('https://your-cors-proxy.com/https://victim-bank.com/api/balance', {
  credentials: 'include'  // Try to send victim's cookies
});
```

#### 2. Internal Network Scanning
**Mitigation**: Use `handleInitialRequest` to block internal domains

```javascript
handleInitialRequest: function(req, res, location) {
  if (location && location.hostname.match(/\.(local|internal)$/)) {
    res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
    res.end('Access to internal domains is blocked');
    return true;
  }
  // Block private IP ranges
  if (location && location.hostname.match(/^(10|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\./)) {
    res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
    res.end('Access to private IP ranges is blocked');
    return true;
  }
  return false;
}
```

#### 3. Server-Side Request Forgery (SSRF)
Attackers can make your server request internal resources:
```
GET /your-cors-proxy.com/http://localhost:6379/  # Try to access Redis
GET /your-cors-proxy.com/http://169.254.169.254/latest/meta-data/  # AWS metadata
```

**Mitigation**: Validate hostnames and block localhost/private IPs

## Recommended Production Configuration

```javascript
var cors_proxy = require('cors-anywhere');

cors_proxy.createServer({
  // Security: Only allow your specific origins
  originWhitelist: [
    'https://your-production-app.com',
    'https://your-staging-app.com'
  ],
  
  // Security: Require headers to prevent direct browser access
  requireHeader: ['origin', 'x-requested-with'],
  
  // Security: Strip sensitive headers
  removeHeaders: [
    'cookie',
    'cookie2',
    'authorization',
    'x-request-start',
    'x-request-id',
  ],
  
  // Performance: Redirect same-origin requests to save resources
  redirectSameOrigin: true,
  
  // Rate limiting (configure via environment)
  checkRateLimit: require('./lib/rate-limit')(process.env.CORSANYWHERE_RATELIMIT),
  
  // Block internal/private networks
  handleInitialRequest: function(req, res, location) {
    if (!location) return false;
    
    var hostname = location.hostname;
    
    // Block internal TLDs
    if (hostname.match(/\.(local|internal|localhost)$/i)) {
      res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
      res.end('Access to internal domains is blocked');
      return true;
    }
    
    // Block localhost
    if (hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '::1') {
      res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
      res.end('Access to localhost is blocked');
      return true;
    }
    
    // Block private IP ranges (10.x.x.x, 172.16-31.x.x, 192.168.x.x)
    if (hostname.match(/^(10|127)\.|^172\.(1[6-9]|2\d|3[01])\.|^192\.168\./)) {
      res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
      res.end('Access to private IP ranges is blocked');
      return true;
    }
    
    // Block AWS metadata endpoint
    if (hostname === '169.254.169.254') {
      res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
      res.end('Access blocked');
      return true;
    }
    
    return false;
  },
  
  httpProxyOptions: {
    xfwd: false,  // Don't add X-Forwarded headers if behind a reverse proxy
  },
}).listen(process.env.PORT || 8080, process.env.HOST || '0.0.0.0');
```

## Testing Security

Run the security test suite:

```bash
npm test                # Runs all 137 tests including security tests
npm run test-coverage   # Runs tests with coverage report
```

### Security Test Coverage (test/test-security.js)

The test suite includes 20+ security-focused tests covering:

**Cookie Security:**
- Cookie stripping (Set-Cookie headers removed from responses)
- Cookie header removal from requests
- Cookie protection during redirects

**Authorization & Credentials:**
- Authorization header stripping from requests
- Credential leak prevention

**Origin Control:**
- Origin whitelist enforcement (strict scheme matching)
- Origin blacklist enforcement  
- Origin header presence validation

**Request Validation:**
- Required header validation (blocks requests without specified headers)
- Invalid hostname rejection (favicon.ico, robots.txt, etc.)
- Port number validation (rejects ports > 65535)
- Internal domain blocking (localhost, private IPs, cloud metadata endpoints)

**Combined Protection:**
- Multiple security layers working together
- Open proxy prevention validation

## Security Checklist

- [ ] `originWhitelist` configured (not empty array)
- [ ] `requireHeader` includes at least `['origin', 'x-requested-with']`
- [ ] `removeHeaders` strips sensitive headers (`cookie`, `cookie2`, `authorization`)
- [ ] Rate limiting configured via `CORSANYWHERE_RATELIMIT` environment variable
- [ ] `handleInitialRequest` blocks internal/private networks (localhost, 10.x.x.x, 172.16-31.x.x, 192.168.x.x, 169.254.169.254)
- [ ] Server not exposed directly to internet (use firewall/reverse proxy)
- [ ] Monitoring/logging enabled for abuse detection
- [ ] Regular dependency updates (`npm audit` shows 0 vulnerabilities)
- [ ] All 137 tests passing (`npm test`)

## Development & Maintenance

### Testing Security Features

```bash
# Run security tests specifically
./node_modules/.bin/mocha test/test-security.js

# Run with coverage
npm run test-coverage

# Lint security code
npm run lint
```

### Dependency Security

The project uses:
- `http-proxy` 1.18.1 (upgraded from 1.11.1 to fix CVE-2024-21501 DoS vulnerability)
- Modern test dependencies (mocha v10.7.3, nock v13.5.5, supertest v7.0.0)
- ESLint v8.57.0 for code quality
- nyc v17.1.0 for code coverage

Run `npm audit` regularly to check for vulnerabilities. Current status: **0 vulnerabilities**.

### Updating Dependencies

When updating dependencies:
1. Review the custom buffer hack in [lib/cors-anywhere.js#L87-L101](lib/cors-anywhere.js#L87-L101) if upgrading `http-proxy`
2. Note: `http-proxy` 1.18.1 automatically adds `x-forwarded-host` header (behavior change from 1.11.1)
3. Run full test suite: `npm test` (all 137 tests should pass)
4. Run security audit: `npm audit` (should report 0 vulnerabilities)
5. Test in production-like environment before deploying

## Reporting Security Issues

If you discover a security vulnerability in CORS Anywhere, please email rob@robwu.nl instead of using the public issue tracker.

## Additional Resources

- [README.md](../README.md) - General documentation
- [.github/copilot-instructions.md](../.github/copilot-instructions.md) - Implementation details
- [test/test-security.js](../test/test-security.js) - Security test examples
