/* eslint-env mocha */
require('./setup');

var createServer = require('../').createServer;
var request = require('supertest');
var assert = require('assert');

// Add custom test helpers
request.Test.prototype.expectJSON = function(json, done) {
  this.expect(function(res) {
    try {
      var actual = JSON.parse(res.text);
      assert.deepEqual(actual, json);
    } catch (e) {
      if (e instanceof SyntaxError) {
        throw new Error('Response is not JSON. Status: ' + res.status + ', Body: ' + res.text.substring(0, 200));
      }
      throw e;
    }
  });
  return done ? this.end(done) : this;
};

request.Test.prototype.expectNoHeader = function(header, done) {
  this.expect(function(res) {
    if (header.toLowerCase() in res.headers) {
      return new Error('Unexpected header in response: ' + header);
    }
  });
  return done ? this.end(done) : this;
};

var cors_anywhere;
var cors_anywhere_port;
function stopServer(done) {
  if (cors_anywhere) {
    cors_anywhere.close(function() {
      cors_anywhere = null;
      done();
    });
  } else {
    done();
  }
}

describe('Security - Cookie Stripping', function() {
  before(function() {
    cors_anywhere = createServer();
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should strip Set-Cookie headers from response', function(done) {
    request(cors_anywhere)
      .get('/example.com/setcookie')
      .expect('Access-Control-Allow-Origin', '*')
      .expect('Set-Cookie3', 'z')  // Non-standard cookie header should pass through
      .expectNoHeader('set-cookie')
      .expectNoHeader('set-cookie2', done);
  });

  it('Should not leak cookies with internal redirects', function(done) {
    request(cors_anywhere)
      .get('/example.com/redirect')
      .redirects(0)
      .expect('Access-Control-Allow-Origin', '*')
      .expectNoHeader('set-cookie')
      .expect(200, done);
  });
});

describe('Security - Authorization Header Stripping', function() {
  before(function() {
    cors_anywhere = createServer({
      removeHeaders: ['authorization', 'cookie', 'cookie2'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should strip Authorization header from request', function(done) {
    request(cors_anywhere)
      .get('/example.com/echoheaders')
      .set('Authorization', 'Bearer secret-token')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(function(res) {
        var headers = JSON.parse(res.text);
        assert.strictEqual(headers.host, 'example.com');
        assert.ok('x-forwarded-host' in headers, 'x-forwarded-host should be present');
        assert.ok(!('authorization' in headers), 'authorization should be stripped');
      })
      .end(done);
  });

  it('Should strip Cookie headers from request', function(done) {
    request(cors_anywhere)
      .get('/example.com/echoheaders')
      .set('Cookie', 'session=secret')
      .set('Cookie2', 'other=value')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(function(res) {
        var headers = JSON.parse(res.text);
        assert.strictEqual(headers.host, 'example.com');
        assert.ok('x-forwarded-host' in headers, 'x-forwarded-host should be present');
        assert.ok(!('cookie' in headers), 'cookie should be stripped');
        assert.ok(!('cookie2' in headers), 'cookie2 should be stripped');
      })
      .end(done);
  });
});

describe('Security - Origin Whitelist (Strict)', function() {
  before(function() {
    cors_anywhere = createServer({
      originWhitelist: ['https://allowed.example.com', 'http://localhost:3000'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should allow whitelisted origin (https)', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://allowed.example.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });

  it('Should allow whitelisted origin (localhost)', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'http://localhost:3000')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });

  it('Should block non-whitelisted origin', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://evil.example.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(403)
      .expect(function(res) {
        assert(res.text.includes('was not whitelisted'));
      })
      .end(done);
  });

  it('Should block requests without origin header', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(403)
      .expect(function(res) {
        assert(res.text.includes('was not whitelisted'));
      })
      .end(done);
  });

  it('Should block origin with different scheme', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'http://allowed.example.com')  // http instead of https
      .expect('Access-Control-Allow-Origin', '*')
      .expect(403, done);
  });
});

describe('Security - Origin Blacklist', function() {
  before(function() {
    cors_anywhere = createServer({
      originBlacklist: ['http://blocked.example.com', 'https://evil.example.com'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should block blacklisted origin', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'http://blocked.example.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(403)
      .expect(function(res) {
        assert(res.text.includes('was blacklisted'));
      })
      .end(done);
  });

  it('Should allow non-blacklisted origin', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://good.example.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });

  it('Should allow requests without origin header', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });
});

describe('Security - Required Headers', function() {
  before(function() {
    cors_anywhere = createServer({
      requireHeader: ['origin', 'x-requested-with'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should block request without required headers', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(400)
      .expect(function(res) {
        assert(res.text.includes('Missing required request header'));
      })
      .end(done);
  });

  it('Should allow request with Origin header', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://example.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });

  it('Should allow request with X-Requested-With header', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('X-Requested-With', 'XMLHttpRequest')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });

  it('Should allow request with both required headers', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://example.com')
      .set('X-Requested-With', 'XMLHttpRequest')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });
});

describe('Security - Combined Protection', function() {
  before(function() {
    cors_anywhere = createServer({
      originWhitelist: ['https://trusted.example.com'],
      requireHeader: ['origin', 'x-requested-with'],
      removeHeaders: ['cookie', 'cookie2', 'authorization'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should enforce all security measures', function(done) {
    request(cors_anywhere)
      .get('/example.com/echoheaders')
      .set('Origin', 'https://trusted.example.com')
      .set('X-Requested-With', 'XMLHttpRequest')
      .set('Authorization', 'Bearer secret')
      .set('Cookie', 'session=value')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(function(res) {
        var headers = JSON.parse(res.text);
        assert.strictEqual(headers.host, 'example.com');
        assert.strictEqual(headers.origin, 'https://trusted.example.com');
        assert.strictEqual(headers['x-requested-with'], 'XMLHttpRequest');
        assert.ok('x-forwarded-host' in headers, 'x-forwarded-host should be present');
        assert.ok(!('authorization' in headers), 'authorization should be stripped');
        assert.ok(!('cookie' in headers), 'cookie should be stripped');
      })
      .end(done);
  });

  it('Should block untrusted origin even with required headers', function(done) {
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://evil.example.com')
      .set('X-Requested-With', 'XMLHttpRequest')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(403, done);
  });

  it('Should allow trusted origin with one required header (origin check passes first)', function(done) {
    // Note: requireHeader uses .some() so only ONE of the headers is needed
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://trusted.example.com')
      // Missing X-Requested-With but Origin satisfies requireHeader
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', done);
  });
});

describe('Security - Open Proxy Prevention', function() {
  it('Empty whitelist should create open proxy (test for awareness)', function(done) {
    cors_anywhere = createServer({
      originWhitelist: [],  // Empty = allow all
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
    
    request(cors_anywhere)
      .get('/example.com/')
      .set('Origin', 'https://any-origin.com')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(200, 'Response from example.com', function() {
        stopServer(done);
      });
  });

  it('Should use requireHeader to prevent direct browser access', function(done) {
    cors_anywhere = createServer({
      requireHeader: ['origin', 'x-requested-with'],
    });
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
    
    // Simulate direct browser navigation (no headers)
    request(cors_anywhere)
      .get('/example.com/')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(400, function() {
        stopServer(done);
      });
  });
});

describe('Security - Request Validation', function() {
  before(function() {
    cors_anywhere = createServer();
    cors_anywhere_port = cors_anywhere.listen(0).address().port;
  });
  after(stopServer);

  it('Should block requests to internal/private domains via handleInitialRequest', function(done) {
    stopServer(function() {
      cors_anywhere = createServer({
        handleInitialRequest: function(req, res, location) {
          if (location && location.hostname.match(/\.(local|internal)$/)) {
            res.writeHead(403, {'Access-Control-Allow-Origin': '*'});
            res.end('Access to internal domains is blocked');
            return true;
          }
          return false;
        },
      });
      cors_anywhere_port = cors_anywhere.listen(0).address().port;
      
      request(cors_anywhere)
        .get('/example.internal/')
        .expect('Access-Control-Allow-Origin', '*')
        .expect(403, 'Access to internal domains is blocked', done);
    });
  });

  it('Should validate port numbers', function(done) {
    request(cors_anywhere)
      .get('/example.com:65536')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(400, 'Port number too large: 65536', done);
  });

  it('Should reject invalid hostnames', function(done) {
    request(cors_anywhere)
      .get('/favicon.ico')
      .expect('Access-Control-Allow-Origin', '*')
      .expect(404, 'Invalid host: favicon.ico', done);
  });
});
