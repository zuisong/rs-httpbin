# rs-httpbin

A copy of [go-httpbin](https://github.com/mccutchen/go-httpbin), Just for learning Rust language.

A rust port of the venerable httpbin.org HTTP request & response testing service.

## todo

- [x] [/](/) This page.
- [x] [/anything/:anything](/anything/anything) Returns request data.
- [x] [/delete](/delete) Returns request data. Allows only DELETE requests.
- [x] [/get](/get) Returns request data. Allows only GET requests.
- [x] [/head](/head) Returns request data. Allows only HEAD requests.
- [x] [/options](/options) Returns request data. Allows only OPTIONS requests.
- [x] [/patch](/patch) Returns request data. Allows only PATCH requests.
- [x] [/post](/post) Returns request data. Allows only POST requests.
- [x] [/put](/put) Returns request data. Allows only PUT requests.
- [x] [/trace](/trace) Returns request data. Allows only TRACE requests.
- [ ] /absolute-redirect/:n 302 Absolute redirects n times.
- [ ] /base64/:value Decodes a Base64-encoded string.
- [ ] /base64/decode/:value Explicit URL for decoding a Base64 encoded string.
- [ ] /base64/encode/:value Encodes a string into URL-safe Base64.
- [ ] /basic-auth/:user/:passwd Challenges HTTPBasic Auth.
- [ ] /bearer Checks Bearer token header - returns 401 if not set.
- [ ] /brotli Returns brotli-encoded data.
- [ ] /bytes/:n Generates n random bytes of binary data, accepts optional seed integer parameter.
- [ ] /cache Returns 200 unless an If-Modified-Since or If-None-Match header is provided, when it returns a 304.
- [ ] /cache/:n Sets a Cache-Control header for n seconds.
- [ ] /cookies Returns cookie data.
- [ ] /cookies/delete?name Deletes one or more simple cookies.
- [ ] /cookies/set?name=value Sets one or more simple cookies.
- [ ] /deflate Returns deflate-encoded data.
- [ ] /delay/:n Delays responding for min(n, 10) seconds.
- [ ] /deny Denied by robots.txt file.
- [ ] /digest-auth/:qop/:user/:passwd/:algorithm Challenges HTTP Digest Auth.
- [ ] /digest-auth/:qop/:user/:passwd Challenges HTTP Digest Auth.
- [ ] /drip?numbytes=n&duration=s&delay=s&code=code Drips data over a duration after an optional initial delay, then (optionally) returns with the given status code.
- [ ] /dump/request Returns the given request in its HTTP/1.x wire approximate representation.
- [ ] /encoding/utf8 Returns page containing UTF-8 data.
- [ ] /etag/:etag Assumes the resource has the given etag and responds to If-None-Match header with a 200 or 304 and If-Match with a 200 or 412 as appropriate.
- [ ] /forms/post HTML form that submits to /post
- [ ] /gzip Returns gzip-encoded data.
- [x] [/headers](/headers) Returns request header dict.
- [ ] /hidden-basic-auth/:user/:passwd 404'd BasicAuth.
- [x] [/html](/html) Renders an HTML Page.
- [ ] /hostname Returns the name of the host serving the request.
- [x] [/image](/image) Returns page containing an image based on sent Accept header.
- [x] [/image/jpeg](/image/jpeg) Returns a JPEG image.
- [x] [/image/png](/image/png) Returns a PNG image.
- [x] [/image/svg](/image/svg) Returns a SVG image.
- [x] [/image/webp](/image/webp) Returns a WEBP image.
- [x] [/ip](/ip) Returns Origin IP.
- [x] [/json](/json) Returns JSON.
- [ ] /links/:n Returns page containing n HTML links.
- [ ] /range/1024?duration=s&chunk_size=code Streams n bytes, and allows specifying a Range header to select a subset of the data. Accepts a chunk_size and request duration parameter.
- [ ] /redirect-to?url=foo&status_code=307 307 Redirects to the foo URL.
- [ ] /redirect-to?url=foo 302 Redirects to the foo URL.
- [ ] /redirect/:n 302 Redirects n times.
- [ ] /relative-redirect/:n 302 Relative redirects n times.
- [ ] /response-headers?key=val Returns given response headers.
- [ ] /robots.txt Returns some robots.txt rules.
- [ ] /sse?delay=1s&duration=5s&count=10 a stream of server-sent events.
- [ ] /status/:code Returns given HTTP Status code.
- [ ] /stream-bytes/:n Streams n random bytes of binary data, accepts optional seed and chunk_size integer parameters.
- [ ] /stream/:n Streams min(n, 100) lines.
- [ ] /unstable Fails half the time, accepts optional failure_rate float and seed integer parameters.
- [x] [/user-agent](/user-agent) Returns user-agent.
- [ ] /uuid Generates a UUIDv4 value.
- [ ] /websocket/echo?max_fragment_size=2048&max_message_size=10240 A WebSocket echo service.
- [x] [/xml](/xml) Returns some XML
