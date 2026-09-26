# tlsmask guide

This guide walks through everything tlsmask can do. If you're new, read "Sessions" and "Making requests" first; the rest you can dip into when you need it.

- [Sessions](#sessions)
- [Making requests](#making-requests)
- [The response](#the-response)
- [Headers and their order](#headers-and-their-order)
- [Cookies](#cookies)
- [Redirects](#redirects)
- [Proxies](#proxies)
- [Timeouts and certificates](#timeouts-and-certificates)
- [Errors](#errors)
- [Async and threads](#async-and-threads)
- [Fine-tuning the connection](#fine-tuning-the-connection)
- [A custom TLS fingerprint](#a-custom-tls-fingerprint)
- [Checking your installation](#checking-your-installation)
- [How it works](#how-it-works)

## Sessions

Everything goes through a `Session`. It remembers which browser to imitate, your default headers, cookies and proxies, and it keeps connections open between requests, just like a browser tab.

```python
import tlsmask

session = tlsmask.Session("chrome_150")  # the profile: which browser to be
try:
    r = session.get("https://example.com")
finally:
    session.close()
```

Or let a `with` block close it for you:

```python
with tlsmask.Session("firefox_148") as session:
    r = session.get("https://example.com")
```

Reuse one session for many requests to the same site. Creating a new session for every request is slower (every request starts a fresh connection) and doesn't look like a browser.

**Profiles.** The first argument names the browser. `tlsmask.PROFILES` lists every name, and the README has them grouped by browser. If you pass a name that doesn't exist, tlsmask raises `ValueError` with the closest matches instead of quietly sending some other browser's fingerprint. Leave it out to get tls-client's current default, `tlsmask.DEFAULT_PROFILE`.

## Making requests

```python
session.get(url)
session.post(url, json={"a": 1})
session.put(url, data="raw body")
session.patch(url, data={"field": "value"})
session.delete(url)
session.head(url)
session.options(url)
session.request("PROPFIND", url)  # any other method
```

**Query parameters** are added to whatever query the URL already has:

```python
session.get("https://example.com/search?lang=en", params={"q": "tls", "page": 2})
# -> https://example.com/search?lang=en&q=tls&page=2
```

`session.params` works the same way for parameters you want on every request.

**Request bodies:**

| You pass | What is sent | Content-Type added |
|---|---|---|
| `json={"a": 1}` | `{"a":1}` | `application/json` |
| `data={"a": "1"}` | `a=1` | `application/x-www-form-urlencoded` |
| `data="text"` | the string as is | none |
| `data=b"\x00\x01"` | the bytes as they are | none |

A `Content-Type` you set yourself always wins, and the one tlsmask adds only applies to that one request.

URLs with spaces or non-ASCII characters are encoded the way a browser would encode them (`https://bücher.example/straße` is sent as `https://xn--bcher-kva.example/stra%C3%9Fe`).

## The response

```python
r = session.get("https://httpbin.org/json")

r.status_code  # 200
r.ok  # True for anything below 400
r.reason  # "OK"
r.url  # the final URL
r.protocol  # "HTTP/2.0", "HTTP/1.1", ...
r.headers  # case-insensitive: r.headers["content-type"] == r.headers["Content-Type"]
r.content  # the body as bytes, exactly as received
r.text  # the body as text, decoded with the charset the server declared (UTF-8 otherwise)
r.json()  # the body parsed as JSON
r.cookies  # the cookies this response set
r.history  # the redirect responses that led here, if you followed any
r.raise_for_status()  # raises tlsmask.HTTPError for a 4xx or 5xx status
```

A header the server sent more than once comes back as a list. `r.headers` ignores case; `dict(r.headers)` gives you a plain dictionary.

## Headers and their order

Browsers send their headers in a fixed order, and some sites check it. tlsmask sends headers in exactly the order you set them: first the session's headers, then any new ones from the request.

```python
session.headers = {
    "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...",
    "accept-encoding": "gzip, deflate, br, zstd",
    "accept-language": "en-US,en;q=0.9",
}

session.get(url, headers={"referer": "https://example.com/"})
```

A request header with the same name as a session header replaces its value but keeps its position. Set a header to `None` to leave it out of one request:

```python
session.get(url, headers={"accept-language": None})
```

To control the order explicitly, pass `header_order`. Headers it names come first, in that order, and the rest follow in the order they were set:

```python
session = tlsmask.Session("chrome_150", header_order=["accept", "user-agent", "accept-language"])
session.get(url, header_order=["user-agent", "accept"])  # just for this request
```

A new session starts with a basic set of headers (`User-Agent: tlsmask/<version>`, `Accept-Encoding`, `Accept`, `Connection`). For anything that should look like a browser, replace them with that browser's real headers, as above.

## Cookies

Cookies live in `session.cookies`, and only there. Whatever the server sets is stored, sent back on later requests to the same site, and follows the usual domain, path, `Secure` and expiry rules.

```python
session.get("https://example.com/login")
print(session.cookies.get_dict())  # {'sessionid': '...'}

session.cookies.set("consent", "yes")  # sent to every site
session.cookies.set("theme", "dark", domain="example.com")
session.cookies["lang"] = "en"
del session.cookies["consent"]  # gone from the very next request
session.cookies.clear()  # start again with no cookies
```

`session.cookies` is a standard `http.cookiejar.CookieJar` with some extra helpers: `get`, `set`, `get_dict`, `update`, `keys`, `values`, `items`, `copy`, plus `[]`, `in` and `del`.

Cookies for a single request go with that request only, and only to its site, even if a redirect leads somewhere else:

```python
session.get(url, cookies={"ab_test": "b"})
```

A `Cookie` header that you set yourself is sent unchanged, instead of the jar's cookies.

## Redirects

Redirects are **not** followed unless you ask, which is what the `tls-client` package did too:

```python
r = session.get("https://github.com/login")  # r.status_code == 302
r = session.get("https://github.com/login", allow_redirects=True)  # follows up to 30 redirects
print([hop.status_code for hop in r.history], r.url)
```

When following redirects, tlsmask behaves like a browser:

- a `POST` answered with 301 or 302, or any request answered with 303 (except `GET` and `HEAD`), continues as a `GET` without a body;
- 307 and 308 keep the method and the body;
- cookies set along the way are kept;
- `Authorization` and a `Cookie` header you set yourself are dropped when the redirect leaves the site (a different host, scheme or port), except for an upgrade from http to https on the same host.

More than 30 redirects raises `TLSClientException`.

## Proxies

```python
session.proxies = "http://user:pass@203.0.113.10:8080"  # every request
session.proxies = {"https": "socks5://user:pass@203.0.113.10:1080"}  # by URL scheme

session.get(url, proxy="http://203.0.113.20:8080")  # just this request
session.proxies = {}  # no proxy
```

From a dictionary tlsmask uses the entry for the URL's scheme (`http` or `https`), then `all`, then any other entry. A dictionary with a proxy in it never means "no proxy".

A proxy written as `host:port` or `user:pass@host:port` is taken as `http://`. tls-client can use `http://`, `https://`, `socks5://` and `socks5h://` proxies; anything else raises `TLSClientException` before a request is sent.

If your proxy hands out a new IP address for each connection, `Session(..., is_rotating_proxy=True)` makes tls-client apply the proxy again on every request.

## Timeouts and certificates

Requests time out after 30 seconds unless you say otherwise:

```python
session.timeout_seconds = 10  # the session's default
session.get(url, timeout=2.5)  # seconds, for one request
```

`timeout_seconds=` on a request works too, for code written for `tls-client`, and so does a `(connect, read)` pair as in `requests` (tls-client has a single timeout, so the two are added up).

Connections are kept per timeout: requests with the same timeout share them, and a request with a different timeout opens its own. So pick one timeout per session where you can.

Certificates are verified. To skip verification for a request (for a local test server, say):

```python
session.get("https://localhost:8443/", insecure_skip_verify=True)
```

To accept only specific certificates for a host, pin their public keys (base64 SHA-256 of the SubjectPublicKeyInfo):

```python
session = tlsmask.Session(
    "chrome_150", certificate_pinning={"example.com": ["<pin>", "<backup pin>"]}
)
```

## Errors

| Exception | When |
|---|---|
| `tlsmask.TLSClientException` | the request couldn't be made (DNS, connection refused, timeout, proxy failure, too many redirects, a URL without `http://` or `https://`), or the tls-client library is missing or isn't the file tlsmask pinned |
| `tlsmask.HTTPError` | `response.raise_for_status()` on a 4xx or 5xx response; it is a `TLSClientException` too, and `err.response` is the response |
| `ValueError` | a profile name that doesn't exist, or a custom fingerprint without `ja3_string` |

`TLSClientException` is an `IOError`, and the old name `TLSClientExeption` refers to the same class. Its message starts with the method and URL of the request that failed.

One limitation comes from tls-client 1.16 itself: it can't read an empty response that is marked as brotli-compressed (a 204 or a HEAD response with `Content-Encoding: br`). For `GET`, `HEAD` and `OPTIONS` tlsmask quietly asks again without brotli. Other methods raise `TLSClientException` even though the server received the request; if a site does this, leave `br` out of `Accept-Encoding` for those requests.

```python
try:
    r = session.get(url, timeout=5)
    r.raise_for_status()
except tlsmask.HTTPError as err:
    print("server said", err.response.status_code)
except tlsmask.TLSClientException as err:
    print("request failed:", err)
```

## Async and threads

`AsyncSession` takes the same arguments as `Session`, and every method is awaited:

```python
async with tlsmask.AsyncSession("chrome_150") as session:
    r = await session.get(url)
    rs = await asyncio.gather(*(session.get(u) for u in urls))
```

Each request runs on a thread pool, and the native call releases the GIL, so the requests really do run at the same time. By default all `AsyncSession`s share one pool of 64 threads; `AsyncSession(..., max_workers=16)` gives a session a pool of its own. Its attributes (`headers`, `cookies`, `proxies`, ...) are those of the `Session` inside it.

A plain `Session` is safe to share between threads.

## Fine-tuning the connection

These keyword arguments of `Session` (and `AsyncSession`) change how connections are made:

| Argument | Effect |
|---|---|
| `random_tls_extension_order=True` | shuffles TLS extensions on each handshake, as current Chrome does |
| `force_http1=True` | never uses HTTP/2 |
| `disable_http3=True` | never uses HTTP/3 |
| `with_protocol_racing=True` | tries HTTP/3 and HTTP/2 at the same time and keeps the first that works |
| `disable_ipv4=True` / `disable_ipv6=True` | only connects over the other IP version |
| `local_address="192.0.2.10:0"` | the local address (and port, 0 for any) to connect from |
| `server_name_overwrite="example.com"` | the name sent in the TLS handshake (SNI), if it should differ from the URL's |
| `transport_options={...}` | connection pool settings, using tls-client's names: `maxIdleConns`, `maxIdleConnsPerHost`, `maxConnsPerHost`, `idleConnTimeout` (nanoseconds), `disableKeepAlives`, `readBufferSize`, `writeBufferSize`, `maxResponseHeaderBytes` |
| `catch_panics=False` | lets a crash inside tls-client end the process (on by default, which turns it into an exception) |
| `debug=True` | prints tls-client's debug log |

You can change any of these on a session later (`session.force_http1 = True`); the next request uses the new setting. Combinations that can't work, like `disable_ipv4` with `disable_ipv6`, or `with_protocol_racing` with `force_http1` or `disable_http3`, raise `ValueError`.

## A custom TLS fingerprint

To send a handshake of your own instead of a built-in profile, pass `client_identifier=None` and describe it. `ja3_string` is required; the rest is optional:

```python
session = tlsmask.Session(
    client_identifier=None,
    ja3_string=(
        "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,"
        "0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0"
    ),
    h2_settings={
        "HEADER_TABLE_SIZE": 65536,
        "MAX_CONCURRENT_STREAMS": 1000,
        "INITIAL_WINDOW_SIZE": 6291456,
        "MAX_HEADER_LIST_SIZE": 262144,
    },
    h2_settings_order=[
        "HEADER_TABLE_SIZE",
        "MAX_CONCURRENT_STREAMS",
        "INITIAL_WINDOW_SIZE",
        "MAX_HEADER_LIST_SIZE",
    ],
    supported_signature_algorithms=["ECDSAWithP256AndSHA256", "PSSWithSHA256", "PKCS1WithSHA256"],
    supported_versions=["GREASE", "1.3", "1.2"],
    key_share_curves=["GREASE", "X25519"],
    cert_compression_algos=["brotli"],
    pseudo_header_order=[":method", ":authority", ":scheme", ":path"],
    connection_flow=15663105,
)
```

Some extensions in a JA3 string need a matching setting, because the JA3 only says the extension is there, not what's in it:

| JA3 extension | Setting it needs |
|---|---|
| 13 (signature algorithms) | `supported_signature_algorithms` |
| 27 (certificate compression) | `cert_compression_algos` |
| 43 (supported versions) | `supported_versions` |
| 51 (key share) | `key_share_curves` |
| 16 (ALPN) | `alpn_protocols`, which defaults to `["h2", "http/1.1"]` |
| 17513 (ALPS) | `alps_protocols`, which defaults to `["h2"]` |

If one of the first four is missing, tlsmask raises `ValueError` naming it. Without that check, the handshake would fail later with an unhelpful message from tls-client.

Also available: `supported_delegated_credentials_algorithms`, `priority_frames`, `header_priority`, `record_size_limit`, `ech_candidate_payloads`, `ech_candidate_cipher_suites`, and for HTTP/3 `h3_settings`, `h3_settings_order`, `h3_pseudo_header_order`, `h3_priority_param`, `h3_send_grease_frames`. They take the values tls-client documents. These settings only apply with `client_identifier=None`; next to a profile name they are ignored with a warning.

## Checking your installation

```console
$ python -m tlsmask
tlsmask     1.16.0
tls-client  1.16.0 (github.com/bogdanfinn/tls-client)
platform    linux/x86_64 (64-bit Python) -> linux-amd64
library     OK: .../tlsmask/bin/tls-client-linux-ubuntu-amd64-1.16.0.so (sha256 2ec85349..., as pinned)
```

It exits with a non-zero status if something is wrong, and says what. Please include its output in bug reports.

On a platform without a prebuilt wheel, point tlsmask at a tls-client library you built or downloaded yourself. That file is used as it is, without the hash check:

```bash
export TLSMASK_LIBRARY_PATH=/opt/tls-client/tls-client-linux-riscv64.so
```

## How it works

tlsmask bundles tls-client as a shared library and talks to it through `ctypes`. Each request is a JSON message to the library and each answer a JSON message back, which tlsmask frees straight away. The library does the networking: the TLS handshake, HTTP/1.1, HTTP/2 and HTTP/3, compression and proxies. Cookies and redirects are handled in Python, so what you see in `session.cookies` is exactly what gets sent.

Inside the library, a session keeps a connection pool for every distinct set of connection settings (timeout, certificate checks, profile and so on), which is how per-request timeouts keep working. It keeps at most eight of them and closes the oldest beyond that. `session.close()` closes them all, and so does garbage collection if you forget to.
