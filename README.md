<div align="center">

# tlsmask

**Python HTTP requests with a real browser's TLS and HTTP/2 fingerprint.**

<a href="https://pypi.org/project/tlsmask/"><img src="https://img.shields.io/pypi/v/tlsmask?color=0a7cff" alt="PyPI"></a>
<a href="https://pypi.org/project/tlsmask/"><img src="https://img.shields.io/pypi/pyversions/tlsmask" alt="Python"></a>
<a href="https://pypistats.org/packages/tlsmask"><img src="https://img.shields.io/pypi/dm/tlsmask" alt="Downloads"></a>
<a href="https://github.com/Ubaidullah71/tlsmask/actions/workflows/ci.yml"><img src="https://github.com/Ubaidullah71/tlsmask/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
<a href="https://github.com/Ubaidullah71/tlsmask/blob/main/LICENSE"><img src="https://img.shields.io/pypi/l/tlsmask" alt="License"></a>
<!-- badge:start --><a href="https://github.com/bogdanfinn/tls-client/releases/tag/v1.18.1"><img src="https://img.shields.io/badge/bundles_tls--client-v1.18.1-0a7cff" alt="bundles tls-client v1.18.1"></a><!-- badge:end -->

</div>

tlsmask makes HTTP requests from Python that look like they come from Chrome, Firefox or Safari. Not just the headers: the TLS handshake and the HTTP/2 settings match the browser too. It runs [bogdanfinn's tls-client](https://github.com/bogdanfinn/tls-client), a Go library, and ships its latest official build inside the package.

It is also a drop-in replacement for the [`tls-client`](https://pypi.org/project/tls-client/) package, which hasn't had a release since February 2024.

```python
import tlsmask

with tlsmask.Session("chrome_150") as session:
    r = session.get("https://tls.peet.ws/api/all")
    print(r.status_code, r.protocol)  # 200 HTTP/2.0
    print(r.json()["tls"]["ja4"])  # Chrome's fingerprint, not Python's
```

## Why

Every HTTPS connection starts with a TLS "ClientHello": a list of the ciphers, extensions and curves the client supports, in a particular order. Each browser sends its own recognisable version (often summarised as a JA3 or JA4 fingerprint), and so does Python. A server can tell them apart before it reads a single header, which is why `requests` with a Chrome User-Agent still doesn't look like Chrome.

bogdanfinn's tls-client reproduces real browsers' handshakes and HTTP/2 behaviour. The `tls-client` package made it usable from Python, but it stopped at version 1.0.1. It still bundles tls-client v1.7.2, so its newest browser is Chrome 120, and a number of its bugs were never fixed.

tlsmask carries on from there: the current library, the same API, those bugs fixed, and a weekly check for new tls-client releases.

## tlsmask compared with tls-client
<!-- stats:start -->
| | `tls-client` (the old wrapper) | **tlsmask** |
|---|:---:|:---:|
| bogdanfinn/tls-client inside | v1.7.2 | **v1.18.1** |
| Browser & app profiles | 51 | **86** |
| Newest Chrome | 120 | **154** |
| Newest Firefox | 120 | **148** |
| Newest iOS Safari | 16.0 | **26.0** |
| Brave | none | **146** |
| Last updated | Feb 2024 | **Nov 2026** |
| Native library checked against a pinned SHA-256 | no | **yes, at build and at load** |
| Keeps itself current | no | **yes, a weekly bot** |
<!-- stats:end -->

## Installation

```bash
pip install tlsmask
```

Prebuilt wheels are available for:

- Windows, 64-bit and 32-bit
- macOS 13 or newer, Apple Silicon and Intel
- Linux x86-64, ARM64 and ARMv7 (glibc 2.17 or newer)

Each wheel already contains the tls-client library for its platform, so nothing is downloaded when your code runs. tlsmask needs Python 3.9 or newer and has no other dependencies.

## Usage

```python
import tlsmask

session = tlsmask.Session("chrome_150")
session.headers.update(
    {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "en-US,en;q=0.9",
    }
)

r = session.get("https://example.com", params={"q": "tls"})
print(r.status_code, r.headers["content-type"])

r = session.post("https://httpbin.org/post", json={"hello": "world"})
print(r.json())

session.close()
```

With asyncio:

```python
import asyncio

import tlsmask


async def main():
    async with tlsmask.AsyncSession("firefox_148") as session:
        pages = await asyncio.gather(
            *(session.get(f"https://example.com/?page={i}") for i in range(10))
        )
        print([page.status_code for page in pages])


asyncio.run(main())
```

The **[guide](https://github.com/Ubaidullah71/tlsmask/blob/main/docs/guide.md)** covers the rest: header order, cookies, proxies, redirects, timeouts, errors, threads, custom TLS fingerprints and how to check your install.

## Switching from tls-client

```diff
- import tls_client
+ import tlsmask as tls_client
```

For most code that's the only change. The constructor arguments, the request methods, `response.json()` and the `session.cookies` helpers work the same way. A few things behave differently on purpose, mostly because the old behaviour was a bug:

| | `tls-client` | tlsmask |
|---|---|---|
| Unknown `client_identifier` (including typos like `chrome112`) | silently sends a different browser | raises `ValueError` and suggests the closest names |
| A panic inside the Go library | kills the whole Python process | raises `TLSClientException` (`catch_panics` is on by default) |
| `proxies={"https": ...}` | ignored, so the request goes out **without** the proxy | used |
| `post(json=...)` | adds `Content-Type` to every later request | adds it to that request only |
| Binary responses (images, PDFs) | corrupted | returned byte for byte |
| Header order | tls-client's own order | the order you wrote them in (or `header_order=`) |
| `cert_compression_algo` | silently ignored by current tls-client | translated to the new setting |
| `params` on a URL that already has `?` | `url?a=1?b=2` | `url?a=1&b=2` |
| Deleting a cookie | still sent, because a second copy lives inside Go | gone from the next request |
| Different `timeout_seconds` or `insecure_skip_verify` per request | ignored after the first request | honoured every time |
| Default profile | `chrome_120` | tls-client's current default (`tlsmask.DEFAULT_PROFILE`) |
| `get(url, cookies={...})` | also stored those cookies in `session.cookies` | sends them with that request only, and only to that site, even across redirects |
| A proxy written as `host:port` | failed | treated as `http://host:port`, like `requests` |
| `Authorization` on a redirect | kept whenever the host name matches | kept only on the same origin, or on an upgrade from http to https |
| `client_identifier=None` | built a client from whatever was set, failing later if something was missing | checks up front that `ja3_string` and the settings its extensions need are there, and raises `ValueError` naming what's missing; ALPN defaults to what browsers send |
| `additional_decode=` | decoded one extra encoding | not needed any more (tls-client decodes everything); it warns and is ignored |

The old misspelled `TLSClientExeption` still works. If your code imports `tls_client.settings.ClientIdentifiers`, use `tlsmask.ClientIdentifiers` instead. `response.headers` is case-insensitive now, so use `dict(response.headers)` where you need a plain dict (for `json.dumps`, say).

## Choosing a profile

For most uses, pick a current browser, such as the default (`tlsmask.DEFAULT_PROFILE`), `firefox_148` or `safari_ios_26_0`. Send a User-Agent that matches the profile, because a Firefox User-Agent over a Chrome handshake stands out on its own. The `_PSK` variants resume TLS sessions the way a returning visitor's browser does.

`tlsmask.PROFILES` holds every name, and editors autocomplete them through the `tlsmask.ClientIdentifier` type.
<!-- profiles:start -->
<details>
<summary><b>All 86 profiles in tls-client v1.18.1</b></summary>

| Family | Profiles |
|---|---|
| Chrome | `chrome_103` `chrome_104` `chrome_105` `chrome_106` `chrome_107` `chrome_108` `chrome_109` `chrome_110` `chrome_111` `chrome_112` `chrome_116_PSK` `chrome_116_PSK_PQ` `chrome_117` `chrome_120` `chrome_124` `chrome_130_PSK` `chrome_131` `chrome_131_PSK` `chrome_133` `chrome_133_PSK` `chrome_144` `chrome_144_PSK` `chrome_146` `chrome_146_PSK` `chrome_150` `chrome_150_PSK` `chrome_152` `chrome_152_PSK` `chrome_154` `chrome_154_PSK` |
| Firefox | `firefox_102` `firefox_104` `firefox_105` `firefox_106` `firefox_108` `firefox_110` `firefox_117` `firefox_120` `firefox_123` `firefox_132` `firefox_133` `firefox_135` `firefox_146_PSK` `firefox_147` `firefox_147_PSK` `firefox_148` |
| Safari (iOS & iPadOS) | `safari_ios_15_5` `safari_ios_15_6` `safari_ios_16_0` `safari_ios_17_0` `safari_ios_18_0` `safari_ios_18_5` `safari_ios_26_0` `safari_ipad_15_6` |
| Safari (macOS) | `safari_15_6_1` `safari_16_0` `safari_27_2` |
| Opera | `opera_89` `opera_90` `opera_91` |
| Brave | `brave_146` `brave_146_PSK` |
| Mobile apps & others | `cloudscraper` `confirmed_android` `confirmed_ios` `mesh_android` `mesh_android_1` `mesh_android_2` `mesh_ios` `mesh_ios_1` `mesh_ios_2` `mms_ios` `mms_ios_1` `mms_ios_2` `mms_ios_3` `nike_android_mobile` `nike_ios_mobile` `okhttp4_android_7` `okhttp4_android_8` `okhttp4_android_9` `okhttp4_android_10` `okhttp4_android_11` `okhttp4_android_12` `okhttp4_android_13` `zalando_android_mobile` `zalando_ios_mobile` |

</details>
<!-- profiles:end -->

## Where the library comes from

The native part of tlsmask is bogdanfinn's own release file, byte for byte. It isn't rebuilt or modified.

1. When a wheel is built, the file is downloaded from [tls-client's GitHub releases](https://github.com/bogdanfinn/tls-client/releases). The build refuses it unless its SHA-256 matches both the hash pinned in [`tlsmask/_pins.py`](https://github.com/Ubaidullah71/tlsmask/blob/main/tlsmask/_pins.py) and the digest GitHub publishes for the release.
2. The first time your program makes a request, tlsmask hashes the file again and won't load it if it doesn't match.
3. Releases are published to PyPI from GitHub Actions with trusted publishing and signed attestations, and every GitHub release includes a `SHA256SUMS` file.

To check your own installation:

```console
$ python -m tlsmask
tlsmask     1.16.0
tls-client  1.16.0 (github.com/bogdanfinn/tls-client)
platform    win32/AMD64 (64-bit Python) -> windows-amd64
library     OK: ...\tlsmask\bin\tls-client-windows-64-1.16.0.dll (sha256 53dca636..., as pinned)
```

## Staying up to date

Every Monday a scheduled job looks for a new tls-client release. When there is one, it downloads and verifies every file, reads the new list of profiles, compares the library's API with the previous version, and runs the full test suite on Windows, macOS and Linux, on both Intel and ARM machines.

If nothing important changed and the release is at least a week old, a new tlsmask version is published automatically. Anything unusual, like a removed profile or a changed API, waits for a person to look at it first.

## FAQ

**Is this an official bogdanfinn project?**
No. tlsmask is an independent project and isn't affiliated with or endorsed by Bogdan Finn. It bundles his library unmodified. Please report tlsmask problems [here](https://github.com/Ubaidullah71/tlsmask/issues) rather than to him.

**Does it work on Alpine Linux?**
Not at the moment. tls-client's Alpine (musl) build can't be loaded into Python, so there is no Alpine wheel. In Docker, use a glibc-based image such as `python:3.12-slim` instead.

**My platform has no wheel.**
Get a build of tls-client for it (from its releases, or build it yourself) and point tlsmask at the file with the `TLSMASK_LIBRARY_PATH` environment variable. On such a platform `pip install tlsmask` installs from the source distribution, which has no library of its own.

**Does it work with multiprocessing?**
Yes. The library is only loaded when the first request is made, so child processes are fine as long as the parent hadn't made a request before it forked. If in doubt, use the `spawn` start method (the default on Windows and macOS).

**Why aren't redirects followed by default?**
`tls-client` didn't follow them by default, so existing code keeps working. Pass `allow_redirects=True`.

**What is it for?**
Making requests that look like a real browser: testing your own site's bot protection, research, or talking to APIs that turn away non-browser clients. Please respect the terms of the sites you use it with.

## Contributing

Bug reports and pull requests are welcome. To set up a development copy:

```bash
git clone https://github.com/Ubaidullah71/tlsmask && cd tlsmask
python -m venv .venv && source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python scripts/fetch_binaries.py  # downloads and verifies this machine's library into tlsmask/bin/
pytest                            # unit tests, plus tests against the real library and a local server
pytest -m live                    # fingerprint checks against a public echo service
```

`tlsmask/_pins.py`, `tlsmask/profiles.py`, `tlsmask/_version.py` and the tables in this README are generated by `scripts/render.py`, so please don't edit them by hand.

## Credits

- [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client) does the real work. *This product includes software developed by Bogdan Finn*, distributed under the BSD 4-Clause license (see [LICENSE-tls-client](https://github.com/Ubaidullah71/tlsmask/blob/main/LICENSE-tls-client)).
- [FlorianREGAZ/Python-Tls-Client](https://github.com/FlorianREGAZ/Python-Tls-Client) designed the Python API that tlsmask keeps compatible.

## License

tlsmask's own code is under the [MIT license](https://github.com/Ubaidullah71/tlsmask/blob/main/LICENSE). The bundled tls-client library is under the BSD 4-Clause license ([LICENSE-tls-client](https://github.com/Ubaidullah71/tlsmask/blob/main/LICENSE-tls-client)).
