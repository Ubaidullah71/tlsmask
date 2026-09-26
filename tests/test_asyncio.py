from __future__ import annotations

import asyncio
import copy
import threading

from fake_library import FakeLibrary

from tlsmask import AsyncSession, _library

URL = "https://x.test/"


def test_requests_and_close(fake):
    async def main():
        async with AsyncSession("firefox_148") as s:
            r = await s.get(URL)
            await s.post(URL, json={"a": 1})
            return r

    r = asyncio.run(main())
    assert r.status_code == 200
    assert [name for name, _ in fake.calls] == ["request", "request", "destroySession"]
    assert fake.requests[1]["requestBody"] == '{"a":1}'
    assert fake.requests[0]["tlsClientIdentifier"] == "firefox_148"


def test_attributes_are_the_sessions(fake):
    s = AsyncSession()
    s.proxies = {"https": "http://p:1"}
    assert s._session.proxies == {"https": "http://p:1"}
    assert s.headers is s._session.headers
    asyncio.run(s.get(URL))
    assert fake.requests[0]["proxyUrl"] == "http://p:1"


class BlockingLibrary(FakeLibrary):
    """Answers only once `parties` requests are inside the library at the same time."""

    def __init__(self, parties: int) -> None:
        super().__init__()
        self.barrier = threading.Barrier(parties, timeout=5)

    def request(self, raw):
        self.barrier.wait()
        return super().request(raw)


def test_requests_run_concurrently(monkeypatch):
    monkeypatch.setattr(_library, "_lib", BlockingLibrary(5))

    async def main():
        s = AsyncSession(max_workers=5)
        try:
            return await asyncio.gather(*(s.get(URL) for _ in range(5)))
        finally:
            await s.close()

    assert [r.status_code for r in asyncio.run(main())] == [200] * 5


def test_an_own_pool_survives_closing_twice_and_reuse(fake):
    async def main():
        s = AsyncSession(max_workers=2)
        await s.get(URL)
        await s.close()
        await s.close()
        r = await s.get(URL)  # like a Session, it works again after close()
        async with s:
            pass
        return r

    assert asyncio.run(main()).status_code == 200


def test_an_async_session_can_be_copied(fake):
    clone = copy.copy(AsyncSession())
    assert clone.headers is not None
