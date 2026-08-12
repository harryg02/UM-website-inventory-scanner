"""Optional browser-backed fetching for pages plain HTTP cannot read.

Two kinds of page defeat `requests`: single-page apps that build their links
in JavaScript, and hosts behind a bot-protection interstitial. A real browser
handles the first case outright. For the second it renders the challenge and
waits for it to resolve on its own -- nothing here patches fingerprints,
spoofs automation flags or solves CAPTCHAs, so a challenge that does not
clear by itself is reported as still blocked.
"""

from __future__ import annotations

import queue
import threading
from dataclasses import dataclass

from .config import USER_AGENT
from .fetch import CHALLENGED, ERROR, OK, Response, looks_like_challenge

RENDER_UNAVAILABLE = "render_unavailable"

INSTALL_HINT = (
    "playwright is not installed. Set it up with:\n"
    "    python3 -m venv .venv\n"
    "    .venv/bin/pip install playwright\n"
    "    .venv/bin/playwright install chromium\n"
    "then run the scanner with .venv/bin/python scan.py --render"
)


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
    except ImportError:
        return False
    return True


@dataclass
class _Job:
    url: str
    done: threading.Event
    response: Response | None = None


class PlaywrightFetcher:
    """Renders pages in Chromium, exposing the same `get()` as `Fetcher`.

    Playwright's sync API is bound to the thread that created it, so one
    dedicated worker owns the browser and every caller feeds it a queue.
    """

    def __init__(self, timeout: float = 30.0, challenge_wait: float = 15.0,
                 headless: bool = True, block_assets: bool = True):
        self.timeout = timeout
        self.challenge_wait = challenge_wait
        self.headless = headless
        self.block_assets = block_assets

        self.error = ""
        self._jobs: queue.Queue = queue.Queue()
        self._ready = threading.Event()
        self._thread: threading.Thread | None = None
        self._closed = False

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> bool:
        if not playwright_available():
            self.error = "playwright not installed"
            return False
        self._thread = threading.Thread(target=self._worker, name="renderer", daemon=True)
        self._thread.start()
        self._ready.wait(120)
        return not self.error

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._jobs.put(None)
        if self._thread:
            self._thread.join(timeout=30)

    # -- public API --------------------------------------------------------
    def get(self, url: str, retries: int = 0) -> Response:
        if self.error or self._closed:
            return Response(url, RENDER_UNAVAILABLE,
                            note=self.error or "renderer closed")

        job = _Job(url, threading.Event())
        # One browser serves every crawl worker, so a job may sit behind
        # others. Budget for the queue ahead of it, not just its own render.
        pending = self._jobs.qsize()
        per_job = self.timeout + self.challenge_wait + 30
        self._jobs.put(job)
        if not job.done.wait(per_job * (1 + pending)):
            return Response(url, ERROR, note="renderer did not respond")
        return job.response or Response(url, ERROR, note="renderer returned nothing")

    # -- worker ------------------------------------------------------------
    def _worker(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.error = "playwright not installed"
            self._ready.set()
            return

        browser = context = None
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=self.headless)
                context = browser.new_context(
                    user_agent=USER_AGENT,
                    viewport={"width": 1366, "height": 900},
                    locale="en-US",
                )
                context.set_default_timeout(self.timeout * 1000)
                if self.block_assets:
                    context.route("**/*", _skip_heavy_assets)

                page = context.new_page()
                self._ready.set()

                while True:
                    job = self._jobs.get()
                    if job is None:
                        break
                    try:
                        job.response = self._render(page, job.url)
                    except Exception as exc:            # never strand a caller
                        job.response = Response(job.url, ERROR,
                                                note=f"{type(exc).__name__}: {exc}"[:200])
                    finally:
                        job.done.set()
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"[:300]
            self._ready.set()
        finally:
            for closer in (context, browser):
                try:
                    if closer:
                        closer.close()
                except Exception:
                    pass
            self._drain()

    def _drain(self) -> None:
        """Release anyone still waiting after the worker gives up."""
        while True:
            try:
                job = self._jobs.get_nowait()
            except queue.Empty:
                return
            if job is None:
                continue
            job.response = Response(job.url, RENDER_UNAVAILABLE,
                                    note=self.error or "renderer stopped")
            job.done.set()

    def _render(self, page, url: str) -> Response:
        from playwright.sync_api import Error as PWError

        try:
            nav = page.goto(url, wait_until="domcontentloaded",
                            timeout=self.timeout * 1000)
        except PWError as exc:
            return Response(url, ERROR, note=_short(exc))

        status = nav.status if nav else 0
        html = _safe_content(page)

        if looks_like_challenge(html):
            html = self._wait_out_challenge(page, html)

        if looks_like_challenge(html):
            return Response(url, CHALLENGED, status, final_url=page.url,
                            note="challenge did not clear in browser")

        if status >= 400 and not html.strip():
            return Response(url, ERROR, status, final_url=page.url,
                            note=f"HTTP {status}")

        return Response(url, OK, status, text=html, final_url=page.url,
                        note="rendered")

    def _wait_out_challenge(self, page, html: str) -> str:
        """Give an interstitial the time it asks for, and no more.

        We only wait. If the challenge wants something a plain browser will
        not produce on its own, we let it stay blocked.
        """
        from playwright.sync_api import Error as PWError

        deadline_ms = int(self.challenge_wait * 1000)
        waited = 0
        step = 1000
        while waited < deadline_ms:
            try:
                page.wait_for_timeout(step)
            except PWError:
                break
            waited += step
            try:
                html = _safe_content(page)
            except PWError:
                break
            if not looks_like_challenge(html):
                break
        return html


def _safe_content(page, attempts: int = 4) -> str:
    """Read the DOM, tolerating a page that is mid-redirect.

    Sites that bounce through a meta-refresh or a JS redirect raise
    "page is navigating and changing the content" if we ask at the wrong
    moment. Wait for the navigation to settle and ask again.
    """
    from playwright.sync_api import Error as PWError

    for attempt in range(attempts):
        try:
            return page.content()
        except PWError as exc:
            message = str(exc).lower()
            if "navigating" not in message and "changing the content" not in message:
                raise
            if attempt == attempts - 1:
                return ""
            try:
                page.wait_for_load_state("domcontentloaded", timeout=10_000)
            except PWError:
                try:
                    page.wait_for_timeout(750)
                except PWError:
                    return ""
    return ""


def _skip_heavy_assets(route) -> None:
    """Images and fonts cost bandwidth and reveal nothing about links."""
    try:
        if route.request.resource_type in ("image", "font", "media"):
            route.abort()
        else:
            route.continue_()
    except Exception:
        pass


def _short(exc) -> str:
    return str(exc).splitlines()[0][:160] if str(exc) else type(exc).__name__


class HybridFetcher:
    """Plain HTTP first; escalate to the browser only when it buys something."""

    def __init__(self, plain, renderer: PlaywrightFetcher | None,
                 force: bool = False):
        self.plain = plain
        self.renderer = renderer
        self.force = force
        self.attempted = 0
        self.succeeded = 0
        self.still_blocked = 0
        self._seen: set = set()
        self._lock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.renderer is not None and not self.renderer.error

    def get(self, url: str, retries: int = 1) -> Response:
        if self.force and self.enabled:
            rendered = self._render_once(url)
            if rendered is not None and rendered.usable:
                return rendered

        resp = self.plain.get(url, retries=retries)
        if not self.enabled or not _worth_rendering(resp):
            return resp

        rendered = self._render_once(url)
        if rendered is None:
            return resp
        if rendered.usable:
            return rendered
        if rendered.status == CHALLENGED:
            self.still_blocked += 1
        return resp

    def _render_once(self, url: str) -> Response | None:
        with self._lock:
            if url in self._seen:
                return None
            self._seen.add(url)
            self.attempted += 1

        rendered = self.renderer.get(url)
        if rendered.usable:
            with self._lock:
                self.succeeded += 1
        return rendered

    def stats(self) -> dict:
        return {"attempted": self.attempted, "succeeded": self.succeeded,
                "still_blocked": self.still_blocked}

    def close(self) -> None:
        self.plain.close()
        if self.renderer:
            self.renderer.close()


def _worth_rendering(resp: Response) -> bool:
    if resp.status == CHALLENGED:
        return True
    if resp.status != OK or not resp.text:
        return False
    return _looks_like_js_shell(resp.text)


def _looks_like_js_shell(html: str) -> bool:
    """A page with scripts but almost no anchors builds its links at runtime."""
    lowered = html.lower()
    if lowered.count("<a ") >= 3:
        return False
    return "<script" in lowered or len(html) < 2000
