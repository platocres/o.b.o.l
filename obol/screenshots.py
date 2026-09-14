"""Optional headless-browser screenshots for the debug package.

Screenshots are a *bonus*: the debug package is fully useful as text (state,
events, ledger, reports, terminal renders). When a headless Chromium is reachable
we additionally render PNGs of the web console and of a terminal-styled view, so a
reviewing agent (or human) can see what the operator saw at each point in a run.

Detection degrades gracefully, newest-capable first:
1. Playwright (`pip install "obol[debug]"` + a browser) — full-page, reliable.
2. A system/Playwright Chromium binary driven headless from the CLI — viewport-tall.
3. Nothing found — screenshots are skipped and the manifest says so.
"""
from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

_CHROME_NAMES = ["chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome"]


def _playwright_ok() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def find_chrome() -> str:
    """Absolute path to a headless-capable Chromium/Chrome, or '' if none."""
    for name in _CHROME_NAMES:
        p = shutil.which(name)
        if p:
            return p
    roots = [os.environ.get("PLAYWRIGHT_BROWSERS_PATH", ""), str(Path.home() / ".cache/ms-playwright"),
             "/opt/pw-browsers"]
    for root in roots:
        if not root:
            continue
        for pat in ("chromium-*/chrome-linux/chrome", "chromium-*/chrome-linux/headless_shell",
                    "chrome-*/chrome-linux*/chrome"):
            hits = sorted(glob.glob(str(Path(root) / pat)))
            if hits:
                return hits[-1]
    return ""


class Screenshotter:
    """Renders HTML (from a file) to a PNG. `available` is False when no engine was
    found — callers then skip screenshots and record the reason."""

    def __init__(self):
        self.engine = ""
        self.chrome = ""
        if _playwright_ok():
            self.engine = "playwright"
        else:
            self.chrome = find_chrome()
            if self.chrome:
                self.engine = "chrome-cli"

    @property
    def available(self) -> bool:
        return bool(self.engine)

    @property
    def note(self) -> str:
        if self.engine == "playwright":
            return "playwright"
        if self.engine == "chrome-cli":
            return f"chrome-cli ({self.chrome})"
        return ('no headless browser found — install with `pip install "obol[debug]" && '
                'playwright install chromium`, or install a system chromium')

    def shoot(self, html_path: Path, out_path: Path, *, width: int = 1280, height: int = 1400) -> bool:
        """Render a local HTML file to `out_path` (PNG). Returns True on success."""
        return self._render(Path(html_path).resolve().as_uri(), Path(out_path), width, height)

    def shoot_url(self, url: str, out_path: Path, *, width: int = 1280, height: int = 1400) -> bool:
        """Render a live URL (e.g. a running `obol serve`) to `out_path` (PNG)."""
        return self._render(url, Path(out_path), width, height)

    def _render(self, url: str, out_path: Path, width: int, height: int) -> bool:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if self.engine == "playwright":
                return self._playwright(url, out_path, width, height)
            if self.engine == "chrome-cli":
                return self._chrome_cli(url, out_path, width, height)
        except Exception:
            return False
        return False

    def _playwright(self, url: str, out_path: Path, width: int, height: int) -> bool:
        from playwright.sync_api import sync_playwright
        launch = {}
        if self.chrome or find_chrome():
            launch["executable_path"] = self.chrome or find_chrome()
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(**launch)
            except Exception:
                browser = p.chromium.launch()  # let playwright find its own
            page = browser.new_page(viewport={"width": width, "height": height})
            page.goto(url, wait_until="networkidle")
            page.wait_for_timeout(500)
            page.screenshot(path=str(out_path), full_page=True)
            browser.close()
        return out_path.exists()

    def _chrome_cli(self, url: str, out_path: Path, width: int, height: int) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            cmd = [self.chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
                   "--hide-scrollbars", "--virtual-time-budget=2500",
                   f"--window-size={width},{height}",
                   f"--screenshot={out_path}", f"--user-data-dir={tmp}", url]
            try:
                subprocess.run(cmd, capture_output=True, timeout=60)
            except Exception:
                cmd[1] = "--headless"  # older Chrome uses --headless (no =new)
                subprocess.run(cmd, capture_output=True, timeout=60)
        return out_path.exists()
