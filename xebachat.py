#!/usr/bin/python3
"""
xebachat v1.2 — advanced endpoint/param discovery crawler.
Hardened: retries, per-host rate limit, robots.txt, depth cap, canonical dedupe,
redirect-aware crawl, Content-Type sniffing, structured JSONL output.
"""
import argparse
import sys
import re
import json
import threading
import time
import hashlib
import random
from collections import defaultdict
from queue import Queue, PriorityQueue, Empty
from urllib.parse import urljoin, urlparse, urldefrag, urlunparse
from urllib.robotparser import RobotFileParser
from curl_cffi import requests


# ============================================================
# Banner
# ============================================================
class System:
    art = r"""
 ██   ██ ███████ ██████   █████   ██████ ██   ██  █████  ████████
  ██ ██  ██      ██   ██ ██   ██ ██      ██   ██ ██   ██    ██
   ███   █████   ██████  ███████ ██      ███████ ███████    ██
  ██ ██  ██      ██   ██ ██   ██ ██      ██   ██ ██   ██    ██
 ██   ██ ███████ ██████  ██   ██  ██████ ██   ██ ██   ██    ██

                     \033[2;3;4;97;41mxebachat ☣\033[0m

                     v1.2 Advanced
    """

    @staticmethod
    def banner():
        print(System.art)


# ============================================================
# Constants
# ============================================================
SKIP_EXT = (
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".avi", ".mov", ".m4a", ".webm",
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso", ".dmg",
)

ASSET_EXT = (".js", ".mjs", ".css", ".xml", ".xsl", ".xsd",
             ".php", ".asp", ".aspx", ".jsp", ".cgi", ".json")

HTML_ATTR_RE = re.compile(
    r"""(?:href|src|action|data-url|data-href|data-src|data-action|formaction|poster|cite)
        \s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""",
    re.IGNORECASE | re.VERBOSE,
)
ABS_URL_RE = re.compile(r"""https?://[^\s"'<>()\\]+""", re.IGNORECASE)
PROTO_REL_RE = re.compile(r"""(?<=["'\s(])//[a-zA-Z0-9][^\s"'<>()\\]*""")
JS_PATH_RE = re.compile(r"""["']((?:\.{0,2}/)[^"'\s<>\\]{1,512})["']""")
JS_CALL_RE = re.compile(
    r"""(
        fetch\s*\(\s*["']([^"']+)["']
      | axios(?:\.\w+)?\s*\(\s*["']([^"']+)["']
      | \.open\s*\(\s*["'][A-Z]+["']\s*,\s*["']([^"']+)["']
      | \$\.[a-zA-Z]+\s*\(\s*["']([^"']+)["']
      | import\s*\(\s*["']([^"']+)["']
      | import\s+[^;]*?from\s*["']([^"']+)["']
      | require\s*\(\s*["']([^"']+)["']
    )""", re.VERBOSE,
)
CSS_URL_RE = re.compile(r"""url\(\s*["']?([^"')]+)["']?\s*\)""", re.IGNORECASE)
CSS_IMPORT_RE = re.compile(r"""@import\s+(?:url\()?["']?([^"')\s;]+)""", re.IGNORECASE)
XML_ATTR_RE = re.compile(
    r"""(?:[a-zA-Z0-9_:-]+:)?(?:href|src|action|url)
        \s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))""",
    re.IGNORECASE | re.VERBOSE,
)
XML_TEXT_URL_RE = re.compile(
    r"<(?:[\w]+:)?(?:loc|url|link|uri|href)\b[^>]*>\s*([^<\s]+?)\s*<",
    re.IGNORECASE,
)
PHP_STR_RE = re.compile(r"""["']((?:https?://|/)[^"'\s]{1,512})["']""")
PHP_INCLUDE_RE = re.compile(r"""(?:include|require)(?:_once)?\s*\(?\s*["']([^"']+)["']""")
ENV_URL_RE = re.compile(r"""=\s*["']?(https?://[^\s"'<>]+)""", re.IGNORECASE)
META_REFRESH_RE = re.compile(
    r"""<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["'][^"']*url=([^"'>\s]+)""",
    re.IGNORECASE,
)
CANONICAL_RE = re.compile(
    r"""<link[^>]+rel\s*=\s*["']canonical["'][^>]+href\s*=\s*["']([^"']+)""",
    re.IGNORECASE,
)


# ============================================================
# URL Sanitizer
# ============================================================
_HARD_CUT_CHARS = set("\\$^*{}'`<>|\"[]")
_STRIP_CHARS = ".,;:!?'\"`)]}>*^{\\|"


def sanitize_url(url: str) -> str | None:
    if not url:
        return None
    for i, ch in enumerate(url):
        if ch.isspace():
            url = url[:i]
            break
    cut = len(url)
    for i, ch in enumerate(url):
        if ch in _HARD_CUT_CHARS:
            cut = i
            break
    url = url[:cut].strip(_STRIP_CHARS)
    return url or None


def canonical_form(url: str) -> str:
    """Normalize for dedupe: lowercase host, drop default port, strip trailing slash,
    sort query params, strip fragment."""
    try:
        p = urlparse(url)
    except ValueError:
        return url
    host = (p.hostname or "").lower()
    port = p.port
    if port and not ((p.scheme == "http" and port == 80) or (p.scheme == "https" and port == 443)):
        host = f"{host}:{port}"
    path = p.path or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    query = "&".join(sorted(p.query.split("&"))) if p.query else ""
    return urlunparse((p.scheme, host, path, "", query, ""))


def host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def registrable_domain(host: str) -> str:
    """Cheap eTLD+1 — handles .co.uk, .com.au, etc. (single-label TLDs fallback)."""
    if not host:
        return ""
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    two_level = {"co", "com", "org", "net", "gov", "edu", "ac", "mil", "sch"}
    if parts[-2] in two_level and len(parts) >= 3:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def same_site(url: str, root: str) -> bool:
    return registrable_domain(host_of(url)) == registrable_domain(host_of(root))


def url_path_lower(url: str) -> str:
    return urlparse(url).path.lower()


def is_skipped(url: str) -> bool:
    return url_path_lower(url).endswith(SKIP_EXT)


def ensure_scheme(url: str) -> str:
    if not re.match(r"^https?://", url, re.IGNORECASE):
        url = "http://" + url
    return url


def content_kind(url: str, ctype: str) -> str:
    ct = (ctype or "").lower()
    path = url_path_lower(url)
    if "javascript" in ct or "ecmascript" in ct or path.endswith((".js", ".mjs")):
        return "js"
    if "text/css" in ct or path.endswith(".css"):
        return "css"
    if "xml" in ct or path.endswith((".xml", ".xsl", ".xsd", ".svg", ".rss", ".atom")):
        return "xml"
    if "json" in ct or path.endswith(".json"):
        return "json"
    if "php" in ct or path.endswith((".php", ".asp", ".aspx", ".jsp", ".cgi")):
        return "php"
    if "html" in ct or path.endswith((".html", ".htm", "/")) or not path.rsplit("/", 1)[-1].count("."):
        return "html"
    if ct.startswith("text/") or not ct:
        return "text"
    return "other"


# ============================================================
# Helpers
# ============================================================
def normalize_url(base: str, raw: str) -> str | None:
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith(("javascript:", "mailto:", "tel:", "#", "data:", "blob:", "about:")):
        return None
    if len(raw) > 2048:
        return None
    if any(c in raw for c in ("\n", "\r", "\t", "\x00")):
        return None
    if raw.startswith("//"):
        scheme = urlparse(base).scheme or "http"
        raw = f"{scheme}:{raw}"
    try:
        full = urljoin(base, raw)
        full, _ = urldefrag(full)
    except ValueError:
        return None
    full = sanitize_url(full)
    if not full:
        return None
    try:
        p = urlparse(full)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or not p.netloc:
        return None
    return full


# ============================================================
# Parsers
# ============================================================
def _add(found: set[str], base: str, raw: str) -> None:
    if not raw:
        return
    u = normalize_url(base, raw)
    if u:
        found.add(u)


def parse_html(text, base):
    found = set()
    for m in HTML_ATTR_RE.finditer(text):
        for g in m.groups():
            if g:
                _add(found, base, g)
    for m in META_REFRESH_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in CANONICAL_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


def parse_js(text, base):
    found = set()
    for m in JS_CALL_RE.finditer(text):
        for g in m.groups():
            if g:
                _add(found, base, g)
    for m in JS_PATH_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    for m in PROTO_REL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


def parse_css(text, base):
    found = set()
    for m in CSS_URL_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in CSS_IMPORT_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


def parse_xml(text, base):
    found = set()
    for m in XML_TEXT_URL_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in XML_ATTR_RE.finditer(text):
        for g in m.groups():
            if g:
                _add(found, base, g)
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


def parse_php(text, base):
    found = set()
    for m in PHP_STR_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in PHP_INCLUDE_RE.finditer(text):
        _add(found, base, m.group(1))
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


def parse_json(text, base):
    found = set()

    def walk(obj):
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)
        elif isinstance(obj, str):
            s = obj.strip()
            if not s or len(s) > 2048:
                return
            if s.startswith(("/", "./", "../", "http://", "https://", "//")):
                _add(found, base, s)

    try:
        data = json.loads(text)
    except Exception:
        for m in ABS_URL_RE.finditer(text):
            _add(found, base, m.group(0))
        for m in JS_PATH_RE.finditer(text):
            _add(found, base, m.group(1))
        return found

    try:
        walk(data)
    except RecursionError:
        for m in ABS_URL_RE.finditer(text):
            _add(found, base, m.group(0))
    except Exception:
        pass
    return found


def parse_text(text, base):
    found = set()
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    for m in ENV_URL_RE.finditer(text):
        _add(found, base, m.group(1))
    return found


PARSERS = {
    "html": parse_html, "js": parse_js, "css": parse_css,
    "xml": parse_xml, "php": parse_php, "json": parse_json, "text": parse_text,
}


def extract_urls(text, base, kind):
    found = set()
    fn = PARSERS.get(kind)
    if fn:
        found |= fn(text, base)
    if kind in ("html", "xml", "php", "text", "other"):
        found |= parse_html(text, base)
    for m in ABS_URL_RE.finditer(text):
        _add(found, base, m.group(0))
    return found


# ============================================================
# File opener
# ============================================================
def open_output_file(path):
    seen = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                seen.add(line.rstrip("\n"))
    except FileNotFoundError:
        open(path, "w", encoding="utf-8").close()
    return seen


# ============================================================
# Output Writer (text + JSONL + dedupe by canonical form)
# ============================================================
class OutputWriter:
    def __init__(self, path, jsonl_path=None):
        self.path = path
        self.jsonl_path = jsonl_path
        self.lock = threading.Lock()
        self.seen_canon = set()
        if self.path:
            self.seen_canon = {canonical_form(l) for l in open_output_file(self.path)}
        if self.jsonl_path and not self.jsonl_path.exists() if isinstance(self.jsonl_path, type(open("x"))) else False:
            pass

    def write(self, line, status=None, depth=None, kind=None):
        line = sanitize_url(line)
        if not line:
            return False
        canon = canonical_form(line)
        with self.lock:
            if canon in self.seen_canon:
                return False
            self.seen_canon.add(canon)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            if self.jsonl_path:
                rec = {"url": line, "status": status, "depth": depth, "kind": kind,
                       "ts": time.time()}
                with open(self.jsonl_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            return True


# ============================================================
# Param config
# ============================================================
def resolve_param_config(param_val, pout_val, clean_flag):
    if param_val is None and pout_val is None:
        return (False, None, [], None, False)
    if param_val is None and pout_val is not None:
        print("[!] --pout requires --param to be set.")
        return (False, None, [], None, False)
    if param_val == "":
        mode, exts, file_from_param = "path", [], None
    elif "." in param_val and "," not in param_val:
        mode, exts, file_from_param = "path", [], param_val
    elif param_val.lower() == "type_clean":
        mode, exts, file_from_param = "clean", [], None
    else:
        exts = [x.strip().lstrip(".").lower() for x in param_val.split(",") if x.strip()]
        if not exts:
            print("[!] --param value is empty, ignoring.")
            return (False, None, [], None, False)
        return (True, "ext", exts, pout_val, clean_flag)
    if file_from_param and pout_val:
        print("[!] --param already contains a filename; --pout ignored.")
    out_file = file_from_param or pout_val
    clean = clean_flag
    if mode == "clean" and clean_flag:
        print("[!] --param=type_clean with --clean; type_clean wins.")
        clean = False
    return (True, mode, exts, out_file, clean)


def extract_param_from_url(url: str, mode: str, exts: list[str], clean: bool = False) -> str | None:
    p = urlparse(url)
    path = p.path or "/"
    query = p.query
    if mode == "path":
        s = path + (("?" + query) if query else "")
        if s == "/":
            return None
        if clean:
            s = s.rsplit("/", 1)[-1]
        return s or None
    if mode == "clean":
        seg = path.lstrip("/").split("/", 1)[0]
        return ("/" + seg) if seg else None
    if mode == "ext":
        fname = path.rsplit("/", 1)[-1].lower()
        for e in exts:
            if fname.endswith("." + e) or fname == e:
                val = path.lstrip("/").rstrip("/")
                return (val.rsplit("/", 1)[-1] if clean else val) or None
        return None
    return None


class ParamsWriter:
    def __init__(self, path, mode, exts, clean=False):
        self.path, self.mode, self.exts, self.clean = path, mode, exts, clean
        self.lock = threading.Lock()
        self.seen = open_output_file(path) if path else set()

    def offer(self, url):
        val = extract_param_from_url(url, self.mode, self.exts, self.clean)
        if not val:
            return False
        val = sanitize_url(val)
        if not val:
            return False
        with self.lock:
            if val in self.seen:
                return False
            self.seen.add(val)
            if self.path:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(val + "\n")
            else:
                print(val)
        return True


# ============================================================
# Session Factory (thread-local) + rate limiter + robots
# ============================================================
class RateLimiter:
    def __init__(self, rps: float):
        self.min_interval = 1.0 / rps if rps > 0 else 0.0
        self.lock = threading.Lock()
        self.last: dict[str, float] = defaultdict(float)

    def wait(self, host: str):
        if self.min_interval <= 0:
            return
        with self.lock:
            now = time.monotonic()
            delta = now - self.last[host]
            if delta < self.min_interval:
                time.sleep(self.min_interval - delta)
            self.last[host] = time.monotonic()


class RobotsCache:
    def __init__(self, session_factory, enabled: bool, ua: str):
        self.enabled = enabled
        self.ua = ua
        self.sf = session_factory
        self.lock = threading.Lock()
        self.cache: dict[str, RobotFileParser | None] = {}

    def allowed(self, url: str) -> bool:
        if not self.enabled:
            return True
        host = urlparse(url).netloc
        with self.lock:
            rp = self.cache.get(host, "miss")
        if rp == "miss":
            rp = None
            try:
                robots_url = f"{urlparse(url).scheme}://{host}/robots.txt"
                r = self.sf.get().get(robots_url, timeout=8)
                if r.status_code == 200:
                    rp = RobotFileParser()
                    rp.parse(r.text.splitlines())
            except Exception:
                rp = None
            with self.lock:
                self.cache[host] = rp
        if rp is None:
            return True
        try:
            return rp.can_fetch(self.ua, url)
        except Exception:
            return True


class SessionFactory:
    def __init__(self, args):
        self.args = args
        self._local = threading.local()

    def get(self):
        s = getattr(self._local, "session", None)
        if s is None:
            s = requests.Session(impersonate="firefox")
            if self.args.tor:
                s.proxies = {"http": "socks5h://127.0.0.1:9050",
                             "https": "socks5h://127.0.0.1:9050"}
            if self.args.agent:
                s.headers["User-Agent"] = self.args.agent
            else:
                s.headers["User-Agent"] = (
                    "Mozilla/5.0 (Android 17; Mobile; rv:157.0) Gecko/157.0 Fennec/157.0"
                )
            if self.args.cookie:
                s.headers["Cookie"] = self.args.cookie
            if self.args.headers:
                for h in self.args.headers:
                    if ":" in h:
                        k, v = h.split(":", 1)
                        s.headers[k.strip()] = v.strip()
            self._local.session = s
        return s


# ============================================================
# Single Request
# ============================================================
def do_single_request(args):
    url = ensure_scheme(args.request)
    print(f"[*] Request: {url}")
    factory = SessionFactory(args)
    try:
        r = factory.get().get(url, timeout=20, allow_redirects=True)
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    print(f"[*] Status : {r.status_code}")
    print(f"[*] URL    : {r.url}")
    print(f"[*] Ctype  : {r.headers.get('content-type', '-')}")
    print(f"[*] Length : {len(r.content)} bytes")
    cfg = resolve_param_config(args.param, args.pout, args.clean)
    if cfg and cfg[0]:
        _, mode, exts, out_file, clean = cfg
        pw = ParamsWriter(out_file, mode, exts, clean)
        kind = content_kind(r.url, r.headers.get("content-type", ""))
        try:
            text = r.text
        except Exception:
            text = ""
        urls = extract_urls(text, r.url, kind) if text else set()
        urls.add(r.url)
        for u in urls:
            pw.offer(u)
        print(f"[*] Params : {out_file or 'screen'} ({mode}) → {len(pw.seen)} lines")
    print("\n----- BODY -----\n" + r.text + "\n----- /BODY -----")
    return 0


# ============================================================
# Crawler
# ============================================================
class Cheri:
    def __init__(self, args):
        self.args = args
        self.root = self._normalize_root(args.url)
        self.queue: PriorityQueue = PriorityQueue()
        self.visited = set()          # canonical forms
        self.visited_lock = threading.Lock()
        self.found_count = 0
        self.count_lock = threading.Lock()
        self.active = 0
        self.active_lock = threading.Lock()
        self.stop_event = threading.Event()
        self.output = OutputWriter(args.output, args.jsonl)
        self.sessions = SessionFactory(args)
        self.rate = RateLimiter(args.rps)
        self.robots = RobotsCache(self.sessions, args.respect_robots,
                                  args.agent or "xebachat/1.2")
        self.start_time = time.time()
        self.errors = defaultdict(int)

        self.params_writer = None
        self._params_mode = None
        self._params_file = None
        self._params_clean = False
        cfg = resolve_param_config(args.param, args.pout, args.clean)
        if cfg and cfg[0]:
            _, mode, exts, out_file, clean = cfg
            self.params_writer = ParamsWriter(out_file, mode, exts, clean)
            self._params_mode, self._params_file, self._params_clean = mode, out_file, clean

    def _normalize_root(self, url):
        url = ensure_scheme(url)
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}{p.path or '/'}"

    def enqueue(self, url, depth: int = 0):
        if not url:
            return
        if self.args.max_depth is not None and depth > self.args.max_depth:
            return
        canon = canonical_form(url)
        with self.visited_lock:
            if canon in self.visited:
                return
            self.visited.add(canon)
        if self.args.limit and self.found_count >= self.args.limit:
            return
        # priority = path depth (shallower first)
        pri = depth
        self.queue.put((pri, time.time(), url, depth))

    def fetch(self, url):
        self.rate.wait(urlparse(url).netloc)
        if not self.robots.allowed(url):
            return ("__robots__", None, url)
        last_err = None
        for attempt in range(self.args.retries + 1):
            if self.stop_event.is_set():
                return None
            try:
                r = self.sessions.get().get(
                    url, timeout=self.args.timeout, allow_redirects=True
                )
                if r.status_code in (429, 503) and attempt < self.args.retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                ctype = r.headers.get("content-type", "")
                kind = content_kind(r.url, ctype)
                if kind == "other":
                    return None
                try:
                    text = r.text
                except Exception:
                    return None
                return (text, kind, r.url, r.status_code)
            except Exception as e:
                last_err = e
                if attempt < self.args.retries:
                    time.sleep(1.0 * (attempt + 1) + random.random())
        if self.args.debug and last_err:
            print(f"[!] {url} -> {last_err}")
        self.errors[type(last_err).__name__ if last_err else "unknown"] += 1
        return None

    def worker(self, tid):
        while not self.stop_event.is_set():
            try:
                _, _, url, depth = self.queue.get(timeout=0.5)
            except Empty:
                with self.active_lock:
                    if self.active == 0 and self.queue.empty():
                        return
                continue
            with self.active_lock:
                self.active += 1
            try:
                res = self.fetch(url)
                if res and res[0] != "__robots__":
                    text, kind, final_url, status = res
                    if self.output.write(url, status=status, depth=depth, kind=kind):
                        with self.count_lock:
                            self.found_count += 1
                            n = self.found_count
                        print(f"[+] {url}")
                        if self.args.limit and n >= self.args.limit:
                            self.stop_event.set()
                    if self.params_writer:
                        self.params_writer.offer(url)
                    if self.args.debug:
                        print(f"[.] parse({kind}) {url}")
                    for link in extract_urls(text, final_url, kind):
                        if is_skipped(link):
                            continue
                        if self.args.stay and not same_site(link, self.root):
                            continue
                        self.enqueue(link, depth + 1)
                elif res and res[0] == "__robots__":
                    if self.args.debug:
                        print(f"[r] robots blocked {url}")
            finally:
                with self.active_lock:
                    self.active -= 1
                self.queue.task_done()

    def run(self):
        System.banner()
        print(f"[*] Target       : {self.root}")
        print(f"[*] Threads      : {self.args.threads}")
        print(f"[*] Rate (rps)   : {self.args.rps}")
        print(f"[*] Tor          : {'on' if self.args.tor else 'off'}")
        print(f"[*] Stay         : {'on' if self.args.stay else 'off'}")
        print(f"[*] Robots       : {'on' if self.args.respect_robots else 'off'}")
        print(f"[*] Max depth    : {self.args.max_depth if self.args.max_depth is not None else 'unlimited'}")
        print(f"[*] Output       : {self.args.output or '-'}")
        if self.args.jsonl:
            print(f"[*] JSONL        : {self.args.jsonl}")
        if self.params_writer:
            flags = self._params_mode + (", clean" if self._params_clean else "")
            print(f"[*] Param        : {flags} → {self._params_file or 'screen'}")
        print(f"[*] Limit        : {self.args.limit or 'unlimited'}")
        print()

        self.enqueue(self.root, 0)
        threads = []
        for i in range(self.args.threads):
            t = threading.Thread(target=self.worker, args=(i,), daemon=True)
            t.start()
            threads.append(t)
        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            print("\n[!] User cancelled. Draining...")
            self.stop_event.set()
            for t in threads:
                t.join(timeout=2)

        elapsed = time.time() - self.start_time
        print(f"\n[*] Total found  : {self.found_count}")
        if self.params_writer:
            print(f"[*] Param lines  : {len(self.params_writer.seen)}")
        print(f"[*] Errors       : {dict(self.errors) or 'none'}")
        print(f"[*] Duration     : {elapsed:.2f}s")
        if self.args.output:
            print(f"[*] Saved to     : {self.args.output}")
        if self.args.jsonl:
            print(f"[*] JSONL saved  : {self.args.jsonl}")


# ============================================================
# CLI
# ============================================================
def build_parser():
    p = argparse.ArgumentParser(
        prog="xebachat",
        description="xebachat v1.2 — advanced endpoint/parameter discovery",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  xebachat -u https://example.com -o out.txt -t 10 --rps 5\n"
            "  xebachat -u example.com --jsonl crawl.jsonl --max-depth 3\n"
            "  xebachat -u http://abc.onion --tor --stay -t 5\n"
            "  xebachat -u URL --param=pdf,doc --pout params.txt\n"
            "  xebachat -r https://example.com\n"
            "\n"
            "Safety flags:\n"
            "  --respect-robots   obey robots.txt (recommended)\n"
            "  --rps N            throttle per host (default 5 req/s)\n"
            "  --max-depth N      crawl depth cap\n"
            "  --retries N        retry transient failures\n"
            "  --headers \"K: V\"   extra headers (repeatable)\n"
            "  --cookie \"K=V\"     cookie header\n"
        ),
    )
    mode = p.add_mutually_exclusive_group(required=True)
    mode.add_argument("-u", "--url", help="Target URL (crawl mode)")
    mode.add_argument("-r", "--request", help="Single request (no crawl)")
    p.add_argument("-o", "--output", help="Save unique URLs (append)")
    p.add_argument("--jsonl", help="Structured JSONL output (url,status,depth,kind,ts)")
    p.add_argument("-t", "--threads", type=int, default=5)
    p.add_argument("-ua", "--agent", help="User-Agent")
    p.add_argument("--stay", action="store_true", help="Same registrable domain only")
    p.add_argument("--tor", action="store_true", help="Tor SOCKS5 proxy")
    p.add_argument("--limit", type=int, help="URL discovery limit")
    p.add_argument("--max-depth", type=int, default=None, help="Crawl depth cap")
    p.add_argument("--retries", type=int, default=2, help="Retries on transient errors")
    p.add_argument("--timeout", type=int, default=15, help="Request timeout (s)")
    p.add_argument("--rps", type=float, default=5.0, help="Max requests/sec per host")
    p.add_argument("--respect-robots", action="store_true", help="Obey robots.txt")
    p.add_argument("--headers", action="append", help="Extra header 'Key: Value' (repeatable)")
    p.add_argument("--cookie", help="Cookie header string")
    p.add_argument(
        "--param", nargs="?", const="", default=None, metavar="VALUE",
        help="Parameter filter (ext-list | type_clean | filename | empty=path mode)",
    )
    p.add_argument("--pout", metavar="FILE", help="Param output file (append)")
    p.add_argument("--clean", action="store_true", help="Reduce to last segment")
    p.add_argument("-de", "--debug", action="store_true")
    p.add_argument("-v", "--version", action="version", version="xebachat 1.2")
    return p


def main():
    parser = build_parser()
    args = parser.parse_args()
    if args.threads < 1:
        print("[!] -t must be >= 1")
        return 2
    if args.limit is not None and args.limit < 1:
        print("[!] --limit must be >= 1")
        return 2
    if args.rps < 0:
        print("[!] --rps must be >= 0")
        return 2
    if args.request:
        System.banner()
        return do_single_request(args)
    crawler = Cheri(args)
    try:
        crawler.run()
    except Exception as e:
        print(f"[!] Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())