"""Web Search — real-time intelligence gathering for the AI agent.

Multi-engine, keyless-first search stack (resilient when one engine
blocks or changes its markup):

1. Bing RSS (primary — programmatic endpoint, no JS wall, no API key)
2. Bing HTML (secondary)
3. DuckDuckGo Lite / HTML (fallbacks)
4. Mojeek HTML (last resort)
5. Optional Google Custom Search API (if keys configured)

A small TTL cache prevents hammering engines with repeated identical
queries from swarm loops. Also provides URL content fetching and CVE /
exploit lookups.
"""

from __future__ import annotations

import html as html_module
import json
import logging
import re
import time
from typing import Any
from urllib.parse import quote_plus, unquote, urlparse

import requests

logger = logging.getLogger("zahra.ai_agent.web_search")

_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class WebSearch:
    """Web search and content fetching for the AI agent."""

    def __init__(self, google_api_key: str = "", google_cx: str = "") -> None:
        self.google_api_key = google_api_key
        self.google_cx = google_cx
        self._session = requests.Session()
        self._session.headers.update(
            {
                "User-Agent": _UA,
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        self._cache: dict[str, tuple[float, list[dict[str, Any]]]] = {}
        self._cache_ttl = 180.0  # seconds
        self._cache_max = 256
        self._engine_delay = 1.5  # seconds between engine requests (rate-limit guard)

    # ------------------------------------------------------------------ cache

    def _cache_get(self, key: str) -> list[dict[str, Any]] | None:
        hit = self._cache.get(key)
        if hit and (time.time() - hit[0]) < self._cache_ttl:
            return hit[1]
        return None

    def _cache_put(self, key: str, results: list[dict[str, Any]]) -> None:
        if len(self._cache) >= self._cache_max:
            oldest = min(self._cache, key=lambda k: self._cache[k][0])
            self._cache.pop(oldest, None)
        self._cache[key] = (time.time(), results)

    # ----------------------------------------------------------------- search

    _STOP = {
        "the", "and", "for", "are", "was", "with", "how", "what", "when", "where",
        "who", "why", "this", "that", "from", "into", "which", "have", "has", "its",
        "not", "you", "your", "our", "their", "about", "than", "then", "them", "they",
        "will", "would", "can", "could", "should", "may", "might", "there", "these",
        "those", "also", "all", "any", "per", "via", "using", "used",
    }

    def _extract_terms(self, query: str) -> list[str]:
        words = re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]+", query.lower())
        return [w for w in words if len(w) >= 3 and w not in self._STOP]

    def _relevance(self, results: list[dict[str, Any]], terms: list[str]) -> float:
        """Fraction of results that mention at least one query term."""
        if not results or not terms:
            return 0.0
        hit = 0
        for r in results:
            blob = f"{r.get('title', '')} {r.get('url', '')} {r.get('snippet', '')}".lower()
            if any(t in blob for t in terms):
                hit += 1
        return hit / len(results)

    def search(self, query: str, top_k: int = 5) -> list[dict[str, Any]]:
        """Search the web and return top results across engines.

        Engines that answer with off-topic junk (rate-limit artifacts) are
        rejected via a keyword-relevance gate, so the stack always tries
        the next engine.

        If Agent-Reach is available (libs/agent-reach on sys.path), results
        from the GitHub / RSS / Exa channels are merged in as an additional
        OSINT layer, ranked alongside the engine results.
        """
        cached = self._cache_get(query)
        if cached is not None:
            return self._merge_ar(self._dedupe(cached[:top_k]), query, top_k)

        if self.google_api_key and self.google_cx:
            results = self._search_google(query, top_k)
            if results:
                self._cache_put(query, results)
                return self._merge_ar(self._dedupe(results[:top_k]), query, top_k)

        terms = self._extract_terms(query)
        fallback: list[dict[str, Any]] = []
        fallback_rel = 0.0
        for engine in (self._search_bing_rss, self._search_bing, self._search_ddg_lite,
                       self._search_duckduckgo, self._search_mojeek):
            try:
                time.sleep(self._engine_delay)
                results = engine(query, top_k)
            except Exception:
                logger.exception("web search engine failed: %s", getattr(engine, "__name__", "?"))
                results = []
            if not results:
                continue
            results = self._dedupe(results)
            rel = self._relevance(results, terms)
            if rel >= 0.5:
                self._cache_put(query, results)
                return self._merge_ar(results[:top_k], query, top_k)
            if rel > fallback_rel:  # keep the most on-topic batch as last resort
                fallback, fallback_rel = results, rel
            logger.info("rejected off-topic results from %s (relevance %.2f)",
                        getattr(engine, "__name__", "?"), rel)

        if fallback:
            self._cache_put(query, fallback)
        merged = self._merge_ar(fallback[:top_k], query, top_k) if fallback else self._agent_reach_only(query, top_k)
        return merged

    def _agent_reach_only(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Return results only from Agent-Reach channels (no engine hit)."""
        ar = self._ar_results(query, top_k)
        return ar[:top_k]

    def _merge_ar(
        self, engine_results: list[dict[str, Any]], query: str, top_k: int
    ) -> list[dict[str, Any]]:
        """Merge Agent-Reach OSINT results into the engine results list."""
        ar = self._ar_results(query, top_k)
        if not ar:
            return engine_results
        # Merge, deduplicate by URL, re-rank keeping engine results first
        merged = list(engine_results)
        seen_urls = {r.get("url", "") for r in merged}
        for r in ar:
            url = r.get("url", "")
            if url and url not in seen_urls:
                merged.append(r)
                seen_urls.add(url)
            if len(merged) >= top_k * 2:
                break
        return merged[:top_k]

    def _ar_results(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Query Agent-Reach channels (GitHub, RSS, Exa) and normalize results.

        Returns a list of dicts in the same shape as engine results:
        {title, url, snippet, engine, confidence, ar_channel}.
        Silently returns [] if Agent-Reach is not installed or no channel works.
        """
        try:
            from zahra_agent import AgentReachBridge  # local import to avoid cycle
        except Exception:
            return []
        try:
            bridge = AgentReachBridge()
        except Exception:
            return []
        if not bridge.ready:
            return []

        results: list[dict[str, Any]] = []
        for channel_name in ("github", "rss", "exa_search"):
            try:
                res = bridge.search(channel_name, query, timeout=20)
                if not res.get("ok"):
                    continue
                output = res.get("output", "")
                if not output:
                    continue
                # Parse the structured output (JSON or key|value lines)
                parsed = self._parse_ar_output(output, channel_name)
                results.extend(parsed)
            except Exception:
                logger.debug("Agent-Reach channel %s failed", channel_name, exc_info=True)

        if not results:
            return []
        # Re-rank by relevance
        terms = self._extract_terms(query)
        results.sort(key=lambda r: self._relevance([r], terms), reverse=True)
        return results[:top_k]

    @staticmethod
    def _parse_ar_output(output: str, channel_name: str) -> list[dict[str, Any]]:
        """Parse Agent-Reach channel output into normalized result dicts."""
        results: list[dict[str, Any]] = []
        # Try JSON first
        try:
            data = json.loads(output)
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        results.append({
                            "title": item.get("title", item.get("name", "")),
                            "url": item.get("url", item.get("html_url", "")),
                            "snippet": item.get("description", item.get("body", ""))[:300],
                            "engine": f"agent-reach:{channel_name}",
                            "confidence": 0.85,
                            "ar_channel": channel_name,
                        })
                if results:
                    return results
        except (json.JSONDecodeError, TypeError):
            pass

        # Parse key|value or "Title -> URL" line format
        for line in output.strip().splitlines():
            line = line.strip()
            if not line or line.startswith("##") or line.startswith("#"):
                continue
            # Format: "Title -> URL\nSnippet" or "Title | URL"
            url_match = re.search(r"(https?://[^\s|\n]+)", line)
            title = ""
            url = url_match.group(1) if url_match else ""
            if "->" in line:
                parts = line.split("->", 1)
                title = parts[0].strip()
            elif "|" in line and url:
                parts = line.split("|", 1)
                title = parts[0].strip()
            else:
                title = re.sub(r"\s+", " ", line[:100]).strip()

            if title or url:
                snippet = ""
                # The next non-empty line may be the snippet
                results.append({
                    "title": title,
                    "url": url,
                    "snippet": snippet,
                    "engine": f"agent-reach:{channel_name}",
                    "confidence": 0.7,
                    "ar_channel": channel_name,
                })
        return results

    # -- engines -------------------------------------------------------------

    def _search_google(self, query: str, top_k: int) -> list[dict[str, Any]]:
        url = "https://www.googleapis.com/customsearch/v1"
        params = {"key": self.google_api_key, "cx": self.google_cx,
                  "q": query, "num": min(top_k, 10)}
        resp = self._session.get(url, params=params, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        return [
            {
                "title": item.get("title", ""),
                "url": item.get("link", ""),
                "snippet": item.get("snippet", ""),
                "engine": "google",
            }
            for item in data.get("items", [])[:top_k]
        ]

    def _search_ddg_lite(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """DuckDuckGo Lite (POST) — lightest page, survives bot challenge."""
        resp = self._session.post(
            "https://lite.duckduckgo.com/lite/",
            data={"q": query},
            timeout=15,
        )
        if resp.status_code != 200 or "challenge" in resp.text[:2000].lower():
            return []
        resp.raise_for_status()
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for node in soup.select("a.result-link")[:top_k]:
                title = node.get_text(" ", strip=True)
                url = node.get("href", "")
                if not url.startswith("http"):
                    continue
                # snippet lives in the same <tr> as the link
                tr = node.find_parent("tr")
                sn = tr.select_one(".result-snippet") if tr else None
                snippet = sn.get_text(" ", strip=True) if sn else ""
                results.append(
                    {"title": title, "url": url, "snippet": snippet, "engine": "duckduckgo-lite"}
                )
            return results
        except ImportError:
            return []

    def _search_duckduckgo(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """DuckDuckGo HTML — POST form (survives GET-blocking)."""
        resp = self._session.post(
            "https://html.duckduckgo.com/html/",
            data={"q": query},
            timeout=15,
        )
        if resp.status_code != 200 or "challenge" in resp.text[:2000].lower():
            return []
        return self._parse_ddg(resp.text, top_k)

    def _parse_ddg(self, page: str, top_k: int) -> list[dict[str, Any]]:
        """Extract result__a / result__snippet blocks (BS4 preferred)."""
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(page, "html.parser")
            results = []
            for node in soup.select(".result")[:top_k * 2]:
                a = node.select_one(".result__a")
                if not a:
                    continue
                title = a.get_text(" ", strip=True)
                href = a.get("href", "")
                url = self._decode_ddg_url(href)
                if not url.startswith("http"):
                    continue
                sn = node.select_one(".result__snippet")
                snippet = sn.get_text(" ", strip=True) if sn else ""
                results.append(
                    {"title": title, "url": url, "snippet": snippet, "engine": "duckduckgo"}
                )
                if len(results) >= top_k:
                    break
            if results:
                return results
        except ImportError:
            pass

        links = re.findall(
            r'<a[^>]*class="result__a"[^>]*href="([^"]*)"[^>]*>(.*?)</a>',
            page, re.DOTALL,
        )
        snippets = re.findall(
            r'<a[^>]*class="result__snippet"[^>]*>(.*?)</a>', page, re.DOTALL,
        )
        results = []
        for i, (href, title) in enumerate(links[:top_k]):
            url = self._decode_ddg_url(href)
            if not url.startswith("http"):
                continue
            snippet = ""
            if i < len(snippets):
                snippet = re.sub(r"<[^>]+>", "", snippets[i]).strip()
            results.append(
                {
                    "title": re.sub(r"<[^>]+>", "", title).strip(),
                    "url": url,
                    "snippet": snippet,
                    "engine": "duckduckgo",
                }
            )
        return results

    def _search_bing_rss(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Bing RSS feed — programmatic endpoint, no JS wall, no API key."""
        resp = self._session.get(
            "https://www.bing.com/search",
            params={"q": query, "format": "rss", "count": min(top_k, 20), "mkt": "en-US"},
            timeout=15,
        )
        resp.raise_for_status()
        results = []
        for block in re.findall(r"<item>(.*?)</item>", resp.text, re.DOTALL)[:top_k]:
            title = re.search(r"<title>(.*?)</title>", block, re.DOTALL)
            link = re.search(r"<link>(.*?)</link>", block, re.DOTALL)
            desc = re.search(r"<description>(.*?)</description>", block, re.DOTALL)
            if not title or not link:
                continue
            url = html_module.unescape(link.group(1)).strip()
            if not url.startswith("http"):
                continue
            snippet = re.sub(r"\s+", " ", html_module.unescape(desc.group(1))) if desc else ""
            results.append(
                {
                    "title": html_module.unescape(re.sub(r"\s+", " ", title.group(1))).strip(),
                    "url": url,
                    "snippet": snippet.strip(),
                    "engine": "bing-rss",
                }
            )
        return results

    def _search_bing(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Bing HTML — parse li.b_algo result blocks."""
        url = "https://www.bing.com/search?q=" + quote_plus(query) + "&count=20"
        resp = self._session.get(url, timeout=15)
        resp.raise_for_status()
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for node in soup.select("li.b_algo")[:top_k * 2]:
                a = node.select_one("h2 a")
                if not a:
                    continue
                title = a.get_text(" ", strip=True)
                url = a.get("href", "").strip()
                if not url.startswith("http"):
                    continue
                p = node.select_one("p, .b_caption p")
                snippet = p.get_text(" ", strip=True) if p else ""
                results.append(
                    {"title": title, "url": url, "snippet": snippet, "engine": "bing"}
                )
                if len(results) >= top_k:
                    break
            return results
        except ImportError:
            return []

    def _search_mojeek(self, query: str, top_k: int) -> list[dict[str, Any]]:
        """Mojeek HTML — independent index, no JS."""
        url = "https://www.mojeek.com/search?q=" + quote_plus(query)
        resp = self._session.get(url, timeout=15)
        resp.raise_for_status()
        try:
            from bs4 import BeautifulSoup

            soup = BeautifulSoup(resp.text, "html.parser")
            results = []
            for node in soup.select("ul.results-standard li, .result")[:top_k * 2]:
                a = node.select_one("a.title, h2 a")
                if not a:
                    continue
                title = a.get_text(" ", strip=True)
                url = a.get("href", "").strip()
                if not url.startswith("http"):
                    continue
                sn = node.select_one("p.s, .s")
                snippet = sn.get_text(" ", strip=True) if sn else ""
                results.append(
                    {"title": title, "url": url, "snippet": snippet, "engine": "mojeek"}
                )
                if len(results) >= top_k:
                    break
            return results
        except ImportError:
            return []

    # -- helpers -------------------------------------------------------------

    @staticmethod
    def _decode_ddg_url(url: str) -> str:
        """Decode DuckDuckGo redirect URLs."""
        if "uddg=" in url:
            match = re.search(r"uddg=([^&]+)", url)
            if match:
                return unquote(match.group(1))
        return url

    @staticmethod
    def _dedupe(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen: set[str] = set()
        out: list[dict[str, Any]] = []
        for r in results:
            host = urlparse(r.get("url", "")).netloc
            key = host + "|" + r.get("title", "")[:60]
            if key in seen:
                continue
            seen.add(key)
            out.append(r)
        return out

    # -- content fetching ----------------------------------------------------

    def fetch(self, url: str, max_chars: int = 5000) -> dict[str, Any]:
        """Fetch and extract text content from a URL."""
        try:
            resp = self._session.get(url, timeout=15)
            resp.raise_for_status()
            if resp.encoding is None or resp.encoding.lower() == "iso-8859-1":
                resp.encoding = resp.apparent_encoding
            page = resp.text
            title = ""
            tm = re.search(r"<title[^>]*>(.*?)</title>", page, re.DOTALL | re.IGNORECASE)
            if tm:
                title = re.sub(r"\s+", " ", tm.group(1)).strip()
            try:
                from bs4 import BeautifulSoup

                soup = BeautifulSoup(page, "html.parser")
                for tag in soup(["script", "style", "nav", "footer", "header", "noscript"]):
                    tag.decompose()
                text = soup.get_text(" ", strip=True)
            except ImportError:
                text = re.sub(r"<script[^>]*>.*?</script>", " ", page,
                              flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r"<style[^>]*>.*?</style>", " ", text,
                              flags=re.DOTALL | re.IGNORECASE)
                text = re.sub(r"<[^>]+>", " ", text)
                text = html_module.unescape(text)
            text = re.sub(r"\s+", " ", text).strip()
            return {
                "url": url,
                "title": title,
                "content": text[:max_chars],
                "length": len(text),
                "timestamp": time.time(),
            }
        except Exception as exc:  # noqa: BLE001
            return {"url": url, "error": str(exc), "content": ""}

    def search_and_fetch(self, query: str, top_k: int = 3) -> list[dict[str, Any]]:
        """Search the web and fetch content from top results."""
        results = self.search(query, top_k)
        enriched = []
        for r in results:
            content = self.fetch(r.get("url", ""), max_chars=2000)
            enriched.append({**r, **content})
        return enriched

    # -- CVE / exploit search ------------------------------------------------

    def instant_answer(self, query: str) -> dict[str, Any]:
        """DuckDuckGo Instant Answer API — keyless, gives a clean abstract."""
        try:
            resp = self._session.get(
                "https://api.duckduckgo.com/",
                params={"q": query, "format": "json", "no_html": 1, "skip_disambig": 1},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            abstract = (data.get("AbstractText") or "").strip()
            source = data.get("AbstractSource") or ""
            url = data.get("AbstractURL") or ""
            topics = []
            seen: set[str] = set()
            for t in data.get("RelatedTopics", []) or []:
                if "Topics" in t:
                    t = t.get("Topics", [])
                for item in t if isinstance(t, list) else [t]:
                    if not isinstance(item, dict):
                        continue
                    title = item.get("Text", "")
                    if title and title not in seen:
                        seen.add(title)
                        topics.append({"title": title, "url": item.get("FirstURL", "")})
            return {
                "abstract": abstract,
                "source": source,
                "url": url,
                "topics": topics[:5],
                "timestamp": time.time(),
            }
        except Exception:  # noqa: BLE001
            logger.exception("Instant Answer API failed")
            return {"abstract": "", "source": "", "url": "", "topics": []}

    def search_cve(self, cve_id: str) -> dict[str, Any]:
        """Search for CVE details (instant answer first, then engines)."""
        ia = self.instant_answer(cve_id)
        results = self.search(f"{cve_id} vulnerability details", top_k=3)
        return {
            "cve_id": cve_id,
            "abstract": ia.get("abstract", ""),
            "source": ia.get("source", ""),
            "results": results,
            "timestamp": time.time(),
        }

    def search_exploit(self, software: str, version: str = "") -> dict[str, Any]:
        """Search for known exploits."""
        query = f"{software} {version} exploit CVE".strip()
        results = self.search(query, top_k=5)
        return {
            "software": software,
            "version": version,
            "results": results,
            "timestamp": time.time(),
        }