#!/usr/bin/env python3
"""Fetch presentation-only metadata for plugin project pages.

This stage never decides installation trust. It enriches the catalog with public
project information that can make Discover/product pages more useful:
- project title/description/homepage
- GitHub topics/language/license/activity statistics
- a bounded README excerpt
- up to five useful screenshot/preview URLs

GitHub repositories use the authenticated REST API when GITHUB_TOKEN/GH_TOKEN is
available. Other project pages are shallow-fetched once (no recursive crawl),
with redirect/DNS checks that reject private, loopback, link-local and reserved
network destinations.
"""
from __future__ import annotations

import argparse
import base64
import html
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from html.parser import HTMLParser

USER_AGENT = "Dalagab-Omega-Catalog/0.8 (+https://github.com/dalagab/omega)"
GITHUB_API = "https://api.github.com"
MAX_HTML_BYTES = 2 * 1024 * 1024
README_EXCERPT_BYTES = 4096
README_SCAN_BYTES = 128 * 1024
MAX_IMAGES = 5
BLOCKED_PROJECT_HOSTS = {
    "discord.gg", "discord.com", "www.discord.com",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com",
}
IMAGE_EXTENSIONS = (".png", ".jpg", ".jpeg", ".webp", ".gif")


def normalize_repo_url(url: str | None) -> str:
    value = (url or "").strip().rstrip("/")
    return value[:-4] if value.lower().endswith(".git") else value


def parse_github_repo(url: str | None) -> tuple[str, str] | None:
    """Resolve GitHub project links to their repository identity.

    Community manifests frequently publish branch/deep links such as
    ``https://github.com/owner/repo/tree/main``. Those are still repository
    project links, so enrichment must use the GitHub repository API rather
    than scraping the branch page as a generic website.
    """
    value = normalize_repo_url(url)
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return None
    if parsed.scheme.lower() != "https" or (parsed.hostname or "").lower() not in {"github.com", "www.github.com"}:
        return None
    parts = [urllib.parse.unquote(part) for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        return None
    owner, repo = parts[0], parts[1]
    if repo.lower().endswith(".git"):
        repo = repo[:-4]
    valid = re.compile(r"^[A-Za-z0-9._-]+$")
    if not owner or not repo or not valid.fullmatch(owner) or not valid.fullmatch(repo):
        return None
    return owner, repo


def canonical_github_repo_url(owner_repo: tuple[str, str]) -> str:
    return f"https://github.com/{owner_repo[0]}/{owner_repo[1]}"


def looks_like_http_diagnostic(value: str | None) -> bool:
    """Reject transport/debug output from user-facing presentation fields."""
    text = html.unescape(str(value or "")).strip()
    if not text:
        return False
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    lower = text.lower()
    if lower.startswith((
        "404 not found", "404:", "error 404", "http 404",
        "500 internal server error", "500:", "error 500", "http 500",
        "502 bad gateway", "503 service unavailable", "504 gateway timeout",
    )):
        return True
    status_lines = sum(bool(re.match(r"^(?:http\s*)?[45]\d\d(?:\s|:|-|$)", line, re.I)) for line in lines)
    url_lines = sum(bool(re.match(r"^(?:[-*]\s*)?https?://", line, re.I)) for line in lines)
    return status_lines >= 2 or (status_lines >= 1 and url_lines >= 1)


def sanitize_presentation_text(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return None if looks_like_http_diagnostic(text) else text


def _public_addresses(host: str, port: int) -> bool:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            addr = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            return False
        if (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast or
                addr.is_reserved or addr.is_unspecified):
            return False
    return True


def validate_public_https_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("project URL must be public HTTPS")
    host = parsed.hostname.lower().rstrip(".")
    if host in BLOCKED_PROJECT_HOSTS:
        raise ValueError("support/social URL is not used as a project presentation page")
    port = parsed.port or 443
    if not _public_addresses(host, port):
        raise ValueError("project URL resolves to a non-public network address")
    return url


class SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        validate_public_https_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


SAFE_OPENER = urllib.request.build_opener(SafeRedirectHandler())


def http_get_public_html(url: str, timeout: float) -> bytes:
    validate_public_https_url(url)
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.2"})
    with SAFE_OPENER.open(req, timeout=timeout) as resp:
        final_url = resp.geturl()
        validate_public_https_url(final_url)
        length = resp.headers.get("Content-Length")
        if length and int(length) > MAX_HTML_BYTES:
            raise ValueError("project page exceeds the 2 MiB enrichment limit")
        content_type = (resp.headers.get("Content-Type") or "").lower()
        if content_type and "html" not in content_type and "xhtml" not in content_type:
            raise ValueError("project page is not HTML")
        data = resp.read(MAX_HTML_BYTES + 1)
        if len(data) > MAX_HTML_BYTES:
            raise ValueError("project page exceeds the 2 MiB enrichment limit")
        return data


def github_get(path: str, token: str | None, timeout: float, retries: int = 3) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    last_error: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(f"{GITHUB_API}{path}", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            last_error = exc
            if exc.code not in (403, 429) or attempt + 1 >= retries:
                raise
            retry_after = exc.headers.get("Retry-After")
            reset = exc.headers.get("X-RateLimit-Reset")
            delay = min(30.0, float(retry_after or 0) or max(1.0, 2.0 ** attempt))
            if reset and exc.headers.get("X-RateLimit-Remaining") == "0":
                try:
                    delay = min(30.0, max(delay, int(reset) - int(time.time()) + 1))
                except ValueError:
                    pass
            time.sleep(delay)
        except (urllib.error.URLError, TimeoutError) as exc:
            last_error = exc
            if attempt + 1 >= retries:
                raise
            time.sleep(min(8.0, 2.0 ** attempt))
    assert last_error is not None
    raise last_error


class PageMetadataParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.description = ""
        self.images: list[str] = []
        self._inside_title = False
        self._title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "title":
            self._inside_title = True
            return
        if tag.lower() != "meta":
            return
        key = (values.get("property") or values.get("name") or "").lower()
        content = html.unescape(values.get("content") or "").strip()
        if not content:
            return
        if key in {"og:title", "twitter:title"} and not self.title:
            self.title = content
        elif key in {"og:description", "twitter:description", "description"} and not self.description:
            self.description = content
        elif key in {"og:image", "twitter:image", "twitter:image:src"}:
            self.images.append(content)

    def handle_data(self, data: str) -> None:
        if self._inside_title:
            self._title_parts.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._inside_title = False
            if not self.title:
                self.title = " ".join("".join(self._title_parts).split())


def _useful_image(url: str) -> bool:
    lower = url.lower().split("?", 1)[0]
    filename = lower.rsplit("/", 1)[-1]
    if any(token in lower for token in ("shields.io", "badge", "dcbadge", "limes.pink")):
        return False
    if filename in {"icon.png", "icon.jpg", "icon.webp", "logo.png", "logo.jpg", "logo.webp"}:
        return False
    return lower.endswith(IMAGE_EXTENSIONS) or "githubusercontent.com" in lower or "imgur.com" in lower


def extract_readme_images(text: str, owner: str, repo: str, branch: str) -> list[str]:
    candidates = re.findall(r"!\[[^\]]*\]\(([^)\s]+)", text, flags=re.I)
    candidates += re.findall(r"<img[^>]+src=[\"']([^\"']+)", text, flags=re.I)
    base = f"https://raw.githubusercontent.com/{owner}/{repo}/{branch}/"
    result: list[str] = []
    for raw in candidates:
        value = html.unescape(raw.strip().strip("<>\"'"))
        if not value or value.startswith("data:"):
            continue
        url = value if value.startswith(("https://", "http://")) else urllib.parse.urljoin(base, value)
        if url.startswith("http://"):
            url = "https://" + url[7:]
        if url.startswith("https://") and _useful_image(url) and url not in result:
            result.append(url)
        if len(result) >= MAX_IMAGES:
            break
    return result


def scrape_github_repo(owner_repo: tuple[str, str], token: str | None, timeout: float = 20.0) -> dict:
    owner, repo = owner_repo
    base = f"/repos/{owner}/{repo}"
    out = {
        "owner": owner, "repo": repo, "ok": False, "error": None,
        "stars": None, "forks": None, "watchers": None, "title": None,
        "description": None, "homepage": None, "topics": [], "language": None,
        "license": None, "defaultBranch": None, "lastCommit": None,
        "readmeExcerpt": None, "imageUrls": [], "url": f"https://github.com/{owner}/{repo}",
    }
    try:
        meta = github_get(base, token, timeout)
    except urllib.error.HTTPError as exc:
        out["error"] = f"HTTP {exc.code}: {exc.reason or 'GitHub request failed'}"
        return out
    except (urllib.error.URLError, TimeoutError) as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out

    out.update({
        "ok": True,
        "title": meta.get("name") or repo,
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "watchers": meta.get("subscribers_count") if meta.get("subscribers_count") is not None else meta.get("watchers_count"),
        "description": sanitize_presentation_text(meta.get("description")),
        "homepage": meta.get("homepage") or None,
        "topics": meta.get("topics") or [],
        "language": meta.get("language"),
        "license": ((meta.get("license") or {}).get("spdx_id") if isinstance(meta.get("license") or {}, dict) else None),
        "defaultBranch": meta.get("default_branch"),
        "lastCommit": meta.get("pushed_at"),
    })

    try:
        readme_meta = github_get(f"{base}/readme", token, timeout)
        if readme_meta.get("encoding") == "base64" and readme_meta.get("content"):
            raw = base64.b64decode(readme_meta["content"])[:README_SCAN_BYTES]
            readme = raw.decode("utf-8", errors="replace")
            excerpt = readme.encode("utf-8")[:README_EXCERPT_BYTES].decode("utf-8", errors="ignore")
            out["readmeExcerpt"] = excerpt.strip()
            out["imageUrls"] = extract_readme_images(readme, owner, repo, out["defaultBranch"] or "main")
    except Exception:
        pass
    return out


def scrape_generic(url: str, timeout: float = 20.0) -> dict:
    normalized = normalize_repo_url(url)
    out = {"url": normalized, "ok": False, "error": None, "title": None, "description": None, "imageUrls": []}
    try:
        body = http_get_public_html(normalized, timeout).decode("utf-8", errors="replace")
        parser = PageMetadataParser()
        parser.feed(body)
        images = []
        for value in parser.images:
            candidate = urllib.parse.urljoin(normalized, value)
            if candidate.startswith("https://") and _useful_image(candidate) and candidate not in images:
                images.append(candidate)
            if len(images) >= MAX_IMAGES:
                break
        out.update({"ok": True, "title": parser.title or None, "description": sanitize_presentation_text(parser.description), "imageUrls": images})
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def scrape_all(enriched: dict, token: str | None, concurrency: int = 3, timeout: float = 20.0, verbose: bool = True) -> dict:
    def log(message: str) -> None:
        if verbose:
            print(message, file=sys.stderr)

    started = time.time()
    plugins = enriched.get("plugins") or []
    github_repos: dict[tuple[str, str], list[dict]] = {}
    github_aliases: dict[str, tuple[str, str]] = {}
    other_urls: dict[str, list[dict]] = {}
    for plugin in plugins:
        repo_url = normalize_repo_url(plugin.get("repoUrl"))
        if not repo_url:
            continue
        github = parse_github_repo(repo_url)
        if github:
            github_repos.setdefault(github, []).append(plugin)
            github_aliases[repo_url] = github
        else:
            other_urls.setdefault(repo_url, []).append(plugin)

    log(f"  -> {len(github_repos)} unique GitHub repo(s), {len(other_urls)} other project URL(s)")
    github_results: dict[tuple[str, str], dict] = {}
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as executor:
        futures = {executor.submit(scrape_github_repo, repo, token, timeout): repo for repo in github_repos}
        for future in as_completed(futures):
            repo = futures[future]
            try:
                github_results[repo] = future.result()
            except Exception as exc:
                github_results[repo] = {"url": f"https://github.com/{repo[0]}/{repo[1]}", "ok": False, "error": f"{type(exc).__name__}: {exc}"}

    other_results = {url: scrape_generic(url, timeout) for url in other_urls}
    repo_map: dict[str, dict] = {}
    for owner_repo, record in github_results.items():
        canonical = canonical_github_repo_url(owner_repo)
        repo_map[canonical] = dict(record, url=canonical)
    for alias, owner_repo in github_aliases.items():
        record = github_results.get(owner_repo)
        if record is not None:
            repo_map[alias] = dict(record, url=alias, canonicalUrl=canonical_github_repo_url(owner_repo))
    repo_map.update(other_results)

    enriched_plugins: list[dict] = []
    web_enriched_plugins: list[dict] = []
    for plugin in plugins:
        copy = dict(plugin)
        normalized = normalize_repo_url(copy.get("repoUrl"))
        record = repo_map.get(normalized)
        if record:
            copy["website"] = record
            copy["webEnriched"] = bool(record.get("ok"))
        if copy.get("webEnriched"):
            web_enriched_plugins.append(copy)
        enriched_plugins.append(copy)

    elapsed = time.time() - started
    return {
        "metadata": {
            "generatedAt": datetime.now(timezone.utc).isoformat(),
            "elapsedSeconds": round(elapsed, 2),
            "pluginCount": len(plugins),
            "githubReposScraped": len(github_repos),
            "githubReposOk": sum(1 for record in github_results.values() if record.get("ok")),
            "otherUrlsScraped": len(other_urls),
            "webEnrichedPlugins": len(web_enriched_plugins),
        },
        "repos": dict(sorted(repo_map.items(), key=lambda pair: pair[0].lower())),
        "plugins": enriched_plugins,
        "webEnrichedPlugins": web_enriched_plugins,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Shallow-scrape public plugin project metadata")
    parser.add_argument("--input", "-i", default="catalog/enriched-sources.json")
    parser.add_argument("--output", "-o", default="catalog/website-enrichment.json")
    parser.add_argument("--concurrency", "-c", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=20.0)
    parser.add_argument("--quiet", "-q", action="store_true")
    args = parser.parse_args()
    enriched = json.loads(sys.stdin.read()) if args.input == "-" else json.loads(open(args.input, encoding="utf-8-sig").read())
    out = scrape_all(enriched, os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"), args.concurrency, args.timeout, not args.quiet)
    text = json.dumps(out, ensure_ascii=False, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        with open(args.output, "w", encoding="utf-8") as handle:
            handle.write(text)
        meta = out["metadata"]
        print(f"Wrote {args.output}: {meta['githubReposOk']}/{meta['githubReposScraped']} GitHub repositories OK; {meta['webEnrichedPlugins']} plugin variants web-enriched.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
