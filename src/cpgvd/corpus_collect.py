"""Collect a corpus of real Node/Express apps to mutate.

GitHub repo search for JavaScript projects that plausibly have working access
control -- `express` plus one of `passport` / `express-session` /
`jsonwebtoken` in `package.json` -- with a permissive licence and recent
activity. Everything is scripted: no browsing, and the same query run twice
gives the same candidate set (modulo new stars).

Needs a token for any real run: unauthenticated GitHub allows ~10 search
requests/min and 60 REST/hr, and filtering ~150 candidates by their
package.json burns through that. Set GITHUB_TOKEN (or GH_TOKEN).
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

import requests

logger = logging.getLogger(__name__)

_API = "https://api.github.com"
_PERMISSIVE_LICENSES = {
    "mit", "apache-2.0", "bsd-2-clause", "bsd-3-clause", "bsd-3-clause-clear",
    "isc", "unlicense", "0bsd", "mpl-2.0", "cc0-1.0",
}
_AUTH_LIBS = ("passport", "express-session", "jsonwebtoken", "express-jwt", "cookie-session")


@dataclass
class RepoCandidate:
    full_name: str
    clone_url: str
    default_branch: str
    stars: int
    pushed_at: str
    license_key: str = ""
    auth_libs: list[str] = field(default_factory=list)
    local_path: str = ""
    commit_sha: str = ""

    @property
    def app(self) -> str:
        return self.full_name.replace("/", "__")


def token_from_env() -> str | None:
    return os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or None


class GitHubClient:
    def __init__(self, token: str | None = None, session: requests.Session | None = None):
        self.session = session or requests.Session()
        self.session.headers.update({"Accept": "application/vnd.github+json"})
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"

    def _get(self, url: str, **params) -> requests.Response:
        for attempt in range(4):
            resp = self.session.get(url, params=params or None, timeout=30)
            if resp.status_code == 403 and "rate limit" in resp.text.lower():
                reset = int(resp.headers.get("X-RateLimit-Reset", "0"))
                wait = max(1, min(90, reset - int(time.time())))
                logger.warning("GitHub rate limited; sleeping %ss", wait)
                time.sleep(wait)
                continue
            return resp
        return resp

    def search_repositories(self, query: str, *, per_page: int = 50, max_results: int = 150) -> Iterator[dict]:
        page = 1
        yielded = 0
        while yielded < max_results:
            resp = self._get(
                f"{_API}/search/repositories",
                q=query, sort="stars", order="desc", per_page=per_page, page=page,
            )
            resp.raise_for_status()
            items = resp.json().get("items", [])
            if not items:
                return
            for it in items:
                yield it
                yielded += 1
                if yielded >= max_results:
                    return
            page += 1

    def get_text_file(self, full_name: str, path: str, ref: str | None = None) -> str | None:
        resp = self._get(f"{_API}/repos/{full_name}/contents/{path}", ref=ref)
        if resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", "replace")
        return data.get("content")


def build_query(min_stars: int, pushed_after: str) -> str:
    return (
        f"express language:JavaScript stars:>={min_stars} "
        f"pushed:>={pushed_after} archived:false is:public"
    )


def _package_auth_libs(package_json_text: str) -> list[str] | None:
    """Return the auth libs found in a package.json's deps, or None if it's not
    an Express app / not parseable."""
    try:
        pkg = json.loads(package_json_text)
    except (json.JSONDecodeError, TypeError):
        return None
    deps = {}
    for key in ("dependencies", "devDependencies", "peerDependencies"):
        deps.update(pkg.get(key) or {})
    if "express" not in deps:
        return None
    found = [lib for lib in _AUTH_LIBS if lib in deps]
    return found or None


def screen_candidate(gh: GitHubClient, item: dict) -> RepoCandidate | None:
    lic = ((item.get("license") or {}).get("key") or "").lower()
    if lic not in _PERMISSIVE_LICENSES:
        return None
    full_name = item["full_name"]
    pkg_text = gh.get_text_file(full_name, "package.json")
    if pkg_text is None:
        return None
    auth_libs = _package_auth_libs(pkg_text)
    if not auth_libs:
        return None
    return RepoCandidate(
        full_name=full_name,
        clone_url=item["clone_url"],
        default_branch=item.get("default_branch", "main"),
        stars=item.get("stargazers_count", 0),
        pushed_at=item.get("pushed_at", ""),
        license_key=lic,
        auth_libs=auth_libs,
    )


def find_candidates(
    gh: GitHubClient,
    *,
    min_stars: int = 50,
    pushed_after: str = "2024-01-01",
    max_search: int = 150,
    limit: int = 40,
) -> list[RepoCandidate]:
    query = build_query(min_stars, pushed_after)
    logger.info("GitHub search: %s", query)
    out: list[RepoCandidate] = []
    for item in gh.search_repositories(query, max_results=max_search):
        cand = screen_candidate(gh, item)
        if cand is not None:
            out.append(cand)
            logger.info("  + %s  (%d stars, %s, %s)", cand.full_name, cand.stars, cand.license_key, ",".join(cand.auth_libs))
        if len(out) >= limit:
            break
    return out


def parse_repo_list(text: str) -> list[str]:
    """One repo URL per line; `#` comments and blank lines ignored."""
    urls = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            urls.append(line)
    return urls


def candidate_from_url(url: str) -> RepoCandidate:
    slug = re.sub(r"\.git$", "", url.rstrip("/"))
    parts = slug.split("/")
    full_name = "/".join(parts[-2:]) if len(parts) >= 2 else parts[-1]
    return RepoCandidate(
        full_name=full_name,
        clone_url=url if url.endswith(".git") else url + ".git",
        default_branch="",
        stars=0,
        pushed_at="",
    )


def screen_local(cand: RepoCandidate, path: Path) -> bool:
    """Screen an already-cloned repo: Express + an auth lib in package.json,
    and a permissive licence (package.json `license` field or a LICENSE file)."""
    pkg_path = path / "package.json"
    if not pkg_path.exists():
        return False
    try:
        pkg_text = pkg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    libs = _package_auth_libs(pkg_text)
    if not libs:
        return False
    cand.auth_libs = libs
    try:
        lic = (json.loads(pkg_text).get("license") or "")
    except (json.JSONDecodeError, AttributeError):
        lic = ""
    lic = (lic if isinstance(lic, str) else lic.get("type", "")).lower().strip()
    if lic not in _PERMISSIVE_LICENSES:
        # fall back to a LICENSE file's first line
        for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "license"):
            f = path / name
            if f.exists():
                head = f.read_text(encoding="utf-8", errors="replace")[:400].lower()
                lic = next((k for k in _PERMISSIVE_LICENSES if k.split("-")[0] in head), lic)
                break
    cand.license_key = lic or "unknown"
    return cand.license_key in _PERMISSIVE_LICENSES or cand.license_key == "unknown"


def clone_candidate(cand: RepoCandidate, dest_dir: Path) -> RepoCandidate:
    import git

    dest = Path(dest_dir) / cand.app
    if dest.exists():
        import shutil

        shutil.rmtree(dest)
    repo = git.Repo.clone_from(cand.clone_url, dest, depth=1)
    cand.local_path = str(dest)
    cand.commit_sha = repo.head.commit.hexsha
    return cand


def write_manifest(cands: list[RepoCandidate], path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for c in cands:
            f.write(json.dumps(c.__dict__) + "\n")
    return path


def read_manifest(path: Path) -> list[RepoCandidate]:
    out = []
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(RepoCandidate(**json.loads(line)))
    return out
