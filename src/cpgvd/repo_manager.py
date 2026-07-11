"""Acquire a repository (GitHub URL or local path) for analysis."""

from __future__ import annotations

import logging
import re
import shutil
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import git

logger = logging.getLogger(__name__)

_EXT_TO_LANGUAGE = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".go": "go",
    ".php": "php",
    ".rb": "ruby",
    ".cs": "csharp",
    ".swift": "swift",
}

# Directories we never want to walk when detecting languages or sizing repos.
_IGNORED_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
}


@dataclass
class RepoInfo:
    path: Path
    source: str  # original URL or path the user passed in
    commit_sha: str
    is_temporary: bool
    languages: list[str]
    primary_language: str


def _is_url(source: str) -> bool:
    return bool(re.match(r"^(https?://|git@|ssh://)", source.strip()))


def detect_languages(root: Path, sample_limit: int = 20000) -> tuple[list[str], str]:
    """Walk the tree and count file extensions to guess languages present.

    Returns (languages sorted by prevalence, primary language).
    """
    counts: Counter[str] = Counter()
    scanned = 0
    for path in root.rglob("*"):
        if scanned >= sample_limit:
            break
        if path.is_dir():
            continue
        if any(part in _IGNORED_DIRS for part in path.parts):
            continue
        lang = _EXT_TO_LANGUAGE.get(path.suffix.lower())
        if lang:
            counts[lang] += 1
            scanned += 1
    if not counts:
        return [], ""
    languages = [lang for lang, _ in counts.most_common()]
    return languages, languages[0]


class RepoManager:
    """Clones (or reuses) a repository and reports basic metadata about it."""

    def __init__(self, work_dir: Path):
        self.work_dir = Path(work_dir)
        self.work_dir.mkdir(parents=True, exist_ok=True)

    def acquire(self, source: str, *, ref: str | None = None, shallow: bool = True) -> RepoInfo:
        if _is_url(source):
            return self._clone(source, ref=ref, shallow=shallow)
        return self._use_local(source)

    def _clone(self, url: str, *, ref: str | None, shallow: bool) -> RepoInfo:
        repo_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", url.rstrip("/").split("/")[-1])
        dest = self.work_dir / f"{repo_name}"
        if dest.exists():
            shutil.rmtree(dest)

        logger.info("Cloning %s -> %s", url, dest)
        clone_kwargs: dict = {}
        if shallow and not ref:
            clone_kwargs["depth"] = 1
        repo = git.Repo.clone_from(url, dest, **clone_kwargs)

        if ref:
            try:
                repo.git.fetch("origin", ref, depth=1)
                repo.git.checkout("FETCH_HEAD")
            except git.GitCommandError:
                repo.git.checkout(ref)

        commit_sha = repo.head.commit.hexsha
        languages, primary = detect_languages(dest)
        return RepoInfo(
            path=dest,
            source=url,
            commit_sha=commit_sha,
            is_temporary=True,
            languages=languages,
            primary_language=primary,
        )

    def _use_local(self, path_str: str) -> RepoInfo:
        path = Path(path_str).expanduser().resolve()
        if not path.exists():
            raise FileNotFoundError(f"Local repo path does not exist: {path}")

        commit_sha = ""
        try:
            repo = git.Repo(path, search_parent_directories=True)
            commit_sha = repo.head.commit.hexsha
        except (git.InvalidGitRepositoryError, ValueError):
            pass

        languages, primary = detect_languages(path)
        return RepoInfo(
            path=path,
            source=str(path),
            commit_sha=commit_sha,
            is_temporary=False,
            languages=languages,
            primary_language=primary,
        )

    def cleanup(self, info: RepoInfo) -> None:
        if info.is_temporary and info.path.exists():
            shutil.rmtree(info.path, ignore_errors=True)
