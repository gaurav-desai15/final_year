import json

from cpgvd.corpus_collect import (
    GitHubClient,
    RepoCandidate,
    _package_auth_libs,
    build_query,
    candidate_from_url,
    find_candidates,
    parse_repo_list,
    read_manifest,
    screen_candidate,
    screen_local,
    write_manifest,
)


def test_build_query_has_all_filters():
    q = build_query(50, "2024-02-01")
    assert "stars:>=50" in q and "pushed:>=2024-02-01" in q
    assert "language:JavaScript" in q and "archived:false" in q


def test_package_auth_libs():
    pkg = json.dumps({"dependencies": {"express": "^4", "passport": "^0.7"}})
    assert _package_auth_libs(pkg) == ["passport"]

    # express but no auth lib -> not a candidate
    assert _package_auth_libs(json.dumps({"dependencies": {"express": "^4"}})) is None
    # no express at all
    assert _package_auth_libs(json.dumps({"dependencies": {"passport": "^0.7"}})) is None
    # devDependencies count
    assert _package_auth_libs(json.dumps({"dependencies": {"express": "1"}, "devDependencies": {"jsonwebtoken": "9"}})) == ["jsonwebtoken"]
    assert _package_auth_libs("not json") is None


class _FakeGH:
    def __init__(self, items, files):
        self._items = items
        self._files = files  # {full_name: package.json text or None}

    def search_repositories(self, query, **kw):
        yield from self._items

    def get_text_file(self, full_name, path, ref=None):
        return self._files.get(full_name)


def _item(full_name, license_key="mit", stars=100):
    return {
        "full_name": full_name,
        "clone_url": f"https://github.com/{full_name}.git",
        "default_branch": "main",
        "stargazers_count": stars,
        "pushed_at": "2024-06-01T00:00:00Z",
        "license": {"key": license_key},
    }


def test_screen_candidate_accepts_express_auth_permissive():
    gh = _FakeGH([], {"a/b": json.dumps({"dependencies": {"express": "4", "express-session": "1"}})})
    cand = screen_candidate(gh, _item("a/b"))
    assert cand and cand.auth_libs == ["express-session"] and cand.stars == 100


def test_screen_candidate_rejects_nonpermissive_license():
    gh = _FakeGH([], {"a/b": json.dumps({"dependencies": {"express": "4", "passport": "1"}})})
    assert screen_candidate(gh, _item("a/b", license_key="gpl-3.0")) is None


def test_screen_candidate_rejects_missing_package_json():
    gh = _FakeGH([], {"a/b": None})
    assert screen_candidate(gh, _item("a/b")) is None


def test_find_candidates_filters_and_limits():
    items = [_item(f"o/r{i}") for i in range(5)]
    files = {
        "o/r0": json.dumps({"dependencies": {"express": "4", "passport": "1"}}),
        "o/r1": json.dumps({"dependencies": {"express": "4"}}),           # no auth lib
        "o/r2": json.dumps({"dependencies": {"express": "4", "jsonwebtoken": "9"}}),
        "o/r3": "garbage",
        "o/r4": json.dumps({"dependencies": {"express": "4", "cookie-session": "2"}}),
    }
    got = find_candidates(_FakeGH(items, files), limit=2)
    assert [c.full_name for c in got] == ["o/r0", "o/r2"]


def test_manifest_roundtrip(tmp_path):
    cands = [
        RepoCandidate("o/r0", "https://x.git", "main", 120, "2024-06-01T00:00:00Z", "mit", ["passport"], "corpus/repos/o__r0", "abc"),
    ]
    p = write_manifest(cands, tmp_path / "m.jsonl")
    back = read_manifest(p)
    assert back[0].full_name == "o/r0" and back[0].auth_libs == ["passport"] and back[0].app == "o__r0"


class _FakeResp:
    def __init__(self, status, payload=None, text="", headers=None):
        self.status_code = status
        self._payload = payload or {}
        self.text = text
        self.headers = headers or {}

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(self.status_code)


class _FakeSession:
    def __init__(self, responses):
        self.headers = {}
        self._responses = list(responses)
        self.calls = []

    def get(self, url, params=None, timeout=None):
        self.calls.append((url, params))
        return self._responses.pop(0)


def test_github_client_paginates_search():
    page1 = _FakeResp(200, {"items": [_item("a/1"), _item("a/2")]})
    page2 = _FakeResp(200, {"items": []})
    gh = GitHubClient(session=_FakeSession([page1, page2]))
    names = [it["full_name"] for it in gh.search_repositories("q", per_page=2, max_results=10)]
    assert names == ["a/1", "a/2"]


def test_github_client_sets_auth_header():
    gh = GitHubClient(token="ghp_x", session=_FakeSession([]))
    assert gh.session.headers["Authorization"] == "Bearer ghp_x"


# -- --from-list path -----------------------------------------------------


def test_parse_repo_list_ignores_comments_and_blanks():
    text = "# header\n\nhttps://github.com/a/b\n  https://github.com/c/d  # inline\n\n"
    assert parse_repo_list(text) == ["https://github.com/a/b", "https://github.com/c/d"]


def test_candidate_from_url():
    c = candidate_from_url("https://github.com/owner/my-repo")
    assert c.full_name == "owner/my-repo"
    assert c.clone_url == "https://github.com/owner/my-repo.git"
    assert c.app == "owner__my-repo"


def test_screen_local_accepts_express_auth_with_permissive_license(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"license": "MIT", "dependencies": {"express": "4", "passport": "0.7"}})
    )
    cand = candidate_from_url("https://github.com/a/b")
    assert screen_local(cand, tmp_path)
    assert cand.auth_libs == ["passport"] and cand.license_key == "mit"


def test_screen_local_rejects_non_express(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"license": "MIT", "dependencies": {"koa": "2"}}))
    assert not screen_local(candidate_from_url("https://github.com/a/b"), tmp_path)


def test_screen_local_reads_license_file_when_package_json_silent(tmp_path):
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"express": "4", "jsonwebtoken": "9"}}))
    (tmp_path / "LICENSE").write_text("MIT License\n\nCopyright (c) 2024 ...")
    cand = candidate_from_url("https://github.com/a/b")
    assert screen_local(cand, tmp_path)
    assert cand.license_key == "mit"
