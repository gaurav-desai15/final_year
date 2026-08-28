from cpgvd.repo_manager import RepoManager, detect_languages, source_fingerprint


def test_detect_languages_counts_by_extension(tmp_path):
    (tmp_path / "a.py").write_text("print(1)\n")
    (tmp_path / "b.py").write_text("print(2)\n")
    (tmp_path / "c.js").write_text("console.log(1)\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "ignored.js").write_text("skip me\n")

    languages, primary = detect_languages(tmp_path)

    assert primary == "python"
    assert "javascript" in languages
    # node_modules should not have inflated the javascript count above python
    assert languages[0] == "python"


def test_detect_languages_empty_dir_returns_nothing(tmp_path):
    languages, primary = detect_languages(tmp_path)
    assert languages == []
    assert primary == ""


def test_acquire_local_path_non_git(tmp_path):
    (tmp_path / "main.py").write_text("print('hi')\n")
    manager = RepoManager(work_dir=tmp_path / "_work")

    info = manager.acquire(str(tmp_path))

    assert info.path == tmp_path
    assert info.is_temporary is False
    assert info.primary_language == "python"
    # cleanup on a non-temporary (user-owned) path must be a no-op
    manager.cleanup(info)
    assert tmp_path.exists()


def test_is_url_detection_via_acquire_local_fallback(tmp_path):
    manager = RepoManager(work_dir=tmp_path / "_work")
    missing = tmp_path / "does-not-exist"
    try:
        manager.acquire(str(missing))
        raised = False
    except FileNotFoundError:
        raised = True
    assert raised


def _tree(root):
    (root / "src").mkdir()
    (root / "src" / "app.js").write_text("app.get('/admin', requireAuth, h)\n")
    (root / "src" / "util.py").write_text("x = 1\n")
    (root / "README.md").write_text("docs, not source\n")
    nm = root / "node_modules"
    nm.mkdir()
    (nm / "dep.js").write_text("vendored\n")


def test_source_fingerprint_is_stable_and_ignores_non_source(tmp_path):
    _tree(tmp_path)
    fp1 = source_fingerprint(tmp_path)
    # Touching a non-source file and a vendored file must not change the hash.
    (tmp_path / "README.md").write_text("different docs\n")
    (tmp_path / "node_modules" / "dep.js").write_text("different vendored\n")
    assert source_fingerprint(tmp_path) == fp1


def test_source_fingerprint_changes_when_source_content_changes(tmp_path):
    """The mutation-harness case: same file path, one line rewritten in place."""
    _tree(tmp_path)
    fp1 = source_fingerprint(tmp_path)
    (tmp_path / "src" / "app.js").write_text("app.get('/admin', h)\n")  # auth dropped
    assert source_fingerprint(tmp_path) != fp1
