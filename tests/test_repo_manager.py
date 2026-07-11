from cpgvd.repo_manager import RepoManager, detect_languages


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
