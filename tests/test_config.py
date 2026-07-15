from cpgvd.config import Config


def test_joern_binary_finds_top_level_layout(tmp_path):
    (tmp_path / "joern-parse").write_text("#!/bin/sh\n")
    config = Config()
    config.joern_home = str(tmp_path)

    assert config.joern_binary("joern-parse") == str(tmp_path / "joern-parse")


def test_joern_binary_finds_nested_joern_cli_layout(tmp_path):
    """Some Joern installer versions unpack into a joern-cli/ subdirectory
    instead of putting binaries at JOERN_HOME's top level -- this must
    still resolve correctly."""
    nested = tmp_path / "joern-cli"
    nested.mkdir()
    (nested / "joern-parse").write_text("#!/bin/sh\n")
    config = Config()
    config.joern_home = str(tmp_path)

    assert config.joern_binary("joern-parse") == str(nested / "joern-parse")


def test_joern_binary_falls_back_to_path_lookup_when_not_found(tmp_path):
    config = Config()
    config.joern_home = str(tmp_path)  # empty dir, binary not present anywhere

    assert config.joern_binary("joern-parse") == "joern-parse"


def test_joern_binary_falls_back_to_path_lookup_when_no_joern_home():
    config = Config()
    config.joern_home = None

    assert config.joern_binary("joern-parse") == "joern-parse"
