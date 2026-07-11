from cpgvd.rules import load_rules


def test_load_rules_has_expected_languages():
    rules = load_rules()
    for lang in ("python", "javascript", "java", "go", "php", "ruby", "csharp", "c", "cpp"):
        assert lang in rules, f"missing rules for {lang}"
        assert rules[lang].sinks, f"no sinks defined for {lang}"
        assert rules[lang].sources, f"no sources defined for {lang}"


def test_python_command_injection_sink_matches():
    rules = load_rules()
    py_sinks = rules["python"].sinks
    assert any(r.pattern.search("os.system(cmd)") for r in py_sinks)
    assert any(r.pattern.search("subprocess.run(args)") for r in py_sinks)


def test_python_source_pattern_matches_flask_request():
    rules = load_rules()
    py_sources = rules["python"].sources
    assert any(r.pattern.search("request.args.get('id')") for r in py_sources)


def test_javascript_xss_sink_matches():
    rules = load_rules()
    js_sinks = rules["javascript"].sinks
    assert any(r.pattern.search("el.innerHTML = userInput") for r in js_sinks)


def test_rule_has_category_and_cwe():
    rules = load_rules()
    rule = rules["python"].sinks[0]
    assert rule.category
    assert rule.cwe.startswith("CWE-")
