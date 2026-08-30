from cpgvd.rules import load_absence_rules, load_rules


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


def test_javascript_sql_sink_matches_real_query_call_not_bare_property_access():
    """Regression test for a real bug found via a live OWASP/NodeGoat run:
    the SQL Injection sink pattern was `\\.query$|\\.execute$|...`, anchored
    on the bare method name. A genuine call's `code` always includes the
    invocation syntax (e.g. "db.query(sql)"), which ends in ")" not
    "query" -- so the anchored pattern could never match a real call. It
    matched instead on Joern's synthesized fieldAccess node for the
    extremely common Express property access `req.query` (whose `code` is
    exactly "req.query", nothing else), mislabeling unrelated code as SQL
    Injection. The fix requires an opening paren after the method name."""
    rules = load_rules()
    sql_sinks = [r for r in rules["javascript"].sinks if r.category == "SQL Injection"]

    assert any(r.pattern.search("db.query(sql)") for r in sql_sinks)
    assert not any(r.pattern.search("req.query") for r in sql_sinks)


def test_python_sql_sink_matches_real_execute_call_not_bare_reference():
    rules = load_rules()
    sql_sinks = [r for r in rules["python"].sinks if r.category == "SQL Injection"]

    assert any(r.pattern.search("cursor.execute(sql)") for r in sql_sinks)
    assert not any(r.pattern.search("obj.execute") for r in sql_sinks)


def test_javascript_nosql_sink_matches_mongo_query_not_array_find():
    """NodeGoat's login bypass (`usersCol.findOne({userName: ..., password:
    ...})`) was missed entirely because no rule shortlisted Mongo query
    calls. The `.find({` form requires an object-literal argument so that
    ubiquitous Array.prototype.find callbacks don't flood the shortlist."""
    rules = load_rules()
    nosql = [r for r in rules["javascript"].sinks if r.category == "NoSQL Injection"]

    assert nosql, "javascript should have a NoSQL Injection sink rule"
    assert any(r.pattern.search("usersCol.findOne({userName: userName, password: password})") for r in nosql)
    assert any(r.pattern.search("collection.find({name: req.query.name})") for r in nosql)
    assert not any(r.pattern.search("items.find(x => x.id === id)") for r in nosql)


def test_javascript_open_redirect_sink_matches():
    rules = load_rules()
    redirect = [r for r in rules["javascript"].sinks if r.category == "Open Redirect"]

    assert redirect, "javascript should have an Open Redirect sink rule"
    assert any(r.pattern.search("res.redirect(req.query.url)") for r in redirect)


# -- control-absence rules -------------------------------------------------


def test_load_absence_rules_has_triggers_and_guards():
    rules = load_absence_rules()
    for lang in ("javascript", "typescript", "python"):
        assert lang in rules, f"missing absence rules for {lang}"
        assert rules[lang].triggers, f"no triggers for {lang}"
        assert rules[lang].guards, f"no guards for {lang}"


def test_absence_trigger_matches_express_route_and_db_write():
    js = load_absence_rules()["javascript"].triggers
    route = [r for r in js if r.operation == "route"]
    assert any(r.pattern.search("app.get('/admin', handler)") for r in route)
    assert any(r.pattern.search("router.post('/users/:id', h)") for r in route)
    assert any(
        r.pattern.search("usersCol.updateOne({_id: id}, {$set: doc})")
        for r in js
        if r.operation == "db_write"
    )


def test_absence_guard_matches_auth_and_ownership_checks():
    js = load_absence_rules()["javascript"].guards
    assert any(
        r.control == "authentication" and r.pattern.search("router.get('/x', requireAuth, h)")
        for r in js
    )
    assert any(
        r.control == "authentication" and r.pattern.search("passport.authenticate('local')")
        for r in js
    )
    assert any(
        r.control == "ownership" and r.pattern.search("if (doc.ownerId !== req.user.id) return")
        for r in js
    )


def test_absence_guard_does_not_match_plain_db_call():
    js = load_absence_rules()["javascript"].guards
    assert not any(r.pattern.search("usersCol.findOne({name: name})") for r in js)


# -- A: additional injection classes -------------------------------------------

def test_new_injection_classes_present():
    rules = load_rules()
    js = {r.category for r in rules["javascript"].sinks}
    py = {r.category for r in rules["python"].sinks}
    assert {"Prototype Pollution", "HTTP Response Splitting", "Regular Expression Denial of Service"} <= js
    assert {"XPath Injection", "LDAP Injection"} <= py


def test_prototype_pollution_matches_deep_merge_call_not_bare_name():
    rules = load_rules()
    pp = [r for r in rules["javascript"].sinks if r.category == "Prototype Pollution"]
    assert any(r.pattern.search("_.merge(target, req.body)") for r in pp)
    assert any(r.pattern.search("Object.assign(cfg, input)") for r in pp)


def test_redos_matches_runtime_regexp_construction():
    rules = load_rules()
    redos = [r for r in rules["javascript"].sinks if "Denial of Service" in r.category]
    assert any(r.pattern.search("const re = new RegExp(userPattern)") for r in redos)
    assert not any(r.pattern.search("/static/literal/.test(x)") for r in redos)


def test_xpath_and_ldap_match_real_calls():
    rules = load_rules()
    assert any(r.pattern.search("root.xpath('//user[name=\"' + n + '\"]')")
               for r in rules["python"].sinks if r.category == "XPath Injection")
    assert any(r.pattern.search("conn.search_s(base, SCOPE, f'(uid={u})')")
               for r in rules["python"].sinks if r.category == "LDAP Injection")


# -- B: hygiene rules --------------------------------------------------------

def test_load_hygiene_rules_covers_languages_and_shapes():
    from cpgvd.rules import load_hygiene_rules

    hy = load_hygiene_rules()
    for lang in ("javascript", "typescript", "python", "java", "go"):
        assert hy.get(lang), f"no hygiene checks for {lang}"
    cats = {r.category for r in hy["javascript"]}
    assert {"Weak Cryptography", "Improper Certificate / TLS Validation", "Hardcoded Credential"} <= cats
    assert all(r.cwe.startswith("CWE-") and r.severity for r in hy["python"])


def test_hygiene_patterns_match_real_misconfig():
    from cpgvd.rules import load_hygiene_rules

    hy = load_hygiene_rules()
    def hit(lang, s):
        return any(r.pattern.search(s) for r in hy[lang])
    assert hit("javascript", "crypto.createHash('md5')")
    assert hit("javascript", "{ rejectUnauthorized: false }")
    assert hit("javascript", "const apiKey = 'sk_live_abcd1234efgh5678'")
    assert hit("python", "requests.get(url, verify=False)")
    assert hit("python", "hashlib.md5(pw.encode())")
    assert hit("go", "tls.Config{InsecureSkipVerify: true}")
    # a normal env-var read must NOT trip the hardcoded-secret pattern
    assert not any(r.pattern.search("apiKey = process.env.API_KEY") for r in hy["javascript"] if r.category == "Hardcoded Credential")
