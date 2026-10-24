"""Tests sin red: versiones, CVSS, parsers, cruce CPE local, plantillas y API."""
import json
import os
import tempfile
from pathlib import Path

os.environ["PM_DATA"] = tempfile.mkdtemp(prefix="pm-test-")
os.environ["PM_ADMIN_TOKEN"] = "test-admin"

from hypothesis import given, strategies as st  # noqa: E402

from preventivemeasure import advice, cvss, db, engine, manifests, notify, sources  # noqa: E402
from preventivemeasure.versions import compare, in_range, parse_cpe  # noqa: E402

FIX = Path(__file__).parent / "fixtures" / "demo"
version = st.lists(st.integers(0, 50), min_size=1, max_size=4).map(lambda p: ".".join(map(str, p)))
suffix = st.sampled_from(["", "rc1", "-beta2", "a", "k", "-alpha", ".post1"])
any_version = st.tuples(version, suffix).map("".join)


# --- versiones ---------------------------------------------------------------

def test_compare_known_cases():
    assert compare("1.0", "1.0.0") == 0
    assert compare("1.0rc1", "1.0") < 0
    assert compare("1.0.0-rc1", "1.0") < 0
    assert compare("1.1.1", "1.1.1k") < 0          # sufijos OpenSSL son posteriores
    assert compare("1.1.1j", "1.1.1k") < 0
    assert compare("2.10", "2.9") > 0
    assert compare("v1.2.3", "1.2.3") == 0
    assert compare("1:2.0", "1.9") > 0             # epoch descartado
    assert compare("8.1.2", "8.1.29") < 0


@given(any_version, any_version)
def test_compare_antisymmetric(a, b):
    assert compare(a, b) == -compare(b, a)


@given(any_version)
def test_compare_reflexive(a):
    assert compare(a, a) == 0


@given(any_version, any_version, any_version)
def test_compare_transitive(a, b, c):
    if compare(a, b) <= 0 and compare(b, c) <= 0:
        assert compare(a, c) <= 0


@given(version, version)
def test_in_range_matches_compare(v, end):
    assert in_range(v, "*", None, None, None, end) == (compare(v, end) < 0)


def test_in_range_semantics():
    assert in_range("8.1.2", "*", "8.1.0", None, None, "8.1.29")
    assert not in_range("8.1.29", "*", "8.1.0", None, None, "8.1.29")
    assert in_range("2.4", "2.4")
    assert not in_range("2.4", "*")               # '*' sin rango no se trata como "todas"
    assert not in_range("", "*", None, None, None, "9")


def test_parse_cpe_escapes():
    assert parse_cpe(r"cpe:2.3:a:joomla:joomla\!:3.0:*:*:*:*:*:*:*")["product"] == "joomla!"
    assert parse_cpe("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*")["vendor"] == "f5"


# --- CVSS --------------------------------------------------------------------

def test_cvss_reference_scores():
    assert cvss.score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss.score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss.score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert cvss.score_v3("basura") is None


@given(*[st.sampled_from(v) for v in (["N", "A", "L", "P"], ["L", "H"], ["N", "L", "H"], ["N", "R"], ["U", "C"],
                                       ["H", "L", "N"], ["H", "L", "N"], ["H", "L", "N"])])
def test_cvss_bounds(av, ac, pr, ui, s, c, i, a):
    score = cvss.score_v3(f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}")
    assert 0.0 <= score <= 10.0 and round(score, 1) == score


# --- parsers -----------------------------------------------------------------

def test_scan_demo_project():
    comps, errors = manifests.scan_path(str(FIX))
    got = {(c["ecosystem"], c["name"], c["version"]) for c in comps}
    assert not errors
    assert ("npm", "lodash", "4.17.15") in got
    assert ("npm", "minimist", "1.2.0") in got       # dependencia anidada
    assert ("PyPI", "django", "3.2.0") in got
    assert ("PyPI", "requests", "2.19.0") in got     # extras [security]
    assert not any(n == "flask" for _, n, _ in got)  # rango abierto, sin versión fija
    assert ("Packagist", "laravel/framework", "8.0.0") in got
    assert ("CPE", "php", "8.1.2") in got            # composer platform + Dockerfile


def test_parsers_misc(tmp_path):
    cases = {
        "yarn.lock": ('"@babel/core@^7.0.0", "@babel/core@^7.1.0":\n  version "7.22.5"\n', ("npm", "@babel/core", "7.22.5")),
        "Gemfile.lock": ("GEM\n  specs:\n    rails (7.0.4)\n", ("RubyGems", "rails", "7.0.4")),
        "go.mod": ("module x\n\ngo 1.21.0\n\nrequire (\n\tgithub.com/gin-gonic/gin v1.9.0\n)\n", ("Go", "github.com/gin-gonic/gin", "1.9.0")),
        "Cargo.lock": ('[[package]]\nname = "tokio"\nversion = "1.28.0"\n', ("crates.io", "tokio", "1.28.0")),
        "pubspec.lock": ('packages:\n  http:\n    dependency: direct\n    version: "0.13.5"\n', ("Pub", "http", "0.13.5")),
        "build.gradle": ("implementation 'com.squareup.okhttp3:okhttp:4.9.0'\n", ("Maven", "com.squareup.okhttp3:okhttp", "4.9.0")),
        "pom.xml": ("<project xmlns='http://maven.apache.org/POM/4.0.0'><properties><log4j.version>2.14.1</log4j.version></properties>"
                    "<dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId>"
                    "<version>${log4j.version}</version></dependency></dependencies></project>",
                    ("Maven", "org.apache.logging.log4j:log4j-core", "2.14.1")),
        "app.csproj": ('<PackageReference Include="Newtonsoft.Json" Version="12.0.1" />', ("NuGet", "Newtonsoft.Json", "12.0.1")),
        "bom.json": (json.dumps({"components": [{"purl": "pkg:npm/%40angular/core@15.0.0"}]}), ("npm", "@angular/core", "15.0.0")),
    }
    for name, (text, expected) in cases.items():
        (tmp_path / name).write_text(text, encoding="utf-8")
        got = {(c["ecosystem"], c["name"], c["version"]) for c in manifests.scan_file(tmp_path / name)}
        assert expected in got, (name, got)


def test_purl_os_packages():
    c = manifests.from_purl("pkg:deb/debian/openssl@3.0.11-1?distro=debian-12", "sbom")
    assert (c["ecosystem"], c["name"]) == ("Debian:12", "openssl")


@given(st.text(max_size=400))
def test_parsers_never_crash_on_garbage(text):
    p = Path("x")
    for parse in (manifests.yarn_lock, manifests.requirements, manifests.gemfile_lock, manifests.go_mod,
                  manifests.gradle, manifests.dockerfile, manifests.pubspec_lock, manifests.podfile_lock):
        assert isinstance(parse(p, text), list)


# --- fuentes (parseo de respuestas reales recortadas) ------------------------

def test_parse_nvd_cna_fallback():
    item = {"cve": {"id": "CVE-2026-0001", "vulnStatus": "Awaiting Analysis", "descriptions": [{"lang": "en", "value": "RCE"}],
                    "metrics": {}, "references": [], "affected": [{"source": "cna", "affectedData": [
                        {"vendor": "PHP Group", "product": "PHP", "versions": [
                            {"version": "8.1.0", "status": "affected", "lessThan": "8.1.33", "versionType": "semver"}]}]}]}}
    v = sources.parse_nvd(item)
    assert v["cpes"][0]["product"] == "php" and v["cpes"][0]["end_exc"] == "8.1.33" and v["cpes"][0]["origin"] == "cna"


def test_osv_fixed_prefers_containing_range():
    v = {"affected": [{"package": {"ecosystem": "PyPI", "name": "django"}, "ranges": [{"type": "ECOSYSTEM", "events": [
        {"introduced": "3.2"}, {"fixed": "3.2.13"}, {"introduced": "4.0"}, {"fixed": "4.0.4"}]}]}]}
    assert sources.osv_fixed(v, "PyPI", "django", "3.2.0") == "3.2.13"
    assert sources.osv_fixed(v, "PyPI", "django", "4.0.1") == "4.0.4"
    assert sources.osv_fixed(v, "npm", "django", "3.2.0") is None


# --- motor local (BD real, sin red) ------------------------------------------

def test_cpe_matching_and_resolution():
    db.init()
    with db.conn() as c:
        tid = c.execute("INSERT INTO targets(name, kind, created_at) VALUES('t','manual',0)").lastrowid
    engine.store_components(tid, [manifests.cpe_comp("php", "8.1.2", "test", "php")])
    vuln = sources.parse_nvd({"cve": {"id": "CVE-2026-0002", "vulnStatus": "Analyzed", "descriptions": [{"lang": "en", "value": "x"}],
                                      "metrics": {}, "references": [], "configurations": [{"nodes": [{"cpeMatch": [
                                          {"vulnerable": True, "criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                           "versionStartIncluding": "8.1.0", "versionEndExcluding": "8.1.29"}]}]}]}})
    with db.conn() as c:
        engine.save_vuln(c, vuln)
    comps = engine.active_components([tid])
    engine.match_cpe(comps)
    engine.reprioritize()
    f = db.rows("SELECT * FROM findings")[0]
    assert (f["vuln_id"], f["confidence"], f["fixed_version"], f["status"]) == ("CVE-2026-0002", "confirmed", "8.1.29", "open")
    assert "8.1.29" in json.loads(f["recommendation"])["steps"][0]
    # Actualizar a la versión corregida resuelve el hallazgo
    import time
    start = time.time()
    engine.store_components(tid, [manifests.cpe_comp("php", "8.1.29", "test", "php")])
    evaluated = engine.match_cpe(engine.active_components([tid]))
    engine.resolve_missing(evaluated, start)
    assert db.rows("SELECT status FROM findings WHERE vuln_id='CVE-2026-0002'")[0]["status"] == "resolved"


def test_text_hits_word_boundaries():
    kw = {"php": "php", "nginx": "nginx"}
    assert engine.text_hits("Critical PHP2Shell flaw in PHP 8", kw) == {"php"}
    assert engine.text_hits("phpMyAdmin bug", kw) == set()


# --- prioridad, plantillas -------------------------------------------------

def test_priority_rules():
    assert advice.priority(3.0, True, None, "confirmed") == "critical"
    assert advice.priority(7.5, False, 0.5, "confirmed") == "critical"
    assert advice.priority(9.8, False, None, "possible") == "high"
    assert advice.priority(None, False, None, "confirmed") == "medium"


def test_template_safe_substitute():
    assert notify.render("$vuln_id en $component $missing", {"vuln_id": "CVE-1", "component": "php"}) == "CVE-1 en php $missing"


# --- API ---------------------------------------------------------------------

def test_api_auth_and_secret_masking():
    from fastapi.testclient import TestClient

    from preventivemeasure.api import app

    with TestClient(app) as client:
        engine.STATE["last_run"] = 9e12  # que el scheduler no lance un ciclo con red
        assert client.get("/api/status").status_code == 401
        assert client.get("/api/status", headers={"Authorization": "Bearer nope"}).status_code == 401
        h = {"Authorization": "Bearer test-admin"}
        assert client.get("/api/status", headers=h).status_code == 200
        r = client.put("/api/settings", headers=h, json={"channels": {"telegram": {"bot_token": "123:abc", "chat_id": "1"}}})
        assert r.status_code == 200 and r.json()["channels"]["telegram"]["bot_token"] == "********"
        client.put("/api/settings", headers=h, json={"channels": {"telegram": {"bot_token": "********"}}})
        assert db.channels()["telegram"]["bot_token"] == "123:abc"   # la máscara no sobrescribe
        assert client.put("/api/settings", headers=h, json={"channels": {"evil": {"x": "y"}}}).status_code == 400
        assert client.put("/api/settings", headers=h, json={"interval_minutes": 1}).status_code == 422
        assert client.post("/api/targets", headers=h, json={"name": "x", "kind": "url", "location": "file:///etc/passwd"}).status_code == 400
        r = client.get("/")
        assert "default-src 'self'" in r.headers["content-security-policy"]
        # Cuerpo grande cortado antes de leerlo, aun sin token
        big = client.post("/api/settings/preview", content=b"x" * (2 * 1024 * 1024),
                          headers={"Content-Type": "application/json"})
        assert big.status_code == 413


def test_admin_token_hash_and_migration(monkeypatch):
    from fastapi.testclient import TestClient

    from preventivemeasure.api import app

    monkeypatch.delenv("PM_ADMIN_TOKEN")
    db.set_setting("admin_token", "legacy-plain-token")       # BD de una versión anterior
    with db.conn() as c:
        c.execute("DELETE FROM settings WHERE key='admin_token_sha256'")
    assert db.init() is None                                   # migrado, no se genera uno nuevo
    assert db.get_setting("admin_token_sha256") == db.token_hash("legacy-plain-token")
    assert not db.rows("SELECT 1 FROM settings WHERE key='admin_token'")
    with TestClient(app) as client:
        engine.STATE["last_run"] = 9e12
        assert client.get("/api/status", headers={"Authorization": "Bearer legacy-plain-token"}).status_code == 200
        new = db.rotate_admin_token()
        assert client.get("/api/status", headers={"Authorization": "Bearer legacy-plain-token"}).status_code == 401
        assert client.get("/api/status", headers={"Authorization": f"Bearer {new}"}).status_code == 200


# --- hardening ---------------------------------------------------------------

def test_safe_xml_rejects_internal_dtd_but_not_cdata():
    import pytest

    bomb = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><r>&b;</r>'
    with pytest.raises(ValueError):
        manifests.safe_xml(bomb)
    ok = '<rss><channel><item><title>XXE</title><description><![CDATA[<!ENTITY x SYSTEM "file:///">]]></description></item></channel></rss>'
    assert manifests.safe_xml(ok).tag == "rss"


def test_zip_member_read_is_bounded(tmp_path):
    import zipfile

    apk = tmp_path / "app.apk"
    with zipfile.ZipFile(apk, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("META-INF/androidx.core_core.version", "1.9.0" + "0" * 50_000_000)  # 50 MB comprimidos a KB
    got = manifests.apk_archive(apk)
    assert got and got[0]["name"] == "androidx.core:core" and len(got[0]["version"]) <= 64


def test_check_url_blocks_metadata_and_bad_schemes():
    import pytest

    for url in ("http://169.254.169.254/latest/meta-data/", "ftp://example.com/x", "file:///etc/passwd"):
        with pytest.raises(ValueError):
            sources.check_url(url, allow_private=True)
    with pytest.raises(ValueError):
        sources.check_url("http://127.0.0.1:9/", allow_private=False)
    sources.check_url("http://127.0.0.1:9/", allow_private=True)  # intranet permitida donde procede


def test_env_secrets_never_expose_monitor_tokens(monkeypatch):
    monkeypatch.setenv("PM_AGENT_TOKEN", "x" * 40)
    monkeypatch.setenv("TG_TOKEN", "123:abc")
    assert db.resolve_secret("env:PM_AGENT_TOKEN") == ""
    assert db.resolve_secret("env:TG_TOKEN") == "123:abc"
    assert notify.resolved({"server": "env:TG_TOKEN", "token": "env:TG_TOKEN"}) == {"server": "env:TG_TOKEN", "token": "123:abc"}


def test_partial_scan_does_not_resolve_findings(tmp_path):
    db.init()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text("FROM php:8.1.2\n")
    with db.conn() as c:
        tid = c.execute("INSERT INTO targets(name, kind, location, created_at) VALUES('p','path',?,0)", (str(proj),)).lastrowid
    assert engine.refresh_target(db.rows("SELECT * FROM targets WHERE id=?", (tid,))[0])
    assert len(engine.active_components([tid])) == 1
    (proj / "Dockerfile").unlink()
    (proj / "pom.xml").write_text("<project><dependencies>")  # roto -> inventario parcial
    assert not engine.refresh_target(db.rows("SELECT * FROM targets WHERE id=?", (tid,))[0])
    assert len(engine.active_components([tid])) == 1  # no se retira lo que no se pudo leer


def test_scan_roots(monkeypatch, tmp_path):
    monkeypatch.setenv("PM_SCAN_ROOTS", str(tmp_path / "allowed"))
    assert manifests.path_allowed(str(tmp_path / "allowed" / "app"))
    assert not manifests.path_allowed(str(tmp_path / "other"))
    monkeypatch.delenv("PM_SCAN_ROOTS")
    assert manifests.path_allowed(str(tmp_path / "other"))
