import pickle
import threading

from copy import deepcopy
from os import environ

import pytest

from sanic import Sanic
from sanic.config import (
    Config,
    ConfigProvenanceError,
    ConfigSource,
)


@pytest.fixture
def clean_env(monkeypatch):
    for key in list(environ):
        if key.startswith("SANIC_"):
            monkeypatch.delenv(key)
    return monkeypatch


def test_provenance_chain_records_all_sources(clean_env):
    clean_env.setenv("SANIC_REQUEST_TIMEOUT", "45")
    config = Config(defaults={"REQUEST_TIMEOUT": 50})
    config.REQUEST_TIMEOUT = 30

    explanation = config.explain("REQUEST_TIMEOUT")
    sources = [rec.source for rec in explanation.records]
    assert sources == [
        ConfigSource.DEFAULT,
        ConfigSource.FACTORY,
        ConfigSource.ENVIRONMENT,
        ConfigSource.RUNTIME,
    ]
    assert explanation.effective.value == 30
    assert explanation.source is ConfigSource.RUNTIME


def test_explain_reports_origin_and_reason(clean_env):
    clean_env.setenv("SANIC_MOTD", "false")
    config = Config()
    text = str(config.explain("MOTD"))
    assert "env:SANIC_MOTD" in text
    assert "environment" in text
    assert "[active]" in text
    assert config.explain("MOTD").to_dict()["effective"]["source"] == (
        "environment"
    )


def test_explain_unknown_key():
    config = Config()
    explanation = config.explain("NO_SUCH_KEY")
    assert explanation.records == []
    assert explanation.effective is None
    assert "no provenance" in str(explanation)


def test_sensitive_values_show_only_source_and_digest(clean_env):
    clean_env.setenv("SANIC_DB_PASSWORD", "s3cret-value")
    config = Config()

    explanation = config.explain("DB_PASSWORD")
    text = str(explanation)
    assert "s3cret-value" not in text
    assert "sha256:" in text
    assert "env:SANIC_DB_PASSWORD" in text
    assert explanation.to_dict()["effective"]["value"].startswith("***")

    # 摘要稳定且可比较，但不泄露原值
    digest = explanation.effective.digest
    assert digest == config.explain("DB_PASSWORD").effective.digest


def test_sensitive_detection_by_name_and_marking():
    config = Config()
    config.MY_API_TOKEN = "abc"
    config.PLAIN_KEY = "visible"
    config.CUSTOM = "hidden"
    config.mark_sensitive("CUSTOM")

    assert "sha256" in str(config.explain("MY_API_TOKEN"))
    assert "'visible'" in str(config.explain("PLAIN_KEY"))
    assert "hidden" not in str(config.explain("CUSTOM"))

    manifest = config.provenance_manifest()
    assert manifest["keys"]["MY_API_TOKEN"]["sensitive"] is True
    assert manifest["keys"]["PLAIN_KEY"]["sensitive"] is False
    assert manifest["keys"]["CUSTOM"]["sensitive"] is True


def test_factory_load_records_origin(tmp_path):
    config = Config()
    config.update_config({"LOADED": 1})
    assert config.source_of("LOADED") is ConfigSource.FACTORY
    assert config.explain("LOADED").effective.origin == "mapping"

    path = tmp_path / "settings.py"
    path.write_text("FROM_FILE = 2\n")
    config.update_config(str(path))
    assert config.source_of("FROM_FILE") is ConfigSource.FACTORY
    assert "settings.py" in config.explain("FROM_FILE").effective.origin


def test_inheritance_full_and_propagation():
    parent = Config(defaults={"SHARED": "p1"}, label="main")
    child = Config(label="aux")
    child.inherit_from(parent)

    assert child.SHARED == "p1"
    assert child.source_of("SHARED") is ConfigSource.INHERITED
    assert child.explain("SHARED").inherited

    parent.SHARED = "p2"
    assert child.SHARED == "p2"


def test_controlled_sharing_only_allows_listed_keys():
    parent = Config(
        defaults={"ALLOWED": 1, "NOT_ALLOWED": 2}, label="main"
    )
    child = Config(label="aux")
    child.inherit_from(parent, keys=["ALLOWED"])

    assert child.ALLOWED == 1
    assert "NOT_ALLOWED" not in child

    parent.NOT_ALLOWED = 3
    parent.ALLOWED = 4
    assert "NOT_ALLOWED" not in child
    assert child.ALLOWED == 4


def test_share_with_is_controlled():
    parent = Config(defaults={"A": 1, "B": 2}, label="main")
    child = Config(label="aux")
    parent.share_with(child, keys=["B"])
    assert "A" not in child
    assert child.B == 2


def test_app_level_override_wins_and_is_visible():
    parent = Config(defaults={"K": "p1"}, label="main")
    child = Config(label="aux")
    child.inherit_from(parent)

    child.K = "local"
    parent.K = "p2"

    assert child.K == "local"
    explanation = child.explain("K")
    assert explanation.effective.value == "local"
    superseded = [
        rec for rec in explanation.records if not rec.applied
    ]
    assert len(superseded) == 1
    assert superseded[0].value == "p2"
    assert superseded[0].source is ConfigSource.INHERITED


def test_revert_falls_back_to_inherited():
    parent = Config(defaults={"K": "p1"}, label="main")
    child = Config(label="aux")
    child.inherit_from(parent)
    child.K = "local"

    child.revert("K")
    assert child.K == "p1"
    assert child.source_of("K") is ConfigSource.INHERITED


def test_revert_promotes_latest_superseded_inherited_value():
    parent = Config(defaults={"K": "p1"}, label="main")
    child = Config(label="aux")
    child.inherit_from(parent)
    child.K = "local"
    parent.K = "p2"  # 被本地覆盖压制
    parent.K = "p3"  # 也被压制

    child.revert("K")
    assert child.K == "p3"
    assert child.source_of("K") is ConfigSource.INHERITED


def test_local_value_set_before_inherit_wins():
    parent = Config(defaults={"K": "p1"}, label="main")
    child = Config(defaults={"K": "factory"}, label="aux")
    child.inherit_from(parent)
    assert child.K == "factory"

    parent.K = "p2"
    assert child.K == "factory"


def test_inherited_beats_local_default():
    parent = Config(defaults={"REQUEST_TIMEOUT": 5}, label="main")
    child = Config(label="aux")
    child.inherit_from(parent)
    assert child.REQUEST_TIMEOUT == 5


def test_grandchild_inherits_through_child():
    grand = Config(defaults={"K": "g"}, label="grand")
    parent = Config(label="parent")
    child = Config(label="child")
    parent.inherit_from(grand)
    child.inherit_from(parent)
    assert child.K == "g"
    grand.K = "g2"
    assert child.K == "g2"


def test_circular_inheritance_rejected():
    a = Config(label="a")
    b = Config(label="b")
    c = Config(label="c")
    a.inherit_from(b)
    b.inherit_from(c)

    with pytest.raises(ValueError, match="[Cc]ircular"):
        c.inherit_from(a)
    with pytest.raises(ValueError, match="itself"):
        a.inherit_from(a)
    with pytest.raises(TypeError):
        a.inherit_from(object())  # type: ignore


def test_revoke_key_falls_back_to_previous_source(clean_env):
    clean_env.setenv("SANIC_K", "1")
    config = Config(defaults={"K": "factory"})
    config.K = "runtime"

    config.revoke("K")
    assert "K" not in config

    clean_env.delenv("SANIC_K")
    config2 = Config(defaults={"K": "factory"})
    config2.K = "runtime"
    config2.revert("K")
    assert config2.K == "factory"
    assert config2.source_of("K") is ConfigSource.FACTORY


def test_revoke_by_source(clean_env):
    clean_env.setenv("SANIC_A", "1")
    clean_env.setenv("SANIC_B", "2")
    config = Config()
    assert config.A == 1

    affected = config.revoke(source=ConfigSource.ENVIRONMENT)
    assert set(affected) == {"A", "B"}
    assert "A" not in config
    assert "B" not in config


def test_unload_environment_keeps_runtime_values(clean_env):
    clean_env.setenv("SANIC_K", "1")
    config = Config()
    config.K = 99
    config.unload_environment()
    assert config.K == 99
    sources = [
        rec.source
        for rec in config.explain("K").records
        if not rec.revoked
    ]
    assert ConfigSource.ENVIRONMENT not in sources


def test_parent_revocation_propagates_to_children():
    parent = Config(defaults={"K": "v"}, label="main")
    child = Config(label="aux")
    override = Config(label="aux2")
    child.inherit_from(parent)
    override.inherit_from(parent)
    override.K = "local"

    parent.revoke("K")
    assert "K" not in child
    assert override.K == "local"


def test_delete_item_revokes_all_sources():
    config = Config(defaults={"K": 1})
    del config["K"]
    assert "K" not in config
    assert all(
        rec.revoked for rec in config.explain("K").records
    )


def test_concurrent_refresh_and_writes(clean_env):
    clean_env.setenv("SANIC_COUNTER", "1")
    config = Config(defaults={"A": 0, "B": 0, "C": 0})
    errors = []

    def writer(offset):
        try:
            for i in range(200):
                config[f"K{offset}"] = i
                config.A = i
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def refresher():
        try:
            for _ in range(200):
                config.load_environment_vars()
        except Exception as e:  # pragma: no cover
            errors.append(e)

    def revoker():
        try:
            for _ in range(100):
                config.revoke(source=ConfigSource.RUNTIME)
        except Exception as e:  # pragma: no cover
            errors.append(e)

    threads = [
        threading.Thread(target=writer, args=(n,)) for n in range(3)
    ] + [threading.Thread(target=refresher) for _ in range(2)]
    threads += [threading.Thread(target=revoker)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    # 来源链与字典视图必须一致：生效记录的值就是字典里的值
    for key in config.keys():
        effective = config.explain(key).effective
        if effective is not None:
            assert config[key] == effective.value
    sequences = [
        rec.sequence
        for chain in config._provenance.values()
        for rec in chain
    ]
    assert len(sequences) == len(set(sequences))


def test_manifest_and_verify_transfer():
    config = Config(defaults={"NEEDED": "yes"}, label="main")
    config.require("NEEDED")
    manifest = config.provenance_manifest()

    assert config.verify_provenance(manifest) == []

    other = Config(label="copy")
    discrepancies = other.verify_provenance(manifest)
    assert any("NEEDED" in d and "missing" in d for d in discrepancies)
    with pytest.raises(ConfigProvenanceError):
        other.verify_provenance(manifest, strict=True)
    assert other.last_verification


def test_manifest_detects_value_mismatch():
    config = Config(defaults={"K": 1}, label="main")
    manifest = config.provenance_manifest(required=["K"])
    config.K = 2
    discrepancies = config.verify_provenance(manifest)
    assert len(discrepancies) == 1
    assert "mismatch" in discrepancies[0]
    assert "sha256" in discrepancies[0]


def test_manifest_checks_inheritance_topology():
    parent = Config(label="main")
    child = Config(label="aux")
    child.inherit_from(parent, keys=["A"])
    manifest = child.provenance_manifest()

    assert child.verify_provenance(manifest) == []

    orphan = Config(label="aux")
    discrepancies = orphan.verify_provenance(manifest)
    assert any("topology" in d for d in discrepancies)


def test_manifest_excludes_sensitive_values_and_internals():
    config = Config()
    config.DB_SECRET = "hidden"
    manifest = config.provenance_manifest()
    assert "hidden" not in repr(manifest)
    assert "defaults" not in manifest["keys"]
    assert "_init" not in manifest["keys"]


def test_refresh_verifies_transferred_state(app: Sanic):
    app.config.NEEDED = "expected"
    manifest = app.config.provenance_manifest(required=["NEEDED"])

    app.refresh({"config_manifest": manifest})
    assert app.config.last_verification == []

    other = Config(defaults={"NEEDED": "different"})
    bad = other.provenance_manifest(required=["NEEDED"])
    app.refresh({"config_manifest": bad})
    assert app.config.last_verification
    assert not hasattr(app, "config_manifest")


def test_refresh_without_manifest_is_noop(app: Sanic):
    app.refresh({"config": {"ACCESS_LOG": True}})
    assert app.config.ACCESS_LOG is True
    assert app.config.last_verification is None


def test_backward_compatibility_dict_behavior(clean_env):
    clean_env.setenv("SANIC_FROM_ENV", "x")
    config = Config(defaults={"A": 1})
    config["B"] = 2
    config.C = 3
    config.update({"D": 4})

    assert config["A"] == 1
    assert config.B == 2
    assert config.get("C") == 3
    assert config["D"] == 4
    assert config.FROM_ENV == "x"
    assert isinstance(dict(config), dict)
    assert "A" in dict(config)
    assert {*config} >= {"A", "B", "C", "D"}
    assert config.pop("D") == 4

    # 来源链内部状态不泄漏为配置键
    assert "_provenance" not in config
    assert "_parents" not in config
    assert "_children" not in config


def test_pickle_and_deepcopy_preserve_provenance():
    config = Config(defaults={"A": 1}, label="main")
    config.B = "x"
    config.DB_PASSWORD = "pw"

    for restored in (pickle.loads(pickle.dumps(config)), deepcopy(config)):
        assert restored.A == 1
        assert restored.B == "x"
        assert restored.source_of("B") is ConfigSource.RUNTIME
        assert restored.source_of("A") is ConfigSource.FACTORY
        assert "pw" not in str(restored.explain("DB_PASSWORD"))
        # 拷贝不保留子订阅关系
        assert restored._children == []
        # 还原后仍可继续记录
        restored.C = 3
        assert restored.source_of("C") is ConfigSource.RUNTIME


def test_child_does_not_keep_dead_parent_links():
    child = Config(label="aux")
    parent = Config(defaults={"K": 1}, label="main")
    child.inherit_from(parent)
    assert len(parent._children) == 1
