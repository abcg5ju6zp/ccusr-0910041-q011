from __future__ import annotations

import weakref

from abc import ABC, ABCMeta, abstractmethod
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256
from inspect import getmembers, isclass, isdatadescriptor
from itertools import count
from os import environ
from pathlib import Path
from threading import RLock
from typing import Any, Callable, Literal
from warnings import filterwarnings

from sanic.constants import LocalCertCreator
from sanic.errorpages import DEFAULT_FORMAT, check_error_format
from sanic.helpers import Default, _default
from sanic.http import Http
from sanic.log import error_logger
from sanic.utils import load_module_from_file_location, str_to_bool


FilterWarningType = (
    Literal["default"]
    | Literal["error"]
    | Literal["ignore"]
    | Literal["always"]
    | Literal["module"]
    | Literal["once"]
)

SANIC_PREFIX = "SANIC_"


DEFAULT_CONFIG = {
    "_FALLBACK_ERROR_FORMAT": _default,
    "ACCESS_LOG": False,
    "AUTO_EXTEND": True,
    "AUTO_RELOAD": False,
    "EVENT_AUTOREGISTER": False,
    "DEPRECATION_FILTER": "once",
    "FORWARDED_FOR_HEADER": "X-Forwarded-For",
    "FORWARDED_SECRET": None,  # nosec B105
    "GRACEFUL_SHUTDOWN_TIMEOUT": 15.0,
    "GRACEFUL_TCP_CLOSE_TIMEOUT": 5.0,
    "INSPECTOR": False,
    "INSPECTOR_HOST": "localhost",
    "INSPECTOR_PORT": 6457,
    "INSPECTOR_TLS_KEY": _default,
    "INSPECTOR_TLS_CERT": _default,
    "INSPECTOR_API_KEY": "",
    "KEEP_ALIVE_TIMEOUT": 120,
    "KEEP_ALIVE": True,
    "LOCAL_CERT_CREATOR": LocalCertCreator.AUTO,
    "LOCAL_TLS_KEY": _default,
    "LOCAL_TLS_CERT": _default,
    "LOCALHOST": "localhost",
    "LOG_EXTRA": _default,
    "MOTD": True,
    "MOTD_DISPLAY": {},
    "NO_COLOR": False,
    "NOISY_EXCEPTIONS": False,
    "PROXIES_COUNT": None,
    "REAL_IP_HEADER": None,
    "REQUEST_BUFFER_SIZE": 65536,
    "REQUEST_MAX_HEADER_SIZE": 8192,  # Cannot exceed 16384
    "REQUEST_ID_HEADER": "X-Request-ID",
    "REQUEST_MAX_SIZE": 100_000_000,
    "REQUEST_TIMEOUT": 60,
    "RESPONSE_TIMEOUT": 60,
    "TLS_CERT_PASSWORD": "",  # nosec B105
    "TOUCHUP": _default,
    "USE_UVLOOP": _default,
    "WEBSOCKET_MAX_SIZE": 2**20,  # 1 MiB
    "WEBSOCKET_PING_INTERVAL": 20,
    "WEBSOCKET_PING_TIMEOUT": 20,
}


class ConfigSource(str, Enum):
    """配置值的来源类型。"""

    DEFAULT = "default"
    ENVIRONMENT = "environment"
    FACTORY = "factory"
    RUNTIME = "runtime"
    INHERITED = "inherited"


class ConfigProvenanceError(RuntimeError):
    """进程派生后配置状态校验失败时抛出。"""


# 键名中包含以下片段时视为敏感值，explain/manifest 只展示来源与摘要
SENSITIVE_MARKERS = (
    "SECRET",
    "PASSWORD",
    "TOKEN",
    "API_KEY",
    "PRIVATE",
    "CREDENTIAL",
)

# 所有来源链操作共用一把可重入锁：配置写不是热路径，
# 单锁可以避免父子配置传播时的锁排序问题，保证并发刷新安全。
_PROVENANCE_LOCK = RLock()
_SEQUENCE = count()
_MISSING = object()


@dataclass
class ProvenanceRecord:
    """来源链中的一条记录：某个来源在某时刻为键提供过值。"""

    key: str
    source: ConfigSource
    value: Any
    origin: str
    sequence: int
    sensitive: bool = False
    revoked: bool = False
    applied: bool = True

    @property
    def digest(self) -> str:
        """值内容的稳定摘要（跨进程一致），敏感值只暴露它。"""
        return sha256(repr(self.value).encode()).hexdigest()[:12]

    def display_value(self) -> str:
        if self.sensitive:
            return f"*** (sha256:{self.digest})"
        return repr(self.value)


@dataclass
class ConfigExplanation:
    """单个键的解释：生效值、来源链与裁决原因。"""

    key: str
    records: list[ProvenanceRecord] = field(default_factory=list)
    effective: ProvenanceRecord | None = None
    present: bool = False

    @property
    def source(self) -> ConfigSource | None:
        return self.effective.source if self.effective else None

    @property
    def inherited(self) -> bool:
        return bool(
            self.effective
            and self.effective.source is ConfigSource.INHERITED
        )

    def to_dict(self) -> dict[str, Any]:
        """转为可安全展示的字典，敏感值只含来源与摘要。"""
        return {
            "key": self.key,
            "present": self.present,
            "effective": (
                {
                    "source": self.effective.source.value,
                    "origin": self.effective.origin,
                    "value": self.effective.display_value(),
                }
                if self.effective
                else None
            ),
            "chain": [
                {
                    "sequence": rec.sequence,
                    "source": rec.source.value,
                    "origin": rec.origin,
                    "value": rec.display_value(),
                    "revoked": rec.revoked,
                    "applied": rec.applied,
                }
                for rec in self.records
            ],
        }

    def __str__(self) -> str:
        if not self.records:
            return f"{self.key}: no provenance recorded"
        effective = (
            f"{self.effective.display_value()} "
            f"(source: {self.effective.source.value}, "
            f"origin: {self.effective.origin})"
            if self.effective
            else "<unset>"
        )
        lines = [
            f"{self.key} = {effective}",
            "  chain (oldest -> newest):",
        ]
        for rec in self.records:
            flags = []
            if rec is self.effective:
                flags.append("active")
            if rec.revoked:
                flags.append("revoked")
            if not rec.applied:
                flags.append("superseded by local override")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            lines.append(
                f"    #{rec.sequence} {rec.source.value:<11} "
                f"{rec.origin} value={rec.display_value()}{suffix}"
            )
        return "\n".join(lines)


@dataclass
class _InheritanceLink:
    """子配置记录的一条继承边：从 parent 受控地继承键。"""

    parent: Config
    keys: frozenset[str] | None
    label: str


class DescriptorMeta(ABCMeta):
    """项目内部接口说明。"""

    def __init__(cls, *_):
        cls.__setters__ = {name for name, _ in getmembers(cls, cls._is_setter)}

    @staticmethod
    def _is_setter(member: object):
        return isdatadescriptor(member) and hasattr(member, "setter")


class DetailedConverter(ABC):
    """项目内部接口说明。"""

    @abstractmethod
    def __call__(
        self, full_key: str, config_key: str, value: str, defaults: dict
    ) -> Any:
        """项目内部接口说明。"""


class Config(dict, metaclass=DescriptorMeta):
    """项目内部接口说明。"""

    ACCESS_LOG: bool
    AUTO_EXTEND: bool
    AUTO_RELOAD: bool
    EVENT_AUTOREGISTER: bool
    DEPRECATION_FILTER: FilterWarningType
    FORWARDED_FOR_HEADER: str
    FORWARDED_SECRET: str | None
    GRACEFUL_SHUTDOWN_TIMEOUT: float
    GRACEFUL_TCP_CLOSE_TIMEOUT: float
    INSPECTOR: bool
    INSPECTOR_HOST: str
    INSPECTOR_PORT: int
    INSPECTOR_TLS_KEY: Path | str | Default
    INSPECTOR_TLS_CERT: Path | str | Default
    INSPECTOR_API_KEY: str
    KEEP_ALIVE_TIMEOUT: int
    KEEP_ALIVE: bool
    LOCAL_CERT_CREATOR: str | LocalCertCreator
    LOCAL_TLS_KEY: Path | str | Default
    LOCAL_TLS_CERT: Path | str | Default
    LOCALHOST: str
    LOG_EXTRA: Default | bool
    MOTD: bool
    MOTD_DISPLAY: dict[str, str]
    NO_COLOR: bool
    NOISY_EXCEPTIONS: bool
    PROXIES_COUNT: int | None
    REAL_IP_HEADER: str | None
    REQUEST_BUFFER_SIZE: int
    REQUEST_MAX_HEADER_SIZE: int
    REQUEST_ID_HEADER: str
    REQUEST_MAX_SIZE: int
    REQUEST_TIMEOUT: int
    RESPONSE_TIMEOUT: int
    SERVER_NAME: str
    TLS_CERT_PASSWORD: str
    TOUCHUP: Default | bool
    USE_UVLOOP: Default | bool
    WEBSOCKET_MAX_SIZE: int
    WEBSOCKET_PING_INTERVAL: int
    WEBSOCKET_PING_TIMEOUT: int

    def __init__(
        self,
        defaults: dict[str, str | bool | int | float | None] | None = None,
        env_prefix: str | None = SANIC_PREFIX,
        keep_alive: bool | None = None,
        *,
        converters: Sequence[Callable[[str], Any]] | None = None,
        label: str | None = None,
    ):
        # 来源链相关的内部状态必须走 object.__setattr__，
        # 否则会被 __setattr__ 当作配置键写入字典
        object.__setattr__(self, "_provenance", {})
        object.__setattr__(self, "_pending_source", None)
        object.__setattr__(self, "_recording", False)
        object.__setattr__(self, "_parents", [])
        object.__setattr__(self, "_children", [])
        object.__setattr__(self, "_sensitive_keys", set())
        object.__setattr__(self, "_required_keys", set())
        object.__setattr__(self, "_label", label)
        object.__setattr__(self, "_last_verification", None)

        defaults = defaults or {}
        self.defaults = {**DEFAULT_CONFIG, **defaults}
        super().__init__(self.defaults)
        self._record_many(
            DEFAULT_CONFIG, ConfigSource.DEFAULT, "sanic.DEFAULT_CONFIG"
        )
        if defaults:
            self._record_many(
                defaults, ConfigSource.FACTORY, "constructor defaults"
            )
        object.__setattr__(self, "_recording", True)
        self._configure_warnings()

        self._converters = [str, str_to_bool, float, int]

        if converters:
            for converter in converters:
                self.register_type(converter)

        if keep_alive is not None:
            self._update_with_source(
                {"KEEP_ALIVE": keep_alive},
                ConfigSource.FACTORY,
                "constructor:keep_alive",
            )

        if env_prefix != SANIC_PREFIX:
            if env_prefix:
                self.load_environment_vars(env_prefix)
        else:
            self.load_environment_vars(SANIC_PREFIX)

        self._configure_header_size()
        self._check_error_format()
        self._init = True

    def __getattr__(self, attr: Any):
        try:
            return self[attr]
        except KeyError as ke:
            raise AttributeError(f"Config has no '{ke.args[0]}'")

    def __setattr__(self, attr: str, value: Any) -> None:
        self.update({attr: value})

    def __setitem__(self, attr: str, value: Any) -> None:
        self.update({attr: value})

    def __delitem__(self, attr: str) -> None:
        # 删除等价于撤销该键的全部来源
        with _PROVENANCE_LOCK:
            dict.__delitem__(self, attr)
            for rec in self._provenance.get(attr, ()):
                rec.revoked = True
            self._propagate(attr, _MISSING)

    def update(self, *other: Any, **kwargs: Any) -> None:
        """项目内部接口说明。"""
        kwargs.update({k: v for item in other for k, v in dict(item).items()})
        setters: dict[str, Any] = {
            k: kwargs.pop(k)
            for k in {**kwargs}.keys()
            if k in self.__class__.__setters__
        }

        for key, value in setters.items():
            try:
                super().__setattr__(key, value)
            except AttributeError:
                ...

        super().update(**kwargs)
        applied = {**setters, **kwargs}
        for attr, value in applied.items():
            self._post_set(attr, value)
        self._record_update(applied)

    def _record_update(self, mapping: dict[str, Any]) -> None:
        if not getattr(self, "_recording", False):
            return
        with _PROVENANCE_LOCK:
            pending = self._pending_source
            source, origin = (
                pending if pending else (ConfigSource.RUNTIME, None)
            )
            self._record_many(mapping, source, origin)

    def _update_with_source(
        self,
        mapping: dict[str, Any],
        source: ConfigSource,
        origin: str | None = None,
    ) -> None:
        with _PROVENANCE_LOCK:
            object.__setattr__(self, "_pending_source", (source, origin))
            try:
                self.update(mapping)
            finally:
                object.__setattr__(self, "_pending_source", None)

    def _record_many(
        self,
        mapping: dict[str, Any],
        source: ConfigSource,
        origin: str | None = None,
    ) -> None:
        with _PROVENANCE_LOCK:
            for key, value in mapping.items():
                self._append_record(key, value, source, origin)
            for key, value in mapping.items():
                self._propagate(key, value)

    def _append_record(
        self,
        key: str,
        value: Any,
        source: ConfigSource,
        origin: str | None,
        applied: bool = True,
    ) -> ProvenanceRecord:
        chain = self._provenance.setdefault(key, [])
        record = ProvenanceRecord(
            key=key,
            source=source,
            value=value,
            origin=origin or source.value,
            sequence=next(_SEQUENCE),
            sensitive=self._is_sensitive(key),
            applied=applied,
        )
        chain.append(record)
        return record

    def _propagate(self, key: str, value: Any) -> None:
        """把键的最新状态传播给继承了本配置的子配置。"""
        with _PROVENANCE_LOCK:
            for ref in list(self._children):
                child = ref()
                if child is None:
                    self._children.remove(ref)
                    continue
                if value is _MISSING:
                    child._receive_revocation(key, self)
                else:
                    child._receive_inherited(key, value, self)

    def _post_set(self, attr, value) -> None:
        if self.get("_init"):
            if attr in (
                "REQUEST_MAX_HEADER_SIZE",
                "REQUEST_BUFFER_SIZE",
                "REQUEST_MAX_SIZE",
            ):
                self._configure_header_size()

        if attr == "LOCAL_CERT_CREATOR" and not isinstance(
            self.LOCAL_CERT_CREATOR, LocalCertCreator
        ):
            self.LOCAL_CERT_CREATOR = LocalCertCreator[
                self.LOCAL_CERT_CREATOR.upper()
            ]
        elif attr == "DEPRECATION_FILTER":
            self._configure_warnings()

    @property
    def FALLBACK_ERROR_FORMAT(self) -> str:
        if isinstance(self._FALLBACK_ERROR_FORMAT, Default):
            return DEFAULT_FORMAT
        return self._FALLBACK_ERROR_FORMAT

    @FALLBACK_ERROR_FORMAT.setter
    def FALLBACK_ERROR_FORMAT(self, value):
        self._check_error_format(value)
        if (
            not isinstance(self._FALLBACK_ERROR_FORMAT, Default)
            and value != self._FALLBACK_ERROR_FORMAT
        ):
            error_logger.warning(
                "Setting config.FALLBACK_ERROR_FORMAT on an already "
                "configured value may have unintended consequences."
            )
        self._FALLBACK_ERROR_FORMAT = value

    def _configure_header_size(self):
        Http.set_header_max_size(
            self.REQUEST_MAX_HEADER_SIZE,
            self.REQUEST_BUFFER_SIZE - 4096,
            self.REQUEST_MAX_SIZE,
        )

    def _configure_warnings(self):
        filterwarnings(
            self.DEPRECATION_FILTER,
            category=DeprecationWarning,
            module=r"sanic.*",
        )

    def _check_error_format(self, format: str | None = None):
        check_error_format(format or self.FALLBACK_ERROR_FORMAT)

    def load_environment_vars(self, prefix=SANIC_PREFIX):
        """项目内部接口说明。"""
        with _PROVENANCE_LOCK:
            for key, value in environ.items():
                if not key.startswith(prefix) or not key.isupper():
                    continue

                _, config_key = key.split(prefix, 1)

                for converter in reversed(self._converters):
                    try:
                        if isinstance(converter, DetailedConverter):
                            converted = converter(
                                key, config_key, value, self.defaults
                            )
                        else:
                            converted = converter(value)
                        self._update_with_source(
                            {config_key: converted},
                            ConfigSource.ENVIRONMENT,
                            f"env:{key}",
                        )
                        break
                    except ValueError:
                        pass

    def update_config(self, config: bytes | str | dict[str, Any] | Any):
        """项目内部接口说明。"""
        if isinstance(config, (bytes, str, Path)):
            origin = f"file:{config}"
            config = load_module_from_file_location(location=config)
        elif isinstance(config, dict):
            origin = "mapping"
        elif isclass(config):
            origin = f"class:{config.__name__}"
        else:
            origin = f"object:{config.__class__.__name__}"

        if not isinstance(config, dict):
            cfg = {}
            if not isclass(config):
                cfg.update(
                    {
                        key: getattr(config, key)
                        for key in config.__class__.__dict__.keys()
                    }
                )

            config = dict(config.__dict__)
            config.update(cfg)

        config = dict(filter(lambda i: i[0].isupper(), config.items()))

        self._update_with_source(config, ConfigSource.FACTORY, origin)

    load = update_config

    def register_type(self, converter: Callable[[str], Any]) -> None:
        """项目内部接口说明。"""
        if converter in self._converters:
            error_logger.warning(
                f"Configuration value converter '{converter.__name__}' has "
                "already been registered"
            )
            return
        self._converters.append(converter)

    # -------------------------------------------------------------------- #
    # 来源链（provenance）
    # -------------------------------------------------------------------- #

    def explain(self, key: str) -> ConfigExplanation:
        """按键解释：返回该键的来源链、生效值与裁决原因。

        敏感值只展示来源与摘要，不会泄露原始内容。
        """
        with _PROVENANCE_LOCK:
            return ConfigExplanation(
                key=key,
                records=list(self._provenance.get(key, ())),
                effective=self._effective_record(key),
                present=dict.__contains__(self, key),
            )

    def source_of(self, key: str) -> ConfigSource | None:
        """该键当前生效值的来源。"""
        with _PROVENANCE_LOCK:
            record = self._effective_record(key)
            return record.source if record else None

    def _effective_record(self, key: str) -> ProvenanceRecord | None:
        for rec in reversed(self._provenance.get(key, ())):
            if not rec.revoked and rec.applied:
                return rec
        return None

    # -------------------------------------------------------------------- #
    # 敏感值
    # -------------------------------------------------------------------- #

    def mark_sensitive(self, *keys: str) -> None:
        """显式把键标记为敏感值，explain/manifest 只展示来源与摘要。"""
        with _PROVENANCE_LOCK:
            marked = {key.upper() for key in keys}
            self._sensitive_keys |= marked
            for key, chain in self._provenance.items():
                if key.upper() in marked:
                    for rec in chain:
                        rec.sensitive = True

    def _is_sensitive(self, key: str) -> bool:
        upper = key.upper()
        return upper in self._sensitive_keys or any(
            marker in upper for marker in SENSITIVE_MARKERS
        )

    # -------------------------------------------------------------------- #
    # 继承与受控共享
    # -------------------------------------------------------------------- #

    def inherit_from(
        self,
        parent: Config,
        *,
        keys: Iterable[str] | None = None,
        name: str | None = None,
    ) -> None:
        """从 parent 继承配置。

        keys 为 None 时继承全部键（受控共享时传入允许共享的键集合）。
        本地（环境、工厂、运行期）设置的值优先于继承值，即应用级覆盖。
        继承图不允许成环。
        """
        if not isinstance(parent, Config):
            raise TypeError(
                "Can only inherit from another Config instance, "
                f"not {type(parent)!r}"
            )
        if parent is self:
            raise ValueError("Config cannot inherit from itself")
        key_filter = (
            frozenset(key.upper() for key in keys)
            if keys is not None
            else None
        )
        with _PROVENANCE_LOCK:
            if parent._has_ancestor(self):
                raise ValueError(
                    "Circular config inheritance detected: "
                    f"{self._display_label()} is already an ancestor of "
                    f"{parent._display_label()}"
                )
            # 同一 parent 重复继承时替换旧的继承边
            self._parents[:] = [
                link for link in self._parents if link.parent is not parent
            ]
            link = _InheritanceLink(
                parent=parent,
                keys=key_filter,
                label=name or parent._display_label(),
            )
            self._parents.append(link)
            parent._children.append(weakref.ref(self))
            for key, value in parent.items():
                if not self._is_shareable_key(key):
                    continue
                if key_filter is not None and key not in key_filter:
                    continue
                self._receive_inherited(key, value, parent)

    def share_with(
        self, child: Config, keys: Iterable[str], name: str | None = None
    ) -> None:
        """受控共享：只把指定的键共享给 child。"""
        child.inherit_from(self, keys=keys, name=name)

    @staticmethod
    def _is_shareable_key(key: str) -> bool:
        return not key.startswith("_") and key != "defaults"

    def _display_label(self) -> str:
        return self._label or "unnamed"

    def _link_to(self, parent: Config) -> _InheritanceLink | None:
        for link in self._parents:
            if link.parent is parent:
                return link
        return None

    def _has_ancestor(self, target: Config) -> bool:
        seen: set[int] = set()
        stack = [link.parent for link in self._parents]
        while stack:
            node = stack.pop()
            if node is target:
                return True
            if id(node) in seen:
                continue
            seen.add(id(node))
            stack.extend(link.parent for link in node._parents)
        return False

    def _receive_inherited(
        self, key: str, value: Any, parent: Config
    ) -> None:
        with _PROVENANCE_LOCK:
            link = self._link_to(parent)
            if link is None:
                return
            if link.keys is not None and key not in link.keys:
                return
            current = self._effective_record(key)
            # 本地已主动设置的值（环境/工厂/运行期）优先，继承值被压制
            applied = current is None or current.source in (
                ConfigSource.DEFAULT,
                ConfigSource.INHERITED,
            )
            self._append_record(
                key,
                value,
                ConfigSource.INHERITED,
                f"app:{link.label}",
                applied=applied,
            )
            if applied:
                dict.__setitem__(self, key, value)
                self._post_set(key, value)
                self._propagate(key, value)

    def _receive_revocation(self, key: str, parent: Config) -> None:
        with _PROVENANCE_LOCK:
            link = self._link_to(parent)
            if link is None:
                return
            if link.keys is not None and key not in link.keys:
                return
            origin = f"app:{link.label}"
            changed = False
            for rec in self._provenance.get(key, ()):
                if (
                    rec.source is ConfigSource.INHERITED
                    and rec.origin == origin
                    and not rec.revoked
                ):
                    rec.revoked = True
                    changed = True
            if changed:
                self._reresolve(key)

    # -------------------------------------------------------------------- #
    # 来源撤销
    # -------------------------------------------------------------------- #

    def revoke(
        self,
        key: str | None = None,
        *,
        source: ConfigSource | str | None = None,
    ) -> list[str]:
        """撤销来源：指定键的全部记录，或所有键中来自指定来源的记录。

        撤销后值回退到来源链中上一个仍有效的来源；链为空时键被移除。
        返回受影响的键。
        """
        if isinstance(source, str):
            source = ConfigSource(source)
        with _PROVENANCE_LOCK:
            if key is not None:
                items = [(key, self._provenance.get(key, []))]
            else:
                items = list(self._provenance.items())
            affected = []
            for item_key, chain in items:
                changed = False
                for rec in chain:
                    if rec.revoked:
                        continue
                    if source is not None and rec.source is not source:
                        continue
                    rec.revoked = True
                    changed = True
                if changed:
                    self._reresolve(item_key)
                    affected.append(item_key)
            return affected

    def revert(self, key: str) -> None:
        """撤销某键的运行期覆盖，回退到工厂、环境、继承或默认值。"""
        with _PROVENANCE_LOCK:
            chain = self._provenance.get(key, [])
            changed = False
            for rec in chain:
                if rec.revoked or rec.source is not ConfigSource.RUNTIME:
                    continue
                rec.revoked = True
                changed = True
            if changed:
                self._reresolve(key)

    def unload_environment(self, prefix: str | None = None) -> list[str]:
        """撤销来自环境变量的值（可按前缀过滤），实现来源撤销。"""
        with _PROVENANCE_LOCK:
            affected = []
            for key, chain in list(self._provenance.items()):
                changed = False
                for rec in chain:
                    if rec.revoked or rec.source is not ConfigSource.ENVIRONMENT:
                        continue
                    if prefix is not None and not rec.origin.startswith(
                        f"env:{prefix}"
                    ):
                        continue
                    rec.revoked = True
                    changed = True
                if changed:
                    self._reresolve(key)
                    affected.append(key)
            return affected

    def _reresolve(self, key: str) -> None:
        with _PROVENANCE_LOCK:
            chain = self._provenance.get(key, [])
            record = self._effective_record(key)
            if record is None or record.source in (
                ConfigSource.DEFAULT,
                ConfigSource.INHERITED,
            ):
                # 本地覆盖被撤销后，此前被压制的更新继承值重新生效
                floor = record.sequence if record else -1
                for rec in reversed(chain):
                    if (
                        not rec.revoked
                        and not rec.applied
                        and rec.source is ConfigSource.INHERITED
                        and rec.sequence > floor
                    ):
                        rec.applied = True
                        record = rec
                        break
            had = dict.__contains__(self, key)
            if record is None:
                if had:
                    dict.__delitem__(self, key)
                    self._propagate(key, _MISSING)
                return
            if not had or dict.__getitem__(self, key) != record.value:
                dict.__setitem__(self, key, record.value)
                self._post_set(key, record.value)
                self._propagate(key, record.value)

    # -------------------------------------------------------------------- #
    # 进程派生后的状态校验
    # -------------------------------------------------------------------- #

    def require(self, *keys: str) -> None:
        """把键标记为必要状态，派生后校验会核对这些键是否完整传递。"""
        self._required_keys.update(keys)

    def provenance_manifest(
        self, *, required: Iterable[str] | None = None
    ) -> dict[str, Any]:
        """生成可跨进程传递的校验清单，只含摘要与来源，不含敏感值。"""
        with _PROVENANCE_LOCK:
            keys: dict[str, Any] = {}
            for key in dict.keys(self):
                if not self._is_shareable_key(key):
                    continue
                rec = self._effective_record(key)
                if rec is None:
                    continue
                keys[key] = {
                    "source": rec.source.value,
                    "digest": rec.digest,
                    "sensitive": rec.sensitive,
                }
            return {
                "label": self._display_label(),
                "keys": keys,
                "required": sorted(
                    self._required_keys | set(required or ())
                ),
                "inheritance": [
                    {
                        "parent": link.label,
                        "keys": (
                            sorted(link.keys)
                            if link.keys is not None
                            else None
                        ),
                    }
                    for link in self._parents
                ],
            }

    def verify_provenance(
        self, manifest: dict[str, Any], *, strict: bool = False
    ) -> list[str]:
        """派生后校验：对照清单检查必要状态是否完整传递。

        返回差异描述列表（不含敏感值）；strict 时抛出
        ConfigProvenanceError。
        """
        with _PROVENANCE_LOCK:
            discrepancies: list[str] = []
            remote_keys = manifest.get("keys", {})
            for key in manifest.get("required", ()):
                expected = remote_keys.get(key)
                record = self._effective_record(key)
                if expected is None:
                    discrepancies.append(
                        f"{key}: required key absent from source manifest"
                    )
                elif record is None:
                    discrepancies.append(
                        f"{key}: missing after process transfer "
                        f"(expected source={expected['source']})"
                    )
                elif record.digest != expected["digest"]:
                    discrepancies.append(
                        f"{key}: value mismatch after process transfer "
                        f"(local source={record.source.value} "
                        f"sha256:{record.digest}, expected "
                        f"source={expected['source']} "
                        f"sha256:{expected['digest']})"
                    )
            local_links = sorted(
                (link.label, tuple(sorted(link.keys)) if link.keys else None)
                for link in self._parents
            )
            remote_links = sorted(
                (
                    item["parent"],
                    tuple(item["keys"]) if item["keys"] else None,
                )
                for item in manifest.get("inheritance", [])
            )
            if local_links != remote_links:
                discrepancies.append(
                    "inheritance topology differs after process transfer: "
                    f"local={local_links} expected={remote_links}"
                )
            object.__setattr__(self, "_last_verification", discrepancies)
            if strict and discrepancies:
                raise ConfigProvenanceError(
                    "Config state was not fully transferred: "
                    + "; ".join(discrepancies)
                )
            return discrepancies

    @property
    def last_verification(self) -> list[str] | None:
        """最近一次派生校验的结果，未校验过为 None。"""
        return self._last_verification

    # -------------------------------------------------------------------- #
    # 序列化：来源链可随配置跨进程传递，子订阅关系不随拷贝传播
    # -------------------------------------------------------------------- #

    def __reduce__(self):
        return (
            self.__class__._reconstruct,
            (dict(self), self.__getstate__()),
        )

    def __getstate__(self) -> dict[str, Any]:
        state = self.__dict__.copy()
        state["_children"] = []
        state["_pending_source"] = None
        return state

    def __setstate__(self, state: dict[str, Any]) -> None:
        self.__dict__.update(state)

    @classmethod
    def _reconstruct(
        cls, items: dict[str, Any], state: dict[str, Any]
    ) -> Config:
        obj = cls.__new__(cls)
        object.__setattr__(obj, "_recording", False)
        dict.update(obj, items)
        obj.__setstate__(state)
        object.__setattr__(obj, "_recording", True)
        return obj
