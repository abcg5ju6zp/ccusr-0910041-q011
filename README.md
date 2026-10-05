# Sanic 服务框架

本项目提供异步 HTTP 服务、路由、蓝图、中间件、信号和工作进程管理能力。生产源码位于 `sanic/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install -e . pytest sanic-testing pytest-asyncio`

## 测试

`python3 -m pytest -q tests/test_blueprints.py tests/test_blueprint_group.py`

## 构建

`python3 -m compileall -q sanic`

## 使用

应用通过 `Sanic` 创建服务，通过蓝图组合路由，并可使用测试客户端完成本地 HTTP 验收。

## 配置来源链与继承

`Config` 在保持字典行为不变的前提下记录每个键的来源链（默认值、环境变量、工厂参数、运行期覆盖、应用间继承），用于解释同一进程中主应用与辅助应用配置不一致的原因：

- `config.explain(key)`：按键输出来源链、生效值与裁决原因；敏感值（键名含 `SECRET`/`PASSWORD`/`TOKEN`/`API_KEY` 等，或用 `mark_sensitive` 标记）只显示来源与 sha256 摘要。
- `child.inherit_from(parent, keys=[...])` / `parent.share_with(child, keys=[...])`：应用间受控共享；本地设置优先于继承值（应用级覆盖），`revert(key)` 可回退到继承值；循环继承会被拒绝。
- `config.revoke(...)` / `unload_environment()`：来源撤销，值回退到来源链中上一个有效来源，并沿继承边传播。
- `config.require(*keys)` + `provenance_manifest()` / `verify_provenance(...)`：进程派生后校验必要状态是否完整传递（多进程启动时由 `refresh()` 自动执行，差异记录到 `config.last_verification`）。

