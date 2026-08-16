"""Config-driven, one-command HTTP gate service.

This module turns the KineGrant reference implementation into a small JSON
service a customer can run without knowing any of the internals:

    pip install kinegrant-protocol
    kinegrant-serve --demo            # starts on http://127.0.0.1:8770

or, with a directory they can edit:

    kinegrant-init --dir ./my-deploy  # writes policy.json + config.json + README
    kinegrant-serve --dir ./my-deploy

The service exposes the three roles of the protocol as HTTP endpoints:

    POST /authorize   policy decision + short-lived signed capability
    POST /verify      fail-closed enforcement point (single-use, replay-safe)
    POST /receipt     executor-signed audit record
    POST /run         the whole loop in one call (for a first test)

Only the Python standard library is used for the HTTP layer, so the only
runtime dependency remains ``cryptography`` (already a package dependency).
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from typing import Any, Mapping
from urllib.parse import urlparse

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from . import __version__
from .adapters.odrl import odrl_to_rules
from .capability import CapabilityIssuer
from .crypto import Ed25519KeyPair
from .gate import ActionGate, InMemoryReplayStore, SQLiteReplayStore
from .models import ActionRequest, parse_time, utc_now
from .policy import PolicyEngine
from .receipt import ReceiptLog, verify_receipt_chain


# --------------------------------------------------------------------------- #
# Defaults
# --------------------------------------------------------------------------- #

DEFAULT_POLICY: dict[str, Any] = {
    "@context": "http://www.w3.org/ns/odrl.jsonld",
    "uid": "urn:kinegrant:policy:delivery-door",
    "assigner": "urn:person:space-owner",
    "permission": [
        {
            "target": "urn:space:demo:door-7",
            "assignee": "urn:robot:delivery-1",
            "action": "open",
            "constraint": [
                {"leftOperand": "purpose", "operator": "eq", "rightOperand": "delivery"},
                {"leftOperand": "risk_tier", "operator": "eq", "rightOperand": 1},
            ],
            "duty": {"action": "emitActionReceipt"},
        }
    ],
    "prohibition": [
        {
            "target": "urn:space:demo:door-7",
            "assignee": "*",
            "action": ["record", "train_on_data"],
        }
    ],
}

DEFAULT_CONFIG: dict[str, Any] = {
    "host": "127.0.0.1",
    "port": 8770,
    "capability_ttl_seconds": 30,
    "trusted_policy_issuers": ["urn:person:space-owner"],
    "keys_dir": "keys",
    "replay_db": "gate-replay.sqlite3",
    "receipt_log": "receipt-log.json",
}

_RESULT_VALUES = {"succeeded", "failed", "aborted"}


# --------------------------------------------------------------------------- #
# Key persistence
# --------------------------------------------------------------------------- #


def _write_private_key(key: Ed25519PrivateKey, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    path.write_bytes(pem)
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def _load_or_create_private_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = Ed25519PrivateKey.generate()
    _write_private_key(key, path)
    return key


def _new_request_id() -> str:
    return "req-" + secrets.token_urlsafe(9)


def _request_from_mapping(value: Mapping[str, Any]) -> ActionRequest:
    try:
        issued_at = parse_time(value["issued_at"]) if value.get("issued_at") else utc_now()
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("request.issued_at is invalid") from exc
    try:
        return ActionRequest(
            request_id=value.get("request_id") or _new_request_id(),
            agent=value["agent"],
            target=value["target"],
            action=value["action"],
            purpose=value["purpose"],
            issued_at=issued_at,
            context=value.get("context", {}),
        )
    except KeyError as exc:
        raise ValueError(f"missing request field: {exc.args[0]}") from exc


# --------------------------------------------------------------------------- #
# Service
# --------------------------------------------------------------------------- #


class GateService:
    """Owns the policy engine, capability issuer, gate, and receipt log."""

    def __init__(
        self,
        *,
        policy: Mapping[str, Any] | None = None,
        policy_path: Path | None = None,
        trusted_policy_issuers: list[str] | tuple[str, ...] | set[str] | None = None,
        issuer_key: Ed25519KeyPair,
        executor_key: Ed25519KeyPair,
        capability_ttl_seconds: int = 30,
        replay_store_path: Path | None = None,
        receipt_log_path: Path | None = None,
    ) -> None:
        self.policy_path = policy_path
        self.trusted_policy_issuers = set(trusted_policy_issuers or ())
        self.issuer_key = issuer_key
        self.executor_key = executor_key
        self.capability_ttl_seconds = capability_ttl_seconds
        self._lock = Lock()
        self._receipt_lock = Lock()
        self._receipt_log_path = receipt_log_path
        self._policy_stat: tuple[int, int] | None = None
        self._engine: PolicyEngine | None = None
        self._policy_doc: Mapping[str, Any] | None = None

        self.capability_issuer = CapabilityIssuer(issuer_key)
        self.gate = ActionGate(
            trusted_issuers={issuer_key.kid},
            replay_store=(
                SQLiteReplayStore(replay_store_path)
                if replay_store_path is not None
                else InMemoryReplayStore()
            ),
        )
        self.receipt_log = ReceiptLog(executor_key)
        if receipt_log_path is not None and receipt_log_path.exists():
            try:
                loaded = json.loads(receipt_log_path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    self.receipt_log.restore(loaded)
            except (json.JSONDecodeError, OSError):
                pass

        self._set_policy(policy or dict(DEFAULT_POLICY))

    def _persist_receipts(self) -> None:
        if self._receipt_log_path is None:
            return
        self._receipt_log_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._receipt_log_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(list(self.receipt_log.entries), ensure_ascii=False),
            encoding="utf-8",
        )
        tmp.replace(self._receipt_log_path)

    # -- policy ------------------------------------------------------------- #

    def _set_policy(self, document: Mapping[str, Any]) -> None:
        rules = odrl_to_rules(document)
        engine = PolicyEngine(
            rules,
            trusted_policy_issuers=self.trusted_policy_issuers,
        )
        with self._lock:
            self._policy_doc = document
            self._engine = engine

    def _current_engine(self) -> PolicyEngine:
        if self.policy_path is not None:
            try:
                stat = self.policy_path.stat()
                signature = (stat.st_mtime_ns, stat.st_size)
            except OSError:
                signature = None
            if signature is not None and signature != self._policy_stat:
                try:
                    document = json.loads(self.policy_path.read_text(encoding="utf-8"))
                except json.JSONDecodeError as exc:
                    raise ValueError(
                        "policy.json 格式错误（JSON 语法问题，请检查是否少了逗号或引号）: "
                        f"{exc}"
                    ) from exc
                self._set_policy(document)
                self._policy_stat = signature
        with self._lock:
            assert self._engine is not None
            return self._engine

    # -- operations --------------------------------------------------------- #

    def authorize(self, request_value: Mapping[str, Any]) -> dict[str, Any]:
        request = _request_from_mapping(request_value)
        decision = self._current_engine().evaluate(request)
        result: dict[str, Any] = {
            "decision": decision.to_dict(),
            "request": request.to_dict(),
            "capability": None,
        }
        if decision.allowed:
            result["capability"] = self.capability_issuer.issue(
                request,
                decision,
                ttl_seconds=self.capability_ttl_seconds,
            )
        return result

    def verify(
        self,
        request_value: Mapping[str, Any],
        capability: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(capability, Mapping):
            raise ValueError("capability must be a JSON object")
        request = _request_from_mapping(request_value)
        claims = self.gate.authorize(capability, request)
        return {"allowed": True, "claims": dict(claims)}

    def receipt(
        self,
        request_value: Mapping[str, Any],
        capability: Mapping[str, Any],
        result: str,
        evidence_hash: str | None,
    ) -> dict[str, Any]:
        if not isinstance(capability, Mapping):
            raise ValueError("capability must be a JSON object")
        if result not in _RESULT_VALUES:
            raise ValueError("result must be one of succeeded, failed, aborted")
        request = _request_from_mapping(request_value)
        # Validate the capability with a throwaway replay store so we reuse all
        # gate checks (fields, issuer, time window, content id) without double
        # consuming the persistent replay token already spent by /verify.
        probe = ActionGate(
            trusted_issuers={self.issuer_key.kid},
            replay_store=InMemoryReplayStore(),
        )
        claims = probe.authorize(capability, request)
        with self._receipt_lock:
            envelope = self.receipt_log.append(
                claims,
                result=result,
                evidence_hash=evidence_hash,
            )
            self._persist_receipts()
        return {
            "receipt": envelope,
            "receipt_chain_valid": verify_receipt_chain(
                self.receipt_log.entries,
                trusted_executors={self.executor_key.kid},
            ),
        }

    def run(self, request_value: Mapping[str, Any]) -> dict[str, Any]:
        request = _request_from_mapping(request_value)
        decision = self._current_engine().evaluate(request)
        output: dict[str, Any] = {
            "request": request.to_dict(),
            "decision": decision.to_dict(),
            "capability": None,
            "claims": None,
            "receipt": None,
            "receipt_chain_valid": None,
        }
        if not decision.allowed:
            return output
        capability = self.capability_issuer.issue(
            request,
            decision,
            ttl_seconds=self.capability_ttl_seconds,
        )
        claims = self.gate.authorize(capability, request)
        with self._receipt_lock:
            receipt = self.receipt_log.append(
                claims,
                result=request_value.get("result") or "succeeded",
                evidence_hash=request_value.get("evidence_hash"),
            )
            self._persist_receipts()
        output.update(
            {
                "capability": capability,
                "claims": dict(claims),
                "receipt": receipt,
                "receipt_chain_valid": verify_receipt_chain(
                    self.receipt_log.entries,
                    trusted_executors={self.executor_key.kid},
                ),
            }
        )
        return output

    def health(self) -> dict[str, Any]:
        engine = self._current_engine()
        return {
            "status": "ok",
            "service": "kinegrant-gate",
            "version": __version__,
            "policy_digest": engine._policy_digest(),
            "issuer_kid": self.issuer_key.kid,
            "executor_kid": self.executor_key.kid,
            "endpoints": {
                "authorize": "POST /authorize",
                "verify": "POST /verify",
                "receipt": "POST /receipt",
                "run": "POST /run",
            },
        }


# --------------------------------------------------------------------------- #
# HTTP layer
# --------------------------------------------------------------------------- #


class _Handler(BaseHTTPRequestHandler):
    server_version = "KineGrantGate/" + __version__
    service: GateService

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: D401
        sys.stderr.write("[kinegrant] " + (fmt % args) + "\n")

    def _send_json(self, status: int, payload: Any) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode(
            "utf-8"
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 2_000_000:
            raise ValueError("empty or oversized request body")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("request body must be valid JSON") from exc
        if not isinstance(value, dict):
            raise ValueError("request body must be a JSON object")
        return value

    def _route(self) -> None:
        path = urlparse(self.path).path
        if self.command == "OPTIONS":
            self.send_response(204)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type")
            self.end_headers()
            return
        if self.command == "GET" and path in ("/", "/health"):
            self._send_json(200, self.service.health())
            return
        if self.command == "POST" and path == "/run":
            self._send_json(200, self.service.run(self._read_json()))
            return
        if self.command == "POST" and path == "/authorize":
            self._send_json(200, self.service.authorize(self._read_json()))
            return
        if self.command == "POST" and path == "/verify":
            body = self._read_json()
            self._send_json(200, self.service.verify(body["request"], body["capability"]))
            return
        if self.command == "POST" and path == "/receipt":
            body = self._read_json()
            self._send_json(
                200,
                self.service.receipt(
                    body["request"],
                    body["capability"],
                    body["result"],
                    body.get("evidence_hash"),
                ),
            )
            return
        self._send_json(404, {"error": "not found", "endpoints": self.service.health()["endpoints"]})

    def _handle(self) -> None:
        try:
            self._route()
        except PermissionError as exc:
            self._send_json(403, {"allowed": False, "reason": str(exc)})
        except (ValueError, KeyError) as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:  # pragma: no cover - last-resort guard
            self._send_json(500, {"error": f"{type(exc).__name__}: {exc}"})

    do_GET = _handle
    do_POST = _handle
    do_OPTIONS = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_PATCH = _handle


# --------------------------------------------------------------------------- #
# Wiring helpers
# --------------------------------------------------------------------------- #


def build_service_from_dir(directory: Path) -> GateService:
    directory = directory.resolve()
    if not directory.exists():
        raise FileNotFoundError(f"deployment directory does not exist: {directory}")
    policy_path = directory / "policy.json"
    config_path = directory / "config.json"
    if not policy_path.exists():
        raise FileNotFoundError(f"missing {policy_path}")

    config: dict[str, Any] = dict(DEFAULT_CONFIG)
    if config_path.exists():
        try:
            loaded = json.loads(config_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"config.json 格式错误（JSON 语法问题）: {exc}") from exc
        if not isinstance(loaded, dict):
            raise ValueError("config.json must be a JSON object")
        config.update(loaded)

    keys_dir = (directory / config["keys_dir"]).resolve()
    issuer_key = Ed25519KeyPair(_load_or_create_private_key(keys_dir / "issuer_key.pem"))
    executor_key = Ed25519KeyPair(
        _load_or_create_private_key(keys_dir / "executor_key.pem")
    )
    replay_db = (directory / config["replay_db"]).resolve()
    receipt_log = (directory / config.get("receipt_log", "receipt-log.json")).resolve()

    try:
        policy_doc = json.loads(policy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            "policy.json 格式错误（JSON 语法问题，请检查是否少了逗号或引号）: "
            f"{exc}"
        ) from exc

    service = GateService(
        policy=policy_doc,
        policy_path=policy_path,
        trusted_policy_issuers=config["trusted_policy_issuers"],
        issuer_key=issuer_key,
        executor_key=executor_key,
        capability_ttl_seconds=int(config["capability_ttl_seconds"]),
        replay_store_path=replay_db,
        receipt_log_path=receipt_log,
    )
    service._host = str(config["host"])
    service._port = int(config["port"])
    return service


def _run_loop(service: GateService, host: str, port: int) -> None:
    handler = type("BoundHandler", (_Handler,), {"service": service})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.daemon_threads = True
    print(f"KineGrant gate listening on http://{host}:{port}", file=sys.stderr)
    print(f"  health:   GET  /health", file=sys.stderr)
    print(f"  demo:     POST /run", file=sys.stderr)
    print(f"  edit:     policy.json is re-read on every request (no restart)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main_serve(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the KineGrant gate service")
    parser.add_argument("--dir", type=Path, help="deployment directory with policy.json/config.json")
    parser.add_argument("--demo", action="store_true", help="run with the built-in demo policy")
    parser.add_argument("--host", type=str, default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    if args.dir:
        try:
            service = build_service_from_dir(args.dir)
        except (FileNotFoundError, ValueError) as exc:
            print(f"启动失败: {exc}", file=sys.stderr)
            return 1
        host = args.host or getattr(service, "_host", "127.0.0.1")
        port = args.port or getattr(service, "_port", 8770)
    else:
        host = args.host or "127.0.0.1"
        port = args.port or 8770
        service = GateService(
            policy=dict(DEFAULT_POLICY),
            trusted_policy_issuers=tuple(DEFAULT_CONFIG["trusted_policy_issuers"]),
            issuer_key=Ed25519KeyPair.generate(),
            executor_key=Ed25519KeyPair.generate(),
            capability_ttl_seconds=30,
            replay_store_path=None,
        )
        if not args.demo:
            print(
                "NOTE: no --dir given, using built-in demo policy with ephemeral keys.",
                file=sys.stderr,
            )
    _run_loop(service, host, port)
    return 0


_README_TEMPLATE = """# KineGrant 一键部署包（保姆级）

你已经拿到了一个能直接运行的 KineGrant 授权服务。下面是“复制粘贴就能跑”的步骤。

## 1. 装 Python（只要一次）

电脑上要有 Python 3.11 或更新版本。检查方法：

    python --version

如果提示找不到 python，去 https://www.python.org/downloads/ 下载安装，
安装时勾选 “Add python.exe to PATH”。

## 2. 安装 KineGrant

    pip install kinegrant-protocol

## 3. 启动服务（一键）

在这个文件夹里打开终端，执行：

    kinegrant-serve --dir .

看到下面这行就说明成功了：

    KineGrant gate listening on http://127.0.0.1:8770

## 4. 验证它活着

新开一个终端窗口，执行：

    curl http://127.0.0.1:8770/health

## 5. 一键跑通完整流程

    curl -X POST http://127.0.0.1:8770/run ^
      -H "Content-Type: application/json" ^
      -d "{\\"agent\\":\\"urn:robot:delivery-1\\",\\"target\\":\\"urn:space:demo:door-7\\",\\"action\\":\\"open\\",\\"purpose\\":\\"delivery\\",\\"context\\":{\\"risk_tier\\":1}}"

（macOS / Linux 把上面的 ^ 换成 \\ 即可。）

返回里 decision.allowed = true 就表示“这个动作被允许了”，并且拿到一张
30 秒有效的签名票据（capability）。

## 6. 改规则（不需要重启）

用记事本打开本目录的 policy.json，改 target / action / assignee / 约束，
保存即可。服务每次请求都会重新读取，保存后下一次请求立刻生效。

想“拒绝某类动作”，就在 policy.json 的 prohibition 里加条目。
想“只允许某台机器、某个目的”，就改 permission 里的 assignee 和 constraint。

## 7. 接入真实机器人（三个接口各司其职）

    POST /authorize   决定能不能做 + 发一张短期票据
    POST /verify      执行器动手前的最后一道闸（一次性，防重放）
    POST /receipt     动作结束后签名留痕（审计）

顺序：authorize → verify（动手）→ receipt（留痕）。

## 8. 安全提醒（认真看）

- 默认只监听本机 127.0.0.1。要让局域网里的机器人访问，把 config.json 的
  host 改成 "0.0.0.0"，并一定加防火墙、只允许可信设备。
- 生产环境不要直接裸奔：前面加 HTTPS 反向代理（如 Caddy/Nginx）。
- keys/ 目录里是服务私钥，不要上传、不要发给别人、不要提交到 git。
"""


def main_init(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Create a ready-to-run KineGrant deployment")
    parser.add_argument("--dir", type=Path, default=Path("kinegrant-deploy"))
    args = parser.parse_args(argv)

    directory = args.dir.resolve()
    directory.mkdir(parents=True, exist_ok=True)

    policy_path = directory / "policy.json"
    config_path = directory / "config.json"
    readme_path = directory / "README.md"
    if not policy_path.exists():
        policy_path.write_text(
            json.dumps(DEFAULT_POLICY, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    if not config_path.exists():
        config_path.write_text(
            json.dumps(DEFAULT_CONFIG, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    readme_path.write_text(_README_TEMPLATE, encoding="utf-8")

    print(f"Created deployment in {directory}")
    print(f"  1) cd {directory}")
    print(f"  2) kinegrant-serve --dir .")
    print(f"  3) curl http://127.0.0.1:8770/health")
    return 0


if __name__ == "__main__":
    raise SystemExit(main_serve())
