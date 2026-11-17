"""Private subprocess worker for restricted WASI plugin execution."""

from __future__ import annotations

import base64
import hashlib
import json
import sys
import tempfile
import threading
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

from qshield.plugins.api import PluginExecutionError, PluginLimitError, PluginLimits, PluginManifest

_WASI_MODULE = "wasi_snapshot_preview1"
_MAX_REQUEST_BYTES = 24 * 1024 * 1024


def execute(
    plugin_dir: str,
    input_bytes: bytes,
    limits: PluginLimits,
    expected_manifest: dict[str, Any],
) -> bytes:
    manifest, module_path = PluginManifest.load(plugin_dir)
    if asdict(manifest) != expected_manifest:
        raise PluginExecutionError("plugin manifest changed between validation and worker launch")
    if len(input_bytes) > limits.input_bytes:
        raise PluginLimitError(f"plugin input exceeded {limits.input_bytes} bytes")
    try:
        import wasmtime
    except ImportError as exc:
        raise PluginExecutionError("install plugin support with: pip install 'qshield[plugins]'") from exc

    try:
        config = wasmtime.Config()
        config.consume_fuel = True
        config.epoch_interruption = True
        engine = wasmtime.Engine(config)
        module_bytes = module_path.read_bytes()
        if hashlib.sha256(module_bytes).hexdigest() != manifest.sha256:
            raise PluginExecutionError("plugin module changed during worker validation")  # noqa: TRY301
        module = wasmtime.Module(engine, module_bytes)
    except Exception as exc:
        raise PluginExecutionError(f"could not compile plugin module: {exc}") from exc

    imported_modules = {item.module for item in module.imports}
    if imported_modules - {_WASI_MODULE}:
        names = ", ".join(sorted(imported_modules - {_WASI_MODULE}))
        raise PluginExecutionError(f"plugin imports unsupported host modules: {names}")
    network_imports = [
        item.name or "" for item in module.imports
        if item.module == _WASI_MODULE and (item.name or "").startswith(("sock_", "socket_"))
    ]
    if network_imports:
        raise PluginExecutionError(f"network-capable WASI imports are forbidden: {', '.join(network_imports)}")
    if "_start" not in {item.name for item in module.exports}:
        raise PluginExecutionError("WASI plugin must export _start")

    wasi = wasmtime.WasiConfig()
    wasi.argv = [manifest.plugin_id]
    wasi.env = []
    with tempfile.TemporaryDirectory(prefix="qshield-wasi-") as temp_dir:
        input_path = Path(temp_dir) / "input.json"
        stdout_path = Path(temp_dir) / "stdout.json"
        stderr_path = Path(temp_dir) / "stderr.log"
        input_path.write_bytes(input_bytes)
        wasi.stdin_file = str(input_path)
        # File-backed output avoids invoking Python callbacks from Wasmtime's
        # Tokio worker threads. The isolated worker's file-size limit caps both
        # files while keeping result capture bounded.
        wasi.stdout_file = str(stdout_path)
        wasi.stderr_file = str(stderr_path)
        try:
            try:
                import resource
            except ImportError:  # pragma: no cover - resource is Unix-only
                raise PluginExecutionError(
                    "bounded plugin output is unavailable on this platform"
                ) from None
            output_limit = limits.output_bytes + 1
            resource.setrlimit(resource.RLIMIT_FSIZE, (output_limit, output_limit))
            store = wasmtime.Store(engine)
            store.set_limits(
                memory_size=limits.memory_bytes,
                table_elements=10_000,
                instances=1,
                tables=1,
                memories=1,
            )
            store.set_fuel(limits.fuel)
            store.set_epoch_deadline(1)
            store.set_wasi(wasi)
            linker = wasmtime.Linker(engine)
            linker.define_wasi()
            timer = threading.Timer(limits.timeout_seconds, engine.increment_epoch)
            timer.daemon = True
            timer.start()
            try:
                instance = linker.instantiate(store, module)
                start = cast(Any, instance.exports(store)["_start"])
                start(store)
            finally:
                timer.cancel()
        except Exception as exc:
            message = str(exc)
            lowered = message.lower()
            if "file too large" in lowered or "file too big" in lowered:
                raise PluginLimitError(f"plugin output exceeded {limits.output_bytes} bytes") from exc
            if "fuel" in lowered or "epoch deadline" in lowered or "wasm trap: interrupt" in lowered:
                raise PluginLimitError(f"plugin exceeded its fuel/time limit: {message}") from exc
            if "memory" in lowered or "resource limit" in lowered:
                raise PluginLimitError(f"plugin exceeded its memory/table limit: {message}") from exc
            raise PluginExecutionError(f"plugin execution failed: {message}") from exc
        finally:
            wasi.close()

        stdout = stdout_path.read_bytes() if stdout_path.exists() else b""
        stderr = stderr_path.read_bytes() if stderr_path.exists() else b""
        if len(stdout) > limits.output_bytes or len(stderr) > limits.output_bytes:
            raise PluginLimitError(f"plugin output exceeded {limits.output_bytes} bytes")
        if stderr:
            diagnostic = stderr.decode("utf-8", errors="replace").strip()
            if diagnostic:
                raise PluginExecutionError(f"plugin wrote to stderr: {diagnostic[:2_000]}")
        return stdout


def main() -> int:
    raw = sys.stdin.buffer.read(_MAX_REQUEST_BYTES + 1)
    if len(raw) > _MAX_REQUEST_BYTES:
        print("QSHIELD_PLUGIN_LIMIT: worker request exceeds size limit", file=sys.stderr)
        return 20
    try:
        request: Any = json.loads(raw)
        if not isinstance(request, dict) or set(request) != {"plugin_dir", "expected_manifest", "input_b64", "limits"}:
            raise PluginExecutionError("invalid worker request")  # noqa: TRY301
        if not isinstance(request["plugin_dir"], str) or not isinstance(request["input_b64"], str):
            raise PluginExecutionError("invalid worker request types")  # noqa: TRY301
        if not isinstance(request["limits"], dict) or not isinstance(request["expected_manifest"], dict):
            raise PluginExecutionError("invalid worker manifest or limits")  # noqa: TRY301
        limits = PluginLimits(**request["limits"])
        input_bytes = base64.b64decode(request["input_b64"], validate=True)
        output = execute(request["plugin_dir"], input_bytes, limits, request["expected_manifest"])
    except PluginLimitError as exc:
        print(f"QSHIELD_PLUGIN_LIMIT: {exc}", file=sys.stderr)
        return 20
    except Exception as exc:
        print(f"QSHIELD_PLUGIN_ERROR: {exc}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
