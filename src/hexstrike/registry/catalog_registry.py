"""
Runtime CapabilityRegistry managing built-in and custom adapters with SQLite-persisted
enable/disable/quarantine state across restarts and separate processes.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from hexstrike.adapters.catalog import (
    BinaryIdentity,
    CustomAdapterManifest,
    DeclarativeCustomAdapter,
    ToolAdapter,
    build_default_adapters,
    inspect_binary_identity,
    resolve_binary_path,
)
from hexstrike.adapters.dns import DnsEnumAdapter
from hexstrike.adapters.execution import ExecutionSessionAdapter, HostExecutionAdapter
from hexstrike.adapters.research import ResearchAdapter
from hexstrike.adapters.verification import VerificationAdapter, read_receipt, verification_identity
from hexstrike.adapters.offline import build_offline_adapters
from hexstrike.adapters.management import WorkspaceAdapter, ToolInventoryAdapter, CustomToolAdapter, EvidenceComparisonAdapter
from hexstrike.browser.inspector import BrowserInspectionAdapter
from hexstrike.browser.sessions import BrowserSessionAdapter
from hexstrike.domain.models import ToolStatus
from hexstrike.evidence.store import StateStore
from hexstrike.execution.runner import SafeSubprocessRunner
from hexstrike.workflows.engine import ThreatIntelAdapter, WstgWorkflowAdapter


class CapabilityRegistry:
    """
    Central registry of verified tool adapters and custom manifests.
    Persists enable/disable/quarantine state in `StateStore` so administrative
    changes survive restarts and propagate across concurrent processes.
    """

    def __init__(
        self,
        search_paths: Optional[Sequence[str]] = None,
        custom_manifests_dir: Optional[str | Path] = None,
        store: Optional[StateStore] = None,
        workspace=None,
    ) -> None:
        self.search_paths = list(search_paths) if search_paths else None
        self.custom_manifests_dir = Path(custom_manifests_dir) if custom_manifests_dir else None
        self.store = store
        self.workspace = workspace
        self._adapters: Dict[str, ToolAdapter] = {}
        self._disabled_ids: set[str] = set()
        self._quarantined_ids: set[str] = set()
        self._binary_cache: Dict[str, BinaryIdentity] = {}
        self._binary_signatures: Dict[str, Any] = {}
        self._manifest_signatures: Dict[str, Any] = {}
        self._manifest_lock = threading.RLock()
        self._register_defaults()
        if self.custom_manifests_dir and self.custom_manifests_dir.exists():
            self._load_custom_manifests()
        self._sync_persisted_states()

    def _sync_persisted_states(self) -> None:
        self._load_custom_manifests()
        if self.store is None:
            return
        persisted = self.store.list_capability_states()
        for cid, st in persisted.items():
            if st == "disabled":
                self._disabled_ids.add(cid)
                self._quarantined_ids.discard(cid)
            elif st == "quarantined":
                self._quarantined_ids.add(cid)
            elif st == "enabled":
                self._disabled_ids.discard(cid)
                self._quarantined_ids.discard(cid)
            elif st == "removed":
                adapter = self._adapters.get(cid)
                if adapter and adapter.descriptor.pack == "custom":
                    self._adapters.pop(cid, None)

    def _register_defaults(self) -> None:
        for adapter in [*build_default_adapters(), *build_offline_adapters(),
                        WorkspaceAdapter(self.workspace), ToolInventoryAdapter(self), CustomToolAdapter(self), DnsEnumAdapter()]:
            self._adapters[adapter.descriptor.capability_id] = adapter
        if self.store is not None:
            comparison = EvidenceComparisonAdapter(self.store)
            self._adapters[comparison.descriptor.capability_id] = comparison
            verifier = VerificationAdapter()
            self._adapters[verifier.descriptor.capability_id] = verifier
            research = ResearchAdapter(self.store.db_path.parent)
            self._adapters[research.descriptor.capability_id] = research
            browser_session = BrowserSessionAdapter(self.store.db_path.parent)
            self._adapters[browser_session.descriptor.capability_id] = browser_session
            execution = ExecutionSessionAdapter(self.store.db_path.parent)
            self._adapters[execution.descriptor.capability_id] = execution
            host_execution = HostExecutionAdapter(self.store.db_path.parent,
                self.workspace.base_dir if self.workspace is not None else self.store.db_path.parent / "workspace")
            self._adapters[host_execution.descriptor.capability_id] = host_execution
        browser_adapter = BrowserInspectionAdapter()
        self._adapters[browser_adapter.descriptor.capability_id] = browser_adapter
        intel_adapter = ThreatIntelAdapter()
        self._adapters[intel_adapter.descriptor.capability_id] = intel_adapter
        wf_adapter = WstgWorkflowAdapter()
        self._adapters[wf_adapter.descriptor.capability_id] = wf_adapter

    def _load_custom_manifests(self) -> None:
        if not self.custom_manifests_dir:
            return
        with self._manifest_lock:
            present = set()
            for path in sorted(self.custom_manifests_dir.glob("*.json")):
                cid = path.stem
                present.add(cid)
                try:
                    if path.is_symlink():
                        raise ValueError("Custom manifest must be a regular file")
                    info = path.stat()
                    signature = (info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                    if self._manifest_signatures.get(cid) == signature:
                        continue
                    manifest = CustomAdapterManifest.from_dict(json.loads(path.read_text(encoding="utf-8")))
                    if manifest.capability_id != cid:
                        raise ValueError("Manifest name must match its capability ID")
                    existing = self._adapters.get(cid)
                    if existing and existing.descriptor.pack != "custom":
                        raise ValueError("Custom adapters cannot replace built-in capabilities")
                    self._adapters[cid] = DeclarativeCustomAdapter(manifest)
                    self._manifest_signatures[cid] = signature
                except (OSError, ValueError, TypeError, KeyError):
                    if cid in self._manifest_signatures:
                        self._adapters.pop(cid, None)
                        self._manifest_signatures.pop(cid, None)
            for cid in set(self._manifest_signatures) - present:
                self._adapters.pop(cid, None)
                self._manifest_signatures.pop(cid, None)

    def register_adapter(self, adapter: ToolAdapter) -> None:
        self._adapters[adapter.descriptor.capability_id] = adapter

    def register_custom_adapter(self, manifest: CustomAdapterManifest) -> ToolAdapter:
        adapter = DeclarativeCustomAdapter(manifest)
        existing = self._adapters.get(manifest.capability_id)
        if existing and existing.descriptor.pack != "custom":
            raise ValueError("Custom adapters cannot replace built-in capabilities")
        if self.custom_manifests_dir:
            self.custom_manifests_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            target_file = self.custom_manifests_dir / f"{manifest.capability_id}.json"
            fd, temporary = tempfile.mkstemp(prefix=".adapter-", dir=self.custom_manifests_dir)
            try:
                with os.fdopen(fd, "w") as stream:
                    json.dump(manifest.to_dict(), stream, indent=2)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, target_file)
            finally:
                Path(temporary).unlink(missing_ok=True)
        if self.store is not None:
            self.store.set_capability_state(manifest.capability_id, "enabled", reason="Custom adapter installed")
        self._adapters[adapter.descriptor.capability_id] = adapter
        return adapter

    def quarantine_capability(self, capability_id: str, reason: str = "Quarantined") -> bool:
        if capability_id not in self._adapters:
            return False
        self._quarantined_ids.add(capability_id)
        if self.store is not None:
            self.store.set_capability_state(capability_id, "quarantined", reason=reason)
        return True

    def enable_capability(self, capability_id: str, unquarantine: bool = False) -> bool:
        if capability_id not in self._adapters:
            return False
        self._sync_persisted_states()
        if capability_id in self._quarantined_ids and not unquarantine:
            return False
        self._disabled_ids.discard(capability_id)
        self._quarantined_ids.discard(capability_id)
        if self.store is not None:
            self.store.set_capability_state(capability_id, "enabled", reason="Explicitly enabled")
        return True

    def disable_capability(self, capability_id: str, reason: str = "Explicitly disabled") -> bool:
        if capability_id not in self._adapters:
            return False
        self._disabled_ids.add(capability_id)
        if self.store is not None:
            self.store.set_capability_state(capability_id, "disabled", reason=reason)
        return True

    def remove_custom_capability(self, capability_id: str) -> bool:
        adapter = self._adapters.get(capability_id)
        if not adapter or adapter.descriptor.pack != "custom":
            return False
        self._adapters.pop(capability_id, None)
        self._disabled_ids.discard(capability_id)
        self._quarantined_ids.discard(capability_id)
        if self.custom_manifests_dir:
            f = self.custom_manifests_dir / f"{capability_id}.json"
            if f.exists():
                f.unlink()
        if self.store is not None:
            self.store.set_capability_state(capability_id, "removed", reason="Custom adapter removed")
        return True

    def get_adapter(self, capability_id: str) -> Optional[ToolAdapter]:
        self._sync_persisted_states()
        if capability_id in self._disabled_ids or capability_id in self._quarantined_ids:
            return None
        return self._adapters.get(capability_id)

    def get_binary_identity(
        self,
        binary_name: Optional[str],
        probe_version: bool = False,
        runner: Optional[SafeSubprocessRunner] = None,
    ) -> BinaryIdentity:
        key = f"{binary_name or 'builtin'}:{int(probe_version)}"
        signature = None
        if binary_name:
            search_path = os.pathsep.join(self.search_paths) if self.search_paths else None
            resolved = resolve_binary_path(binary_name, search_path=search_path)
            if resolved:
                try:
                    info = Path(resolved).stat()
                    signature = (resolved, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                except OSError:
                    pass
        if key not in self._binary_cache or self._binary_signatures.get(key) != signature:
            self._binary_cache[key] = inspect_binary_identity(
                binary_name or "",
                search_paths=self.search_paths,
                probe_version=probe_version,
                runner=runner,
            )
            self._binary_signatures[key] = signature
        return self._binary_cache[key]

    def search_capabilities(
        self,
        query: str = "",
        category: Optional[str] = None,
        pack: Optional[str] = None,
        only_available: bool = False,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        self._sync_persisted_states()
        results: List[Dict[str, Any]] = []
        q_low = query.strip().lower()
        for cid, adapter in sorted(self._adapters.copy().items()):
            desc = adapter.descriptor
            if category and desc.category.lower() != category.lower():
                continue
            if pack and desc.pack.lower() != pack.lower():
                continue
            if q_low:
                haystack = (
                    f"{desc.capability_id} {desc.name} {desc.category} {desc.description} {desc.binary_name or ''}"
                ).lower()
                if q_low not in haystack:
                    continue

            if cid in self._quarantined_ids:
                status = ToolStatus.QUARANTINED.value
            elif cid in self._disabled_ids:
                status = "disabled"
            else:
                ident = self.get_binary_identity(desc.binary_name, probe_version=False)
                status = ident.status.value

            if only_available and status != ToolStatus.ENABLED.value:
                continue

            results.append(desc.to_summary_dict(install_status=status))
            if len(results) >= max(1, min(limit, 100)):
                break
        return results

    def describe_capabilities(
        self,
        capability_ids: Sequence[str],
        probe_version: bool = False,
        runner: Optional[SafeSubprocessRunner] = None,
    ) -> List[Dict[str, Any]]:
        self._sync_persisted_states()
        details: List[Dict[str, Any]] = []
        for cid in capability_ids:
            adapter = self._adapters.get(cid)
            if not adapter:
                details.append({"capability_id": cid, "error": "CAPABILITY_NOT_FOUND"})
                continue
            ident = self.get_binary_identity(
                adapter.descriptor.binary_name, probe_version=probe_version, runner=runner
            )
            info = ident.to_dict()
            if cid in self._quarantined_ids:
                info["status"] = ToolStatus.QUARANTINED.value
            elif cid in self._disabled_ids:
                info["status"] = "disabled"
            detail = adapter.descriptor.to_detail_dict(install_info=info)
            if self.store:
                detail["verification"] = read_receipt(self.store, cid, verification_identity(adapter, ident))
            details.append(detail)
        return details

    def summary_counts(self) -> Dict[str, int]:
        self._sync_persisted_states()
        total = len(self._adapters)
        enabled = 0
        missing = 0
        incompatible = 0
        restricted = 0
        for cid, adapter in self._adapters.copy().items():
            if cid in self._disabled_ids or cid in self._quarantined_ids:
                continue
            ident = self.get_binary_identity(adapter.descriptor.binary_name, probe_version=False)
            if ident.status == ToolStatus.ENABLED:
                enabled += 1
            elif ident.status == ToolStatus.RESTRICTED:
                restricted += 1
            elif ident.status == ToolStatus.INCOMPATIBLE:
                incompatible += 1
            else:
                missing += 1
        return {
            "registered_capabilities": total,
            "available_local": enabled,
            "missing_local": missing,
            "incompatible_local": incompatible,
            "restricted_local": restricted,
            "disabled": len(self._disabled_ids),
            "quarantined": len(self._quarantined_ids),
        }

    def discover_installed(self, query="", offset=0, limit=25):
        """Inventory PATH without running or automatically trusting executable files."""
        self._sync_persisted_states()
        bindings = {}
        search_path = os.pathsep.join(self.search_paths) if self.search_paths else None
        for adapter in self._adapters.copy().values():
            binary = adapter.descriptor.binary_name
            resolved = resolve_binary_path(binary, search_path) if binary else None
            if resolved:
                bindings.setdefault(Path(resolved).name, []).append(adapter.descriptor.capability_id)
        found = {}
        scanned = 0
        truncated = False
        for directory in self.search_paths or os.get_exec_path():
            if not os.path.isabs(directory):
                continue
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        scanned += 1
                        if scanned > 50000:
                            truncated = True
                            break
                        if entry.name in found or query.casefold() not in entry.name.casefold():
                            continue
                        if entry.is_file() and os.access(entry.path, os.X_OK):
                            found[entry.name] = {"name": entry.name, "path": entry.path,
                                "capability_ids": bindings.get(entry.name, []),
                                "adapter_registered": bool(bindings.get(entry.name))}
            except OSError:
                continue
            if truncated:
                break
        items = sorted(found.values(), key=lambda item: item['name'])
        end = offset + limit
        return {"success": True, "executables": items[offset:end], "total": len(items),
                "next_offset": end if end < len(items) else None, "scan_truncated": truncated,
                "execution": {"capability_id": "execution.host", "operation": "run",
                              "adapter_required": False,
                              "usage": "Pass the executable path as argv[0], followed by its arguments. Use start with tty=true for an interactive session."}}
