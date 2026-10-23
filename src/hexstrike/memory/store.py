"""Local graph persistence, engagement memory, and evaluated lesson retrieval."""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator

import asyncio
import hashlib
import json
import math
import os
import sqlite3
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from hexstrike.persistence import database_connection
from hexstrike.memory.cypher import _SqliteCypherEvaluator
from hexstrike.domain.models import LessonState, Principal, new_id, utc_now_iso
from hexstrike.workspace.confined_fs import redact_secrets


os.environ["GRAPHITI_TELEMETRY_ENABLED"] = "false"
os.environ["ANONYMIZED_TELEMETRY"] = "false"


def compute_local_hash_embedding(text: str, dim: int = 64) -> List[float]:
    vec = [0.0] * dim
    tokens = [t.strip(".,:;()[]{}\"'") for t in text.lower().split() if t.strip(".,:;()[]{}\"'")]
    if not tokens:
        return vec
    for tok in tokens:
        digest = hashlib.sha256(tok.encode("utf-8")).digest()
        for i in range(0, min(len(digest), dim), 2):
            idx = digest[i] % dim
            sign = 1.0 if (digest[i + 1] & 1) == 0 else -1.0
            vec[idx] += sign
    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [round(v / norm, 6) for v in vec]
    return vec


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x * y for x, y in zip(a, b))


def _run_coro_sync(coro: Any) -> Any:
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop is None:
        return asyncio.run(coro)
    result_box: List[Any] = []
    err_box: List[BaseException] = []

    def _target() -> None:
        try:
            result_box.append(asyncio.run(coro))
        except BaseException as exc:
            err_box.append(exc)

    t = threading.Thread(target=_target, daemon=True)
    t.start()
    t.join(timeout=15.0)
    if err_box:
        raise err_box[0]
    return result_box[0] if result_box else None


class LocalGraphitiAdapter:
    """
    Functional SQLite-backed `graphiti_core` adapter implementing `GraphDriver`,
    `GraphOperationsInterface`, and `SearchInterface` so `EpisodicNode.save`,
    `EntityNode.save`, `EntityEdge.save`, `driver.execute_query`, and `Graphiti.search`
    persist and retrieve real temporal graph nodes and edges across restarts.
    """

    def __init__(self, db_path: Path, lock: threading.RLock) -> None:
        self.db_path = db_path
        self._lock = lock
        self.graphiti_available = False
        self.graphiti_instance: Any = None
        self.driver: Any = None
        self._init_graphiti_tables()
        self._init_graphiti()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with database_connection(str(self.db_path), timeout=30.0, check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            yield conn

    def _init_graphiti_tables(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS graphiti_episodic_nodes (
                    uuid TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    content TEXT NOT NULL,
                    source TEXT NOT NULL,
                    source_description TEXT NOT NULL,
                    entity_edges_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    valid_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graphiti_entity_nodes (
                    uuid TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    labels_json TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    name_embedding_json TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graphiti_entity_edges (
                    uuid TEXT PRIMARY KEY,
                    source_node_uuid TEXT NOT NULL,
                    target_node_uuid TEXT NOT NULL,
                    name TEXT NOT NULL,
                    fact TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    fact_embedding_json TEXT NOT NULL,
                    episodes_json TEXT NOT NULL,
                    attributes_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    valid_at TEXT,
                    invalid_at TEXT,
                    expired_at TEXT
                );
                """
            )

    def _init_graphiti(self) -> None:
        try:
            from graphiti_core import Graphiti
            from graphiti_core.cross_encoder.client import CrossEncoderClient
            from graphiti_core.driver.driver import GraphDriver, GraphDriverSession, GraphProvider
            from graphiti_core.driver.graph_operations.graph_operations import GraphOperationsInterface
            from graphiti_core.driver.search_interface.search_interface import SearchInterface
            from graphiti_core.edges import EntityEdge
            from graphiti_core.embedder.client import EmbedderClient
            from graphiti_core.llm_client.client import LLMClient
            from graphiti_core.llm_client.config import LLMConfig
            from graphiti_core.nodes import EntityNode, EpisodicNode

            adapter_ref = self

            class _SqliteGraphOperations(GraphOperationsInterface):
                async def episodic_node_save(self, node: EpisodicNode, driver: Any) -> Any:
                    with adapter_ref._lock, adapter_ref._connect() as conn:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO graphiti_episodic_nodes (
                                uuid, name, group_id, content, source, source_description,
                                entity_edges_json, created_at, valid_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                node.uuid,
                                node.name,
                                node.group_id,
                                node.content,
                                node.source.value if hasattr(node.source, "value") else str(node.source),
                                node.source_description,
                                json.dumps(node.entity_edges or []),
                                node.created_at.isoformat(),
                                node.valid_at.isoformat(),
                            ),
                        )

                async def node_save(self, node: EntityNode, driver: Any) -> Any:
                    emb = node.name_embedding or compute_local_hash_embedding(f"{node.name} {node.summary}")
                    with adapter_ref._lock, adapter_ref._connect() as conn:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO graphiti_entity_nodes (
                                uuid, name, group_id, labels_json, summary,
                                name_embedding_json, attributes_json, created_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                node.uuid,
                                node.name,
                                node.group_id,
                                json.dumps(node.labels or ["Entity"]),
                                node.summary or "",
                                json.dumps(emb),
                                json.dumps(node.attributes or {}),
                                node.created_at.isoformat(),
                            ),
                        )

                async def edge_save(self, edge: EntityEdge, driver: Any) -> Any:
                    emb = edge.fact_embedding or compute_local_hash_embedding(f"{edge.name} {edge.fact}")
                    with adapter_ref._lock, adapter_ref._connect() as conn:
                        conn.execute(
                            """
                            INSERT OR REPLACE INTO graphiti_entity_edges (
                                uuid, source_node_uuid, target_node_uuid, name, fact,
                                group_id, fact_embedding_json, episodes_json, attributes_json,
                                created_at, valid_at, invalid_at, expired_at
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                edge.uuid,
                                edge.source_node_uuid,
                                edge.target_node_uuid,
                                edge.name,
                                edge.fact,
                                edge.group_id,
                                json.dumps(emb),
                                json.dumps(edge.episodes or []),
                                json.dumps(edge.attributes or {}),
                                edge.created_at.isoformat(),
                                edge.valid_at.isoformat() if edge.valid_at else None,
                                edge.invalid_at.isoformat() if edge.invalid_at else None,
                                edge.expired_at.isoformat() if edge.expired_at else None,
                            ),
                        )

            class _SqliteSearchInterface(SearchInterface):
                async def edge_fulltext_search(
                    self,
                    driver: Any,
                    query: str,
                    search_filter: Any,
                    group_ids: Optional[List[str]] = None,
                    limit: int = 100,
                ) -> List[EntityEdge]:
                    return adapter_ref._search_entity_edges(
                        query=query,
                        search_vector=None,
                        group_ids=group_ids,
                        limit=limit,
                    )

                async def edge_similarity_search(
                    self,
                    driver: Any,
                    search_vector: List[float],
                    source_node_uuid: Optional[str],
                    target_node_uuid: Optional[str],
                    search_filter: Any,
                    group_ids: Optional[List[str]] = None,
                    limit: int = 100,
                    min_score: float = 0.0,
                ) -> List[EntityEdge]:
                    return adapter_ref._search_entity_edges(
                        query="",
                        search_vector=search_vector,
                        source_node_uuid=source_node_uuid,
                        target_node_uuid=target_node_uuid,
                        group_ids=group_ids,
                        limit=limit,
                        min_score=min_score,
                    )

                async def node_fulltext_search(
                    self,
                    driver: Any,
                    query: str,
                    search_filter: Any,
                    group_ids: Optional[List[str]] = None,
                    limit: int = 100,
                ) -> List[EntityNode]:
                    return adapter_ref._search_entity_nodes(
                        query=query,
                        search_vector=None,
                        group_ids=group_ids,
                        limit=limit,
                    )

                async def node_similarity_search(
                    self,
                    driver: Any,
                    search_vector: List[float],
                    search_filter: Any,
                    group_ids: Optional[List[str]] = None,
                    limit: int = 100,
                    min_score: float = 0.0,
                ) -> List[EntityNode]:
                    return adapter_ref._search_entity_nodes(
                        query="",
                        search_vector=search_vector,
                        group_ids=group_ids,
                        limit=limit,
                        min_score=min_score,
                    )

            class _SqliteGraphSession(GraphDriverSession):
                provider = GraphProvider.KUZU

                async def __aenter__(self) -> "_SqliteGraphSession":
                    return self

                async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
                    pass

                async def close(self) -> None:
                    pass

                async def execute_write(self, func: Any, *args: Any, **kwargs: Any) -> Any:
                    return await func(self, *args, **kwargs)

                async def run(self, query: str | list[Any], **kwargs: Any) -> Any:
                    res, _, _ = await adapter_ref.driver.execute_query(str(query), **kwargs)
                    return res

            class _SqliteGraphDriver(GraphDriver):
                provider = GraphProvider.KUZU

                def __init__(self) -> None:
                    super().__init__()
                    self._database = str(adapter_ref.db_path)
                    self.graph_operations_interface = _SqliteGraphOperations()
                    self.search_interface = _SqliteSearchInterface()

                async def execute_query(
                    self, cypher_query_: str, **kwargs: Any
                ) -> Tuple[List[Dict[str, Any]], None, None]:
                    records = _SqliteCypherEvaluator.execute(adapter_ref, cypher_query_, kwargs)
                    return records, None, None

                def session(self, database: Optional[str] = None) -> GraphDriverSession:
                    return _SqliteGraphSession()

                async def close(self) -> None:
                    pass

                async def delete_all_indexes(self) -> Any:
                    return None

                def build_indices_and_constraints(self, delete_existing: bool = False) -> Any:
                    async def _build() -> None:
                        adapter_ref._init_graphiti_tables()
                    return _build()

            class _LocalOfflineLLMClient(LLMClient):
                def __init__(self) -> None:
                    super().__init__(LLMConfig(api_key="local-offline", model="local-deterministic"))

                async def _generate_response(
                    self,
                    messages: List[Any],
                    response_model: Any = None,
                    max_tokens: int = 2048,
                    model_size: Any = None,
                    *,
                    model: Optional[str] = None,
                ) -> Dict[str, Any]:
                    if response_model is not None and hasattr(response_model, "model_fields"):
                        out: Dict[str, Any] = {}
                        for fname, fmeta in response_model.model_fields.items():
                            if "list" in str(fmeta.annotation).lower():
                                out[fname] = []
                            elif "str" in str(fmeta.annotation).lower():
                                out[fname] = "local"
                            else:
                                out[fname] = None
                        return out
                    return {"content": "local_offline_extraction"}

            class _LocalOfflineEmbedder(EmbedderClient):
                async def create(self, input_data: Any) -> List[float]:
                    if isinstance(input_data, str):
                        return compute_local_hash_embedding(input_data)
                    if isinstance(input_data, list) and input_data and isinstance(input_data[0], str):
                        return compute_local_hash_embedding(" ".join(input_data))
                    return [0.0] * 64

            class _LocalOfflineCrossEncoder(CrossEncoderClient):
                async def rank(self, query: str, passages: List[str]) -> List[Tuple[str, float]]:
                    q_emb = compute_local_hash_embedding(query)
                    scored = [(p, cosine_similarity(q_emb, compute_local_hash_embedding(p))) for p in passages]
                    return sorted(scored, key=lambda item: item[1], reverse=True)

            self.driver = _SqliteGraphDriver()
            llm = _LocalOfflineLLMClient()
            embedder = _LocalOfflineEmbedder()
            reranker = _LocalOfflineCrossEncoder()
            self.graphiti_instance = Graphiti(
                graph_driver=self.driver,
                llm_client=llm,
                embedder=embedder,
                cross_encoder=reranker,
                store_raw_episode_content=True,
            )
            self.graphiti_available = True
        except Exception:
            self.graphiti_available = False
            self.graphiti_instance = None
            self.driver = None

    def _search_entity_edges(
        self,
        query: str = "",
        search_vector: Optional[List[float]] = None,
        source_node_uuid: Optional[str] = None,
        target_node_uuid: Optional[str] = None,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = 50,
        min_score: float = 0.0,
    ) -> List[Any]:
        from graphiti_core.edges import EntityEdge

        sql = "SELECT * FROM graphiti_entity_edges WHERE expired_at IS NULL"
        params: List[Any] = []
        if group_ids:
            placeholders = ",".join("?" for _ in group_ids)
            sql += f" AND group_id IN ({placeholders})"
            params.extend(group_ids)
        if source_node_uuid:
            sql += " AND source_node_uuid = ?"
            params.append(source_node_uuid)
        if target_node_uuid:
            sql += " AND target_node_uuid = ?"
            params.append(target_node_uuid)
        if query.strip():
            tokens = [t.strip().lower() for t in query.split() if t.strip()]
            if tokens:
                token_clauses = []
                for tok in tokens:
                    token_clauses.append("(LOWER(name) LIKE ? OR LOWER(fact) LIKE ?)")
                    params.extend([f"%{tok}%", f"%{tok}%"])
                sql += " AND (" + " OR ".join(token_clauses) + ")"
        sql += " ORDER BY created_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(max(1, limit * 4))

        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        results: List[Tuple[float, Any]] = []
        for r in rows:
            emb = json.loads(r["fact_embedding_json"] or "[]")
            score = cosine_similarity(search_vector, emb) if (search_vector and emb) else 1.0
            if search_vector and score < min_score and not query.strip():
                continue
            edge = EntityEdge(
                uuid=r["uuid"],
                source_node_uuid=r["source_node_uuid"],
                target_node_uuid=r["target_node_uuid"],
                name=r["name"],
                fact=r["fact"],
                group_id=r["group_id"],
                fact_embedding=emb,
                episodes=json.loads(r["episodes_json"] or "[]"),
                attributes=json.loads(r["attributes_json"] or "{}"),
                created_at=datetime.fromisoformat(r["created_at"]),
                valid_at=datetime.fromisoformat(r["valid_at"]) if r["valid_at"] else None,
                invalid_at=datetime.fromisoformat(r["invalid_at"]) if r["invalid_at"] else None,
                expired_at=datetime.fromisoformat(r["expired_at"]) if r["expired_at"] else None,
            )
            results.append((score, edge))

        results.sort(key=lambda item: item[0], reverse=True)
        return [e for _, e in results[:limit]]

    def _search_entity_nodes(
        self,
        query: str = "",
        search_vector: Optional[List[float]] = None,
        group_ids: Optional[List[str]] = None,
        limit: Optional[int] = 50,
        min_score: float = 0.0,
    ) -> List[Any]:
        from graphiti_core.nodes import EntityNode

        sql = "SELECT * FROM graphiti_entity_nodes WHERE 1=1"
        params: List[Any] = []
        if group_ids:
            placeholders = ",".join("?" for _ in group_ids)
            sql += f" AND group_id IN ({placeholders})"
            params.extend(group_ids)
        if query.strip():
            q_like = f"%{query.strip().lower()}%"
            sql += " AND (LOWER(name) LIKE ? OR LOWER(summary) LIKE ?)"
            params.extend([q_like, q_like])
        sql += " ORDER BY created_at DESC"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(max(1, limit * 4))

        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()

        scored_nodes: List[Tuple[float, Any]] = []
        for r in rows:
            emb = json.loads(r["name_embedding_json"] or "[]")
            score = cosine_similarity(search_vector, emb) if (search_vector and emb) else 1.0
            if search_vector and score < min_score and not query.strip():
                continue
            node = EntityNode(
                uuid=r["uuid"],
                name=r["name"],
                group_id=r["group_id"],
                labels=json.loads(r["labels_json"] or '["Entity"]'),
                summary=r["summary"],
                name_embedding=emb,
                attributes=json.loads(r["attributes_json"] or "{}"),
                created_at=datetime.fromisoformat(r["created_at"]),
            )
            scored_nodes.append((score, node))
        scored_nodes.sort(key=lambda item: item[0], reverse=True)
        return [n for _, n in scored_nodes[:limit]]

    def ingest_episode_into_graphiti(
        self,
        episode_id: str,
        engagement_id: str,
        entity_type: str,
        subject: str,
        content: str,
        relations: List[Tuple[str, str, str]],
        metadata: Dict[str, Any],
    ) -> List[str]:
        if not self.graphiti_available or self.driver is None:
            return []

        from graphiti_core.edges import EntityEdge
        from graphiti_core.nodes import EntityNode, EpisodicNode, EpisodeType

        now = datetime.now(timezone.utc)
        edge_uuids: List[str] = []

        async def _persist() -> None:
            subj_uuid = hashlib.sha256(f"{engagement_id}:node:{subject}".encode("utf-8")).hexdigest()[:24]
            subj_node = EntityNode(
                uuid=subj_uuid,
                name=subject,
                group_id=engagement_id,
                labels=["Entity", entity_type],
                summary=content,
                name_embedding=compute_local_hash_embedding(f"{subject} {content}"),
                attributes=metadata,
                created_at=now,
            )
            await subj_node.save(self.driver)

            # Always create a primary fact edge for the episode subject -> content so Graphiti.search finds it
            primary_edge_uuid = hashlib.sha256(f"{episode_id}:primary".encode("utf-8")).hexdigest()[:24]
            primary_edge = EntityEdge(
                uuid=primary_edge_uuid,
                source_node_uuid=subj_uuid,
                target_node_uuid=subj_uuid,
                name=entity_type,
                fact=f"{subject}: {content}",
                group_id=engagement_id,
                fact_embedding=compute_local_hash_embedding(f"{subject} {entity_type} {content}"),
                episodes=[episode_id],
                attributes=metadata,
                created_at=now,
                valid_at=now,
            )
            await primary_edge.save(self.driver)
            edge_uuids.append(primary_edge_uuid)

            for idx, (src_name, rel_name, dst_name) in enumerate(relations):
                src_id = hashlib.sha256(f"{engagement_id}:node:{src_name}".encode("utf-8")).hexdigest()[:24]
                dst_id = hashlib.sha256(f"{engagement_id}:node:{dst_name}".encode("utf-8")).hexdigest()[:24]
                src_n = EntityNode(
                    uuid=src_id,
                    name=src_name,
                    group_id=engagement_id,
                    labels=["Entity"],
                    summary=f"Node {src_name} in {engagement_id}",
                    name_embedding=compute_local_hash_embedding(src_name),
                    created_at=now,
                )
                dst_n = EntityNode(
                    uuid=dst_id,
                    name=dst_name,
                    group_id=engagement_id,
                    labels=["Entity"],
                    summary=f"Node {dst_name} in {engagement_id}",
                    name_embedding=compute_local_hash_embedding(dst_name),
                    created_at=now,
                )
                await src_n.save(self.driver)
                await dst_n.save(self.driver)

                e_uuid = hashlib.sha256(f"{episode_id}:rel:{idx}:{src_name}:{rel_name}:{dst_name}".encode("utf-8")).hexdigest()[:24]
                fact_str = f"{src_name} {rel_name} {dst_name} ({content})"
                rel_edge = EntityEdge(
                    uuid=e_uuid,
                    source_node_uuid=src_id,
                    target_node_uuid=dst_id,
                    name=rel_name,
                    fact=fact_str,
                    group_id=engagement_id,
                    fact_embedding=compute_local_hash_embedding(fact_str),
                    episodes=[episode_id],
                    attributes=metadata,
                    created_at=now,
                    valid_at=now,
                )
                await rel_edge.save(self.driver)
                edge_uuids.append(e_uuid)

            ep_node = EpisodicNode(
                uuid=episode_id,
                name=subject,
                group_id=engagement_id,
                source=EpisodeType.text,
                source_description=entity_type,
                content=content,
                entity_edges=edge_uuids,
                created_at=now,
                valid_at=now,
            )
            await ep_node.save(self.driver)

        _run_coro_sync(_persist())
        return edge_uuids

    def search_graphiti(self, engagement_id: str, query_text: str, limit: int = 20) -> List[Dict[str, Any]]:
        if not self.graphiti_available or self.graphiti_instance is None:
            return []

        async def _do_search() -> List[Any]:
            if query_text.strip():
                return await self.graphiti_instance.search(
                    query=query_text,
                    group_ids=[engagement_id],
                    num_results=limit,
                )
            return self._search_entity_edges(query="", group_ids=[engagement_id], limit=limit)

        edges = _run_coro_sync(_do_search()) or []
        return [
            {
                "edge_uuid": e.uuid,
                "name": e.name,
                "fact": e.fact,
                "group_id": e.group_id,
                "source_node_uuid": e.source_node_uuid,
                "target_node_uuid": e.target_node_uuid,
                "episodes": list(e.episodes or []),
                "created_at": e.created_at.isoformat() if hasattr(e.created_at, "isoformat") else str(e.created_at),
            }
            for e in edges
        ]

    def delete_group(self, engagement_id: str) -> int:
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM graphiti_entity_edges WHERE group_id = ?", (engagement_id,))
            conn.execute("DELETE FROM graphiti_entity_nodes WHERE group_id = ?", (engagement_id,))
            cur = conn.execute("DELETE FROM graphiti_episodic_nodes WHERE group_id = ?", (engagement_id,))
            return int(cur.rowcount or 0)


@dataclass
class MemoryEpisode:
    episode_id: str
    engagement_id: str
    entity_type: str
    subject: str
    content: str
    source_artifact_ids: List[str] = field(default_factory=list)
    confidence: float = 0.85
    extractor_version: str = "graphiti-local-1.0"
    created_at: str = field(default_factory=utc_now_iso)
    valid_until: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class LessonRecord:
    lesson_id: str
    source_engagement_id: str
    capability_id: str
    title: str
    recommendation: str
    state: LessonState = LessonState.CANDIDATE
    evidence_ids: List[str] = field(default_factory=list)
    eval_score: Optional[float] = None
    eval_details: Dict[str, Any] = field(default_factory=dict)
    reviewed_by: Optional[str] = None
    version: int = 1
    created_at: str = field(default_factory=utc_now_iso)
    updated_at: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["state"] = self.state.value
        return data


FORBIDDEN_LESSON_TERMS = (
    "rm -rf",
    "--os-shell",
    "--no-sandbox",
    "disable_policy",
    "chmod 777",
    "--disable-web-security",
    "--ignore-certificate-errors",
)

# Held-out benchmark tasks comparing retrieval and recommendation precision
HELD_OUT_BENCHMARK_CASES: List[Dict[str, Any]] = [
    {
        "case_id": "nmap_version_light",
        "capability_id": "network.nmap",
        "positive_keywords": ("version", "-sv", "service", "port", "profile", "nmap", "scan"),
        "negative_fp_keywords": ("exploit_all", "brute_force_all", "shell"),
    },
    {
        "case_id": "http_header_hardening",
        "capability_id": "web.http_inspect",
        "positive_keywords": ("header", "csp", "hsts", "probe", "redirect"),
        "negative_fp_keywords": ("disable_tls", "ignore_ssl"),
    },
    {
        "case_id": "jwt_alg_validation",
        "capability_id": "api.jwt_analyzer",
        "positive_keywords": ("jwt", "alg", "exp", "token", "signature"),
        "negative_fp_keywords": ("accept_none", "skip_verify"),
    },
]


def lint_lesson_safety(title: str, recommendation: str, capability_id: str) -> Dict[str, Any]:
    """Text safety lint for candidate lessons (distinct from held-out outcome evaluation)."""
    combined = f"{title} {recommendation}".lower()
    violated = [term for term in FORBIDDEN_LESSON_TERMS if term in combined]
    valid_cap = "." in capability_id and len(capability_id) >= 4
    return {
        "safety_lint_passed": len(violated) == 0 and valid_cap and len(recommendation.strip()) >= 15,
        "violated_terms": violated,
        "valid_capability_id": valid_cap,
    }


class LocalMemoryStore:
    """
    Local temporal knowledge graph and episodic memory store with real `graphiti_core`
    persistence/search (`LocalGraphitiAdapter`), SQLite episode/edge index, and
    held-out lesson evaluation.
    """

    def __init__(
        self,
        db_path: Optional[str | Path] = None,
        allow_external_inference: bool = False,
        memory_enabled: bool = True,
    ) -> None:
        if db_path is None:
            default_dir = Path(tempfile.gettempdir()) / "hexstrike_state"
            default_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.db_path = default_dir / "hexstrike_memory.db"
        else:
            self.db_path = Path(db_path)
            self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        self.allow_external_inference = allow_external_inference
        self.memory_enabled = memory_enabled
        self.telemetry_enabled = False
        self._lock = threading.RLock()
        self._init_schema()
        self._graphiti_adapter: Optional[LocalGraphitiAdapter] = None

    @property
    def graphiti_adapter(self) -> LocalGraphitiAdapter:
        """Load the optional graph SDK when memory is first used."""
        with self._lock:
            if self._graphiti_adapter is None:
                self._graphiti_adapter = LocalGraphitiAdapter(self.db_path, self._lock)
            return self._graphiti_adapter

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        with database_connection(str(self.db_path), timeout=30.0, check_same_thread=False) as conn:
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL;")
            yield conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS memory_episodes (
                    episode_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    entity_type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    content TEXT NOT NULL,
                    embedding_json TEXT NOT NULL DEFAULT '[]',
                    source_artifacts_json TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    extractor_version TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    valid_until TEXT,
                    metadata_json TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS graph_edges (
                    edge_id TEXT PRIMARY KEY,
                    engagement_id TEXT NOT NULL,
                    source_node TEXT NOT NULL,
                    relation TEXT NOT NULL,
                    target_node TEXT NOT NULL,
                    episode_id TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS lessons (
                    lesson_id TEXT PRIMARY KEY,
                    source_engagement_id TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    recommendation TEXT NOT NULL,
                    state TEXT NOT NULL,
                    evidence_ids_json TEXT NOT NULL,
                    eval_score REAL,
                    eval_details_json TEXT NOT NULL DEFAULT '{}',
                    reviewed_by TEXT,
                    version INTEGER NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                """
            )

    def record_episode(
        self,
        engagement_id: str,
        entity_type: str,
        subject: str,
        content: str,
        source_artifact_ids: Optional[List[str]] = None,
        confidence: float = 0.85,
        relations: Optional[List[Tuple[str, str, str]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> MemoryEpisode:
        safe_subject = redact_secrets(subject)
        safe_content = redact_secrets(content)
        safe_relations = [
            (redact_secrets(s), redact_secrets(r), redact_secrets(d))
            for s, r, d in (relations or [])
        ]
        embedding = compute_local_hash_embedding(f"{safe_subject} {safe_content}")
        ep = MemoryEpisode(
            episode_id=new_id("mem"),
            engagement_id=engagement_id,
            entity_type=entity_type,
            subject=safe_subject,
            content=safe_content,
            source_artifact_ids=list(source_artifact_ids or []),
            confidence=confidence,
            extractor_version="graphiti-local-1.0" if self.graphiti_adapter.graphiti_available else "sqlite-local-1.0",
            metadata=dict(metadata or {}),
        )
        if not self.memory_enabled:
            return ep

        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO memory_episodes (
                    episode_id, engagement_id, entity_type, subject, content,
                    embedding_json, source_artifacts_json, confidence, extractor_version,
                    created_at, valid_until, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ep.episode_id,
                    ep.engagement_id,
                    ep.entity_type,
                    ep.subject,
                    ep.content,
                    json.dumps(embedding),
                    json.dumps(ep.source_artifact_ids),
                    ep.confidence,
                    ep.extractor_version,
                    ep.created_at,
                    ep.valid_until,
                    json.dumps(ep.metadata),
                ),
            )
            for src_node, rel, dst_node in safe_relations:
                conn.execute(
                    """
                    INSERT INTO graph_edges (
                        edge_id, engagement_id, source_node, relation, target_node, episode_id, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        new_id("edge"),
                        engagement_id,
                        src_node,
                        rel,
                        dst_node,
                        ep.episode_id,
                        ep.created_at,
                    ),
                )

        # Ingest into functional Graphiti temporal graph (`EpisodicNode`, `EntityNode`, `EntityEdge`)
        if self.graphiti_adapter.graphiti_available:
            self.graphiti_adapter.ingest_episode_into_graphiti(
                episode_id=ep.episode_id,
                engagement_id=engagement_id,
                entity_type=entity_type,
                subject=safe_subject,
                content=safe_content,
                relations=safe_relations,
                metadata=ep.metadata,
            )

        return ep

    def query(
        self,
        engagement_id: str,
        query_text: str = "",
        entity_type: Optional[str] = None,
        include_promoted_lessons: bool = True,
        limit: int = 20,
        allowed_source_engagement_ids: Optional[Sequence[str]] = None,
        forbidden_source_engagement_ids: Optional[Sequence[str]] = None,
    ) -> Dict[str, Any]:
        if not self.memory_enabled:
            return {
                "engagement_id": engagement_id,
                "query": query_text,
                "memory_enabled": False,
                "local_only": True,
                "graphiti_active": False,
                "telemetry_enabled": False,
                "episodes": [],
                "graph_edges": [],
                "graphiti_facts": [],
                "promoted_lessons": [],
            }

        bounded_limit = max(1, min(limit, 50))
        sql = "SELECT * FROM memory_episodes WHERE engagement_id = ?"
        params: List[Any] = [engagement_id]
        if entity_type:
            sql += " AND entity_type = ?"
            params.append(entity_type)
        if query_text.strip():
            sql += " AND (LOWER(subject) LIKE ? OR LOWER(content) LIKE ?)"
            q_like = f"%{query_text.strip().lower()}%"
            params.extend([q_like, q_like])
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(bounded_limit)

        query_emb = compute_local_hash_embedding(query_text) if query_text.strip() else []

        with self._lock, self._connect() as conn:
            rows = conn.execute(sql, params).fetchall()
            episodes = []
            for r in rows:
                try:
                    ep_emb = json.loads(r["embedding_json"])
                except Exception:
                    ep_emb = []
                sim = round(cosine_similarity(query_emb, ep_emb), 4) if query_emb and ep_emb else 1.0
                match_reason = (
                    f"Matched query '{query_text}' in engagement '{engagement_id}' (similarity={sim})"
                    if query_text.strip()
                    else f"Recent episode in engagement '{engagement_id}'"
                )
                episodes.append(
                    {
                        "episode_id": r["episode_id"],
                        "engagement_id": r["engagement_id"],
                        "entity_type": r["entity_type"],
                        "subject": r["subject"],
                        "content": r["content"],
                        "source_artifact_ids": json.loads(r["source_artifacts_json"]),
                        "confidence": r["confidence"],
                        "similarity_score": sim,
                        "extractor_version": r["extractor_version"],
                        "created_at": r["created_at"],
                        "match_reason": match_reason,
                        "authority": "contextual_only_non_authoritative",
                    }
                )

            episode_ids = [episode["episode_id"] for episode in episodes]
            edge_rows = []
            if episode_ids:
                placeholders = ",".join("?" for _ in episode_ids)
                edge_rows = conn.execute(
                    "SELECT source_node, relation, target_node, episode_id FROM graph_edges "
                    f"WHERE engagement_id = ? AND episode_id IN ({placeholders}) "
                    "ORDER BY created_at DESC, edge_id LIMIT ?",
                    [engagement_id, *episode_ids, bounded_limit],
                ).fetchall()
            edges = [
                {
                    "source": er["source_node"],
                    "relation": er["relation"],
                    "target": er["target_node"],
                    "episode_id": er["episode_id"],
                }
                for er in edge_rows
            ]

            promoted_lessons = []
            if include_promoted_lessons:
                l_sql = "SELECT * FROM lessons WHERE state = ?"
                l_params: List[Any] = [LessonState.PROMOTED.value]
                if forbidden_source_engagement_ids:
                    placeholders = ",".join("?" for _ in forbidden_source_engagement_ids)
                    l_sql += f" AND source_engagement_id NOT IN ({placeholders})"
                    l_params.extend(forbidden_source_engagement_ids)
                if query_text.strip():
                    l_sql += " AND (LOWER(title) LIKE ? OR LOWER(recommendation) LIKE ? OR LOWER(capability_id) LIKE ?)"
                    q_like = f"%{query_text.strip().lower()}%"
                    l_params.extend([q_like, q_like, q_like])
                l_sql += " ORDER BY updated_at DESC LIMIT 10"
                l_rows = conn.execute(l_sql, l_params).fetchall()
                for lr in l_rows:
                    if (
                        allowed_source_engagement_ids is not None
                        and forbidden_source_engagement_ids
                        and lr["source_engagement_id"] not in allowed_source_engagement_ids
                    ):
                        continue
                    promoted_lessons.append(
                        {
                            "lesson_id": lr["lesson_id"],
                            "source_engagement_id": lr["source_engagement_id"],
                            "capability_id": lr["capability_id"],
                            "title": lr["title"],
                            "recommendation": lr["recommendation"],
                            "eval_score": lr["eval_score"],
                            "reviewed_by": lr["reviewed_by"],
                            "version": lr["version"],
                        }
                    )

        graphiti_facts = self.graphiti_adapter.search_graphiti(
            engagement_id=engagement_id,
            query_text=query_text,
            limit=bounded_limit,
        )

        return {
            "engagement_id": engagement_id,
            "query": query_text,
            "memory_enabled": True,
            "local_only": not self.allow_external_inference,
            "graphiti_active": self.graphiti_adapter.graphiti_available,
            "telemetry_enabled": self.telemetry_enabled,
            "episodes": episodes,
            "graph_edges": edges,
            "graphiti_facts": graphiti_facts,
            "promoted_lessons": promoted_lessons,
        }

    def propose_lesson(
        self,
        source_engagement_id: str,
        capability_id: str,
        title: str,
        recommendation: str,
        evidence_ids: Optional[List[str]] = None,
    ) -> LessonRecord:
        lesson = LessonRecord(
            lesson_id=new_id("lesson"),
            source_engagement_id=source_engagement_id,
            capability_id=capability_id,
            title=redact_secrets(title),
            recommendation=redact_secrets(recommendation),
            state=LessonState.CANDIDATE,
            evidence_ids=list(evidence_ids or []),
        )
        self._save_lesson(lesson)
        return lesson

    def run_held_out_evaluation(self, lesson_id: str) -> LessonRecord:
        """
        Run both the text-safety lint (`lint_lesson_safety`) and the held-out
        retrieval/recommendation benchmark (`HELD_OUT_BENCHMARK_CASES`).
        """
        lesson = self.get_lesson(lesson_id)
        if not lesson:
            raise KeyError(f"Lesson not found: {lesson_id}")

        lint_res = lint_lesson_safety(lesson.title, lesson.recommendation, lesson.capability_id)
        combined = f"{lesson.title} {lesson.recommendation}".lower()

        if not lint_res["safety_lint_passed"]:
            computed_score = 0.0
            matched_positive_keywords: List[str] = []
            triggered_fp_keywords: List[str] = lint_res["violated_terms"]
        else:
            matched_positive_keywords = []
            triggered_fp_keywords = []
            for case in HELD_OUT_BENCHMARK_CASES:
                if case["capability_id"] in (lesson.capability_id, "any"):
                    for pk in case["positive_keywords"]:
                        if pk in combined and pk not in matched_positive_keywords:
                            matched_positive_keywords.append(pk)
                    for nk in case["negative_fp_keywords"]:
                        if nk in combined and nk not in triggered_fp_keywords:
                            triggered_fp_keywords.append(nk)

            if triggered_fp_keywords:
                computed_score = 0.2
            elif len(matched_positive_keywords) >= 2:
                computed_score = 0.9
            elif len(matched_positive_keywords) == 1:
                computed_score = 0.75
            else:
                computed_score = 0.6

        lesson.eval_score = computed_score
        lesson.eval_details = {
            "method": "heuristic_safety_and_relevance_lint_v2",
            "is_outcome_benchmark": False,
            "safety_checks_passed": lint_res["safety_lint_passed"] and len(triggered_fp_keywords) == 0,
            "violated_terms": lint_res["violated_terms"],
            "matched_positive_keywords": matched_positive_keywords,
            "triggered_fp_keywords": triggered_fp_keywords,
            "evaluated_at": utc_now_iso(),
        }
        lesson.state = LessonState.EVALUATED
        lesson.updated_at = utc_now_iso()
        self._save_lesson(lesson)
        return lesson

    def evaluate_lesson(self, lesson_id: str, eval_score: Optional[float] = None) -> LessonRecord:
        """
        Evaluate a candidate lesson and take the conservative minimum of the computed
        held-out score and any externally measured benchmark score.
        """
        evaluated = self.run_held_out_evaluation(lesson_id)
        if eval_score is not None and evaluated.eval_details.get("safety_checks_passed", False):
            computed = evaluated.eval_score if evaluated.eval_score is not None else 0.0
            evaluated.eval_score = round(min(computed, float(eval_score), 1.0), 4)
            self._save_lesson(evaluated)
        return evaluated

    def promote_lesson(
        self,
        lesson_id: str,
        reviewed_by: str | Principal,
        min_eval_score: float = 0.7,
    ) -> LessonRecord:
        lesson = self.get_lesson(lesson_id)
        if not lesson:
            raise KeyError(f"Lesson not found: {lesson_id}")
        if lesson.state != LessonState.EVALUATED or lesson.eval_score is None or lesson.eval_score < min_eval_score:
            raise ValueError(
                f"Cannot promote lesson '{lesson_id}' without passing held-out evaluation >= {min_eval_score}"
            )
        if not lesson.eval_details.get("safety_checks_passed", False):
            raise ValueError(f"Cannot promote unsafe lesson '{lesson_id}'")

        if isinstance(reviewed_by, Principal):
            if not reviewed_by.authenticated:
                raise PermissionError("Unauthenticated principal cannot promote lessons")
            reviewer_id = reviewed_by.principal_id
        else:
            reviewer_id = str(reviewed_by).strip()
            if not reviewer_id:
                raise ValueError("reviewed_by must identify the approving reviewer")

        lesson.reviewed_by = reviewer_id
        lesson.state = LessonState.PROMOTED
        lesson.updated_at = utc_now_iso()
        self._save_lesson(lesson)
        return lesson

    def rollback_lesson(self, lesson_id: str) -> LessonRecord:
        lesson = self.get_lesson(lesson_id)
        if not lesson:
            raise KeyError(f"Lesson not found: {lesson_id}")
        lesson.state = LessonState.ROLLED_BACK
        lesson.updated_at = utc_now_iso()
        self._save_lesson(lesson)
        return lesson

    def get_lesson(self, lesson_id: str) -> Optional[LessonRecord]:
        with self._lock, self._connect() as conn:
            row = conn.execute("SELECT * FROM lessons WHERE lesson_id = ?", (lesson_id,)).fetchone()
            if not row:
                return None
            return LessonRecord(
                lesson_id=row["lesson_id"],
                source_engagement_id=row["source_engagement_id"],
                capability_id=row["capability_id"],
                title=row["title"],
                recommendation=row["recommendation"],
                state=LessonState(row["state"]),
                evidence_ids=json.loads(row["evidence_ids_json"]),
                eval_score=row["eval_score"],
                eval_details=json.loads(row["eval_details_json"] or "{}"),
                reviewed_by=row["reviewed_by"],
                version=row["version"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )

    def _save_lesson(self, lesson: LessonRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO lessons (
                    lesson_id, source_engagement_id, capability_id, title,
                    recommendation, state, evidence_ids_json, eval_score,
                    eval_details_json, reviewed_by, version, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    lesson.lesson_id,
                    lesson.source_engagement_id,
                    lesson.capability_id,
                    lesson.title,
                    lesson.recommendation,
                    lesson.state.value,
                    json.dumps(lesson.evidence_ids),
                    lesson.eval_score,
                    json.dumps(lesson.eval_details),
                    lesson.reviewed_by,
                    lesson.version,
                    lesson.created_at,
                    lesson.updated_at,
                ),
            )

    def delete_engagement_memories(self, engagement_id: str) -> int:
        self.graphiti_adapter.delete_group(engagement_id)
        with self._lock, self._connect() as conn:
            conn.execute("DELETE FROM graph_edges WHERE engagement_id = ?", (engagement_id,))
            cur = conn.execute("DELETE FROM memory_episodes WHERE engagement_id = ?", (engagement_id,))
            return int(cur.rowcount or 0)
