"""Read-only Cypher subset evaluated against local graph records."""

from __future__ import annotations

import json

from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from hexstrike.memory.store import LocalGraphitiAdapter


class _SqliteCypherEvaluator:
    """
    Deterministic, grammar-parsed Cypher subset evaluator for the SQLite GraphDriver.
    Supported grammar:
      1. Literal/parameter projection:
         `RETURN <expr> [AS <alias>] (, <expr> [AS <alias>])* [LIMIT <n>]`
      2. Single-node or directed single-edge pattern query:
         `MATCH (<var>[:<Label>] [{...}]) [WHERE <bool_expr>] RETURN [DISTINCT] <items> [ORDER BY <expr> [ASC|DESC]] [LIMIT <n>]`
         `MATCH (<src>[:<Label>])-[<rel>[:<Label>]]->(<dst>[:<Label>]) [WHERE <bool_expr>] RETURN [DISTINCT] <items> [ORDER BY ...] [LIMIT <n>]`
    Any query outside this grammar raises `ValueError` (if not valid Cypher syntax) or
    `NotImplementedError` (if using unsupported Cypher clauses, patterns, or functions).
    """

    _CYPHER_STARTERS = frozenset(
        {"MATCH", "RETURN", "OPTIONAL", "WITH", "UNWIND", "CREATE", "MERGE", "DELETE", "DETACH", "SET", "CALL", "DROP"}
    )
    _UNSUPPORTED_CLAUSES = frozenset(
        {"OPTIONAL", "WITH", "UNWIND", "CREATE", "MERGE", "DELETE", "DETACH", "SET", "REMOVE", "CALL", "FOREACH", "UNION", "LOAD", "DROP"}
    )
    _CLAUSE_KEYWORDS = frozenset({"MATCH", "WHERE", "RETURN", "ORDER", "LIMIT", "SKIP"})

    @classmethod
    def tokenize(cls, query: str) -> List[Tuple[str, str]]:
        tokens: List[Tuple[str, str]] = []
        i = 0
        n = len(query)
        while i < n:
            ch = query[i]
            if ch.isspace():
                i += 1
                continue
            if ch in ("'", '"'):
                quote = ch
                i += 1
                buf: List[str] = []
                while i < n and query[i] != quote:
                    if query[i] == "\\" and i + 1 < n:
                        i += 1
                        buf.append(query[i])
                    else:
                        buf.append(query[i])
                    i += 1
                if i >= n or query[i] != quote:
                    raise ValueError("Unterminated string literal in Cypher query")
                i += 1
                tokens.append(("STRING", "".join(buf)))
                continue
            if query[i : i + 2] in ("->", "<-", "<=", ">=", "<>", "!="):
                op2 = query[i : i + 2]
                tokens.append(("ARROW" if op2 in ("->", "<-") else "OP", op2))
                i += 2
                continue
            if ch == "$":
                i += 1
                start = i
                while i < n and (query[i].isalnum() or query[i] == "_"):
                    i += 1
                if start == i:
                    raise ValueError("Empty parameter name '$' in Cypher query")
                tokens.append(("PARAM", query[start:i]))
                continue
            if ch.isdigit() or (ch == "-" and i + 1 < n and query[i + 1].isdigit()):
                start = i
                if ch == "-":
                    i += 1
                has_dot = False
                while i < n and (query[i].isdigit() or (query[i] == "." and not has_dot)):
                    if query[i] == ".":
                        has_dot = True
                    i += 1
                num_str = query[start:i]
                tokens.append(("FLOAT" if has_dot else "INT", num_str))
                continue
            if ch.isalpha() or ch == "_":
                start = i
                while i < n and (query[i].isalnum() or query[i] == "_"):
                    i += 1
                tokens.append(("WORD", query[start:i]))
                continue
            if ch in ("=", "<", ">", ".", ",", ":", ";", "(", ")", "[", "]", "{", "}", "-", "*"):
                tokens.append(("OP", ch))
                i += 1
                continue
            raise ValueError(f"Unsupported character '{ch}' in Cypher query")
        while tokens and tokens[-1] == ("OP", ";"):
            tokens.pop()
        return tokens

    @classmethod
    def execute(
        cls,
        adapter: "LocalGraphitiAdapter",
        cypher_query: str,
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        q_raw = (cypher_query or "").strip()
        if not q_raw:
            raise ValueError("Cypher query cannot be empty")
        tokens = cls.tokenize(q_raw)
        if not tokens:
            raise ValueError("Cypher query cannot be empty")

        first_type, first_val = tokens[0]
        if first_type != "WORD" or first_val.upper() not in cls._CYPHER_STARTERS:
            raise ValueError(f"Unsupported or invalid Cypher query syntax: {cypher_query[:120]}")

        for t_type, t_val in tokens:
            if t_type == "WORD" and t_val.upper() in cls._UNSUPPORTED_CLAUSES:
                raise NotImplementedError(
                    f"Cypher clause '{t_val.upper()}' is not supported by the constrained SQLite GraphDriver"
                )

        if first_val.upper() == "RETURN":
            return cls._eval_return_only(tokens[1:], params)

        if first_val.upper() != "MATCH":
            raise NotImplementedError(f"Unsupported Cypher starter '{first_val}' in constrained SQLite GraphDriver")

        # Locate top-level WHERE, RETURN, ORDER BY, LIMIT outside parentheses/brackets/braces
        depth = 0
        where_idx: Optional[int] = None
        return_idx: Optional[int] = None
        order_idx: Optional[int] = None
        limit_idx: Optional[int] = None

        i = 1
        while i < len(tokens):
            tt, tv = tokens[i]
            if tt == "OP" and tv in ("(", "[", "{"):
                depth += 1
            elif tt == "OP" and tv in (")", "]", "}"):
                depth = max(0, depth - 1)
            elif depth == 0 and tt == "WORD":
                kw = tv.upper()
                if kw == "WHERE" and where_idx is None and return_idx is None:
                    where_idx = i
                elif kw == "RETURN" and return_idx is None:
                    return_idx = i
                elif kw == "ORDER" and return_idx is not None and order_idx is None:
                    if i + 1 < len(tokens) and tokens[i + 1][0] == "WORD" and tokens[i + 1][1].upper() == "BY":
                        order_idx = i
                        i += 1
                    else:
                        raise NotImplementedError("Malformed ORDER BY clause")
                elif kw == "LIMIT" and return_idx is not None and limit_idx is None:
                    limit_idx = i
                elif kw in ("MATCH", "SKIP"):
                    raise NotImplementedError(f"Unsupported multiple/extra clause '{kw}' in constrained SQLite GraphDriver")
            i += 1

        if return_idx is None:
            raise NotImplementedError("MATCH query without RETURN is not supported in constrained SQLite GraphDriver")

        pattern_end = where_idx if where_idx is not None else return_idx
        pattern_tokens = tokens[1:pattern_end]
        where_tokens = tokens[where_idx + 1 : return_idx] if where_idx is not None else []

        ret_end = order_idx if order_idx is not None else (limit_idx if limit_idx is not None else len(tokens))
        return_tokens = tokens[return_idx + 1 : ret_end]

        order_tokens: List[Tuple[str, str]] = []
        if order_idx is not None:
            ord_end = limit_idx if limit_idx is not None else len(tokens)
            order_tokens = tokens[order_idx + 2 : ord_end]

        limit_val: Optional[int] = None
        if limit_idx is not None:
            lim_tokens = tokens[limit_idx + 1 :]
            if len(lim_tokens) != 1:
                raise NotImplementedError("Complex LIMIT expression is not supported")
            l_val = cls._eval_single_value_tokens(lim_tokens, {}, set(), params)
            if not isinstance(l_val, int) or isinstance(l_val, bool):
                raise ValueError("LIMIT value must be an integer")
            limit_val = max(0, l_val)

        candidate_bindings, bound_vars = cls._load_pattern_candidates(adapter, pattern_tokens, params)

        if where_tokens:
            pred_fn = cls._compile_where(where_tokens, bound_vars, params)
            filtered_bindings = [b for b in candidate_bindings if pred_fn(b)]
        else:
            filtered_bindings = candidate_bindings

        if order_tokens:
            filtered_bindings = cls._apply_order_by(filtered_bindings, order_tokens, bound_vars, params)

        rows = cls._project_return(filtered_bindings, return_tokens, bound_vars, params)
        if limit_val is not None:
            rows = rows[:limit_val]
        return rows

    @classmethod
    def _parse_node_spec(
        cls, tokens: List[Tuple[str, str]], start: int, params: Dict[str, Any]
    ) -> Tuple[Optional[str], Optional[str], Dict[str, Any], int]:
        if start >= len(tokens) or tokens[start] != ("OP", "("):
            raise NotImplementedError("Expected '(' in MATCH node pattern")
        idx = start + 1
        var_name: Optional[str] = None
        label_name: Optional[str] = None
        inline_props: Dict[str, Any] = {}

        if idx < len(tokens) and tokens[idx][0] == "WORD":
            var_name = tokens[idx][1]
            idx += 1
        if idx < len(tokens) and tokens[idx] == ("OP", ":"):
            idx += 1
            if idx >= len(tokens) or tokens[idx][0] != "WORD":
                raise NotImplementedError("Expected label identifier after ':' in MATCH pattern")
            label_name = tokens[idx][1]
            idx += 1
        if idx < len(tokens) and tokens[idx] == ("OP", "{"):
            idx += 1
            while idx < len(tokens) and tokens[idx] != ("OP", "}"):
                if tokens[idx][0] != "WORD":
                    raise NotImplementedError("Expected property key in inline pattern map")
                prop_key = tokens[idx][1]
                idx += 1
                if idx >= len(tokens) or tokens[idx] != ("OP", ":"):
                    raise NotImplementedError("Expected ':' after property key in inline pattern map")
                idx += 1
                val_toks: List[Tuple[str, str]] = []
                while idx < len(tokens) and tokens[idx] not in (("OP", ","), ("OP", "}")):
                    val_toks.append(tokens[idx])
                    idx += 1
                inline_props[prop_key] = cls._eval_single_value_tokens(val_toks, {}, set(), params)
                if idx < len(tokens) and tokens[idx] == ("OP", ","):
                    idx += 1
            if idx >= len(tokens) or tokens[idx] != ("OP", "}"):
                raise NotImplementedError("Unterminated '{' in MATCH pattern")
            idx += 1
        if idx >= len(tokens) or tokens[idx] != ("OP", ")"):
            raise NotImplementedError("Unsupported or malformed node pattern in MATCH")
        return var_name, label_name, inline_props, idx + 1

    @classmethod
    def _matches_inline_props(cls, entity: Dict[str, Any], inline_props: Dict[str, Any]) -> bool:
        for k, v in inline_props.items():
            if entity.get(k) != v:
                return False
        return True

    @classmethod
    def _load_pattern_candidates(
        cls,
        adapter: "LocalGraphitiAdapter",
        pattern_tokens: List[Tuple[str, str]],
        params: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Dict[str, Any]]], set[str]]:
        if not pattern_tokens:
            raise NotImplementedError("Empty MATCH pattern")

        src_var, src_label, src_props, next_idx = cls._parse_node_spec(pattern_tokens, 0, params)

        group_id = params.get("group_id")
        group_ids: Optional[List[str]] = params.get("group_ids") or ([str(group_id)] if group_id else None)

        # Case 1: Single node pattern `MATCH (n[:Label] [{...}])`
        if next_idx == len(pattern_tokens):
            bound = {src_var} if src_var else set()
            records = cls._fetch_entities_by_label(adapter, src_label, group_ids, params)
            out: List[Dict[str, Dict[str, Any]]] = []
            for rec in records:
                if cls._matches_inline_props(rec, src_props):
                    out.append({src_var or "_anon_node": rec})
            return out, bound

        # Case 2: Directed relationship pattern `(src)-[rel[:Label] [{...}]]->(dst)`
        if (
            next_idx + 1 < len(pattern_tokens)
            and pattern_tokens[next_idx] == ("OP", "-")
            and pattern_tokens[next_idx + 1] == ("OP", "[")
        ):
            idx = next_idx + 2
            rel_var: Optional[str] = None
            rel_label: Optional[str] = None
            rel_props: Dict[str, Any] = {}
            if idx < len(pattern_tokens) and pattern_tokens[idx][0] == "WORD":
                rel_var = pattern_tokens[idx][1]
                idx += 1
            if idx < len(pattern_tokens) and pattern_tokens[idx] == ("OP", ":"):
                idx += 1
                if idx >= len(pattern_tokens) or pattern_tokens[idx][0] != "WORD":
                    raise NotImplementedError("Expected relationship type after ':'")
                rel_label = pattern_tokens[idx][1]
                idx += 1
            if idx < len(pattern_tokens) and pattern_tokens[idx] == ("OP", "{"):
                idx += 1
                while idx < len(pattern_tokens) and pattern_tokens[idx] != ("OP", "}"):
                    if pattern_tokens[idx][0] != "WORD":
                        raise NotImplementedError("Expected property name in relationship map")
                    pk = pattern_tokens[idx][1]
                    idx += 1
                    if idx >= len(pattern_tokens) or pattern_tokens[idx] != ("OP", ":"):
                        raise NotImplementedError("Expected ':' in relationship property map")
                    idx += 1
                    vtoks: List[Tuple[str, str]] = []
                    while idx < len(pattern_tokens) and pattern_tokens[idx] not in (("OP", ","), ("OP", "}")):
                        vtoks.append(pattern_tokens[idx])
                        idx += 1
                    rel_props[pk] = cls._eval_single_value_tokens(vtoks, {}, set(), params)
                    if idx < len(pattern_tokens) and pattern_tokens[idx] == ("OP", ","):
                        idx += 1
                if idx >= len(pattern_tokens) or pattern_tokens[idx] != ("OP", "}"):
                    raise NotImplementedError("Unterminated '{' in relationship pattern")
                idx += 1
            if (
                idx + 1 >= len(pattern_tokens)
                or pattern_tokens[idx] != ("OP", "]")
                or pattern_tokens[idx + 1] != ("ARROW", "->")
            ):
                raise NotImplementedError("Only single-hop directed '-[...]->' relationships are supported")
            idx += 2
            dst_var, dst_label, dst_props, end_idx = cls._parse_node_spec(pattern_tokens, idx, params)
            if end_idx != len(pattern_tokens):
                raise NotImplementedError("Multi-hop or compound MATCH patterns are not supported")

            bound_vars = {v for v in (src_var, rel_var, dst_var) if v}
            edges = cls._fetch_entities_by_label(adapter, "Edge", group_ids, params)
            nodes_list = cls._fetch_entities_by_label(adapter, "Entity", group_ids, params)
            nodes_by_uuid = {n["uuid"]: n for n in nodes_list}

            joined: List[Dict[str, Dict[str, Any]]] = []
            for e in edges:
                if rel_label and rel_label.upper() not in ("RELATES_TO", e.get("name", "").upper()):
                    continue
                if not cls._matches_inline_props(e, rel_props):
                    continue
                s_node = nodes_by_uuid.get(e["source_node_uuid"], {"uuid": e["source_node_uuid"], "name": e["source_node_uuid"], "group_id": e["group_id"]})
                t_node = nodes_by_uuid.get(e["target_node_uuid"], {"uuid": e["target_node_uuid"], "name": e["target_node_uuid"], "group_id": e["group_id"]})
                if src_label and src_label not in s_node.get("labels", ["Entity"]):
                    continue
                if dst_label and dst_label not in t_node.get("labels", ["Entity"]):
                    continue
                if not cls._matches_inline_props(s_node, src_props) or not cls._matches_inline_props(t_node, dst_props):
                    continue
                row_b: Dict[str, Dict[str, Any]] = {}
                if src_var:
                    row_b[src_var] = s_node
                if rel_var:
                    row_b[rel_var] = e
                if dst_var:
                    row_b[dst_var] = t_node
                joined.append(row_b)
            return joined, bound_vars

        raise NotImplementedError("Unsupported MATCH pattern in constrained SQLite GraphDriver")

    @classmethod
    def _fetch_entities_by_label(
        cls,
        adapter: "LocalGraphitiAdapter",
        label: Optional[str],
        group_ids: Optional[List[str]],
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        lbl = (label or "").lower()
        # Query parameters do not imply predicates or LIMIT clauses. Candidate
        # loading must be complete before filtering, ordering, and aggregation.
        query_filter = ""
        limit = None

        if lbl in ("episodic", "episodicnode", "episode"):
            sql = "SELECT * FROM graphiti_episodic_nodes WHERE 1=1"
            q_params: List[Any] = []
            if group_ids:
                sql += f" AND group_id IN ({','.join('?' for _ in group_ids)})"
                q_params.extend(group_ids)
            sql += " ORDER BY created_at DESC"
            with adapter._lock, adapter._connect() as conn:
                rows = conn.execute(sql, q_params).fetchall()
            return [
                {
                    "uuid": r["uuid"],
                    "name": r["name"],
                    "group_id": r["group_id"],
                    "content": r["content"],
                    "fact": r["content"],
                    "source": r["source"],
                    "source_description": r["source_description"],
                    "created_at": r["created_at"],
                    "labels": ["Episodic"],
                }
                for r in rows
            ]

        if lbl in ("entity", "entitynode", "node"):
            nodes = adapter._search_entity_nodes(query=query_filter, group_ids=group_ids, limit=limit)
            out_nodes: List[Dict[str, Any]] = []
            for n in nodes:
                attrs = dict(n.attributes or {})
                out_nodes.append(
                    {
                        **attrs,
                        "uuid": n.uuid,
                        "name": n.name,
                        "summary": n.summary,
                        "fact": n.summary,
                        "group_id": n.group_id,
                        "labels": list(n.labels or ["Entity"]),
                        "created_at": n.created_at.isoformat() if hasattr(n.created_at, "isoformat") else str(n.created_at),
                    }
                )
            return out_nodes

        edges = adapter._search_entity_edges(query=query_filter, group_ids=group_ids, limit=limit)
        out_edges: List[Dict[str, Any]] = []
        for e in edges:
            attrs = dict(e.attributes or {})
            out_edges.append(
                {
                    **attrs,
                    "uuid": e.uuid,
                    "name": e.name,
                    "fact": e.fact,
                    "summary": e.fact,
                    "group_id": e.group_id,
                    "source_node_uuid": e.source_node_uuid,
                    "target_node_uuid": e.target_node_uuid,
                    "labels": ["EntityEdge", e.name],
                    "created_at": e.created_at.isoformat() if hasattr(e.created_at, "isoformat") else str(e.created_at),
                }
            )
        if not lbl and not out_edges:
            return cls._fetch_entities_by_label(adapter, "Entity", group_ids, params)
        return out_edges

    @classmethod
    def _compile_where(
        cls,
        where_tokens: List[Tuple[str, str]],
        bound_vars: set[str],
        params: Dict[str, Any],
    ) -> Any:
        pos = 0

        def peek() -> Optional[Tuple[str, str]]:
            return where_tokens[pos] if pos < len(where_tokens) else None

        def consume() -> Tuple[str, str]:
            nonlocal pos
            tok = where_tokens[pos]
            pos += 1
            return tok

        def parse_or() -> Any:
            left = parse_and()
            while peek() is not None and peek()[0] == "WORD" and peek()[1].upper() == "OR":
                consume()
                right = parse_and()
                prev_left = left
                left = lambda b, l=prev_left, r=right: bool(l(b)) or bool(r(b))
            return left

        def parse_and() -> Any:
            left = parse_not()
            while peek() is not None and peek()[0] == "WORD" and peek()[1].upper() == "AND":
                consume()
                right = parse_not()
                prev_left = left
                left = lambda b, l=prev_left, r=right: bool(l(b)) and bool(r(b))
            return left

        def parse_not() -> Any:
            if peek() is not None and peek()[0] == "WORD" and peek()[1].upper() == "NOT":
                consume()
                inner = parse_not()
                return lambda b, fn=inner: not bool(fn(b))
            return parse_primary()

        def parse_primary() -> Any:
            if peek() == ("OP", "("):
                consume()
                expr = parse_or()
                if peek() != ("OP", ")"):
                    raise NotImplementedError("Unclosed '(' in WHERE clause")
                consume()
                return expr

            lhs_fn = parse_val_expr()
            nxt = peek()
            if nxt is None or (nxt[0] == "WORD" and nxt[1].upper() in ("AND", "OR")) or nxt == ("OP", ")"):
                def _eval_bool(b: Dict[str, Dict[str, Any]], fn: Any = lhs_fn) -> bool:
                    v = fn(b)
                    if not isinstance(v, bool):
                        raise NotImplementedError(f"Non-boolean standalone expression in WHERE: {v!r}")
                    return v
                return _eval_bool

            if nxt[0] == "WORD" and nxt[1].upper() == "IS":
                consume()
                is_not = False
                if peek() is not None and peek()[0] == "WORD" and peek()[1].upper() == "NOT":
                    consume()
                    is_not = True
                if peek() is None or peek()[0] != "WORD" or peek()[1].upper() != "NULL":
                    raise NotImplementedError("Expected NULL after IS [NOT] in WHERE clause")
                consume()
                return (lambda b, l=lhs_fn: l(b) is not None) if is_not else (lambda b, l=lhs_fn: l(b) is None)

            if nxt[0] == "WORD" and nxt[1].upper() == "IN":
                consume()
                rhs_fn = parse_val_expr()
                return lambda b, l=lhs_fn, r=rhs_fn: (r(b) is not None and l(b) in r(b))

            if nxt[0] == "WORD" and nxt[1].upper() == "CONTAINS":
                consume()
                rhs_fn = parse_val_expr()
                return lambda b, l=lhs_fn, r=rhs_fn: (
                    isinstance(l(b), str) and isinstance(r(b), str) and (r(b) in l(b))
                )

            if nxt[0] == "WORD" and nxt[1].upper() == "STARTS":
                consume()
                if peek() is None or peek()[0] != "WORD" or peek()[1].upper() != "WITH":
                    raise NotImplementedError("Expected WITH after STARTS in WHERE clause")
                consume()
                rhs_fn = parse_val_expr()
                return lambda b, l=lhs_fn, r=rhs_fn: (
                    isinstance(l(b), str) and isinstance(r(b), str) and l(b).startswith(r(b))
                )

            if nxt[0] == "WORD" and nxt[1].upper() == "ENDS":
                consume()
                if peek() is None or peek()[0] != "WORD" or peek()[1].upper() != "WITH":
                    raise NotImplementedError("Expected WITH after ENDS in WHERE clause")
                consume()
                rhs_fn = parse_val_expr()
                return lambda b, l=lhs_fn, r=rhs_fn: (
                    isinstance(l(b), str) and isinstance(r(b), str) and l(b).endswith(r(b))
                )

            if nxt[0] == "OP" and nxt[1] in ("=", "<>", "!=", "<", "<=", ">", ">="):
                op = consume()[1]
                rhs_fn = parse_val_expr()
                return lambda b, o=op, l=lhs_fn, r=rhs_fn: cls._compare_vals(o, l(b), r(b))

            raise NotImplementedError(f"Unsupported operator or token '{nxt[1]}' in WHERE clause")

        def parse_val_expr() -> Any:
            tok = peek()
            if tok is None:
                raise NotImplementedError("Unexpected end of expression in Cypher query")
            tt, tv = consume()
            if tt == "STRING":
                return lambda _b, v=tv: v
            if tt == "INT":
                return lambda _b, v=int(tv): v
            if tt == "FLOAT":
                return lambda _b, v=float(tv): v
            if tt == "PARAM":
                if tv not in params:
                    raise ValueError(f"Missing query parameter '${tv}'")
                return lambda _b, v=params[tv]: v
            if tt == "OP" and tv == "[":
                items_fns: List[Any] = []
                while peek() is not None and peek() != ("OP", "]"):
                    items_fns.append(parse_val_expr())
                    if peek() == ("OP", ","):
                        consume()
                if peek() != ("OP", "]"):
                    raise NotImplementedError("Unclosed '[' in list literal")
                consume()
                return lambda b, fns=items_fns: [fn(b) for fn in fns]
            if tt == "WORD":
                up = tv.upper()
                if up == "TRUE":
                    return lambda _b: True
                if up == "FALSE":
                    return lambda _b: False
                if up == "NULL":
                    return lambda _b: None
                if peek() == ("OP", "("):
                    consume()
                    arg_fns: List[Any] = []
                    while peek() is not None and peek() != ("OP", ")"):
                        arg_fns.append(parse_val_expr())
                        if peek() == ("OP", ","):
                            consume()
                    if peek() != ("OP", ")"):
                        raise NotImplementedError(f"Unclosed '(' in function '{tv}'")
                    consume()
                    return cls._compile_scalar_func(up, arg_fns)
                if peek() == ("OP", "."):
                    consume()
                    prop_tok = peek()
                    if prop_tok is None or prop_tok[0] != "WORD":
                        raise NotImplementedError(f"Expected property name after '{tv}.'")
                    prop_name = consume()[1]
                    if tv not in bound_vars:
                        raise NotImplementedError(f"Unbound pattern variable '{tv}' in property access '{tv}.{prop_name}'")
                    return lambda b, vname=tv, pname=prop_name: (b.get(vname) or {}).get(pname)
                if tv not in bound_vars:
                    raise NotImplementedError(f"Unbound identifier or unsupported keyword '{tv}' in Cypher expression")
                return lambda b, vname=tv: b.get(vname)

            raise NotImplementedError(f"Unsupported value token '{tv}' in Cypher expression")

        pred = parse_or()
        if pos != len(where_tokens):
            raise NotImplementedError(f"Unsupported trailing syntax in WHERE clause near '{where_tokens[pos][1]}'")
        return pred

    @classmethod
    def _compile_scalar_func(cls, func_upper: str, arg_fns: List[Any]) -> Any:
        if func_upper in ("LOWER", "TOLOWER") and len(arg_fns) == 1:
            return lambda b, fn=arg_fns[0]: str(fn(b)).lower() if fn(b) is not None else None
        if func_upper in ("UPPER", "TOUPPER") and len(arg_fns) == 1:
            return lambda b, fn=arg_fns[0]: str(fn(b)).upper() if fn(b) is not None else None
        if func_upper == "TOSTRING" and len(arg_fns) == 1:
            return lambda b, fn=arg_fns[0]: str(fn(b)) if fn(b) is not None else None
        if func_upper in ("TOINTEGER", "TOINT") and len(arg_fns) == 1:
            return lambda b, fn=arg_fns[0]: int(fn(b)) if fn(b) is not None else None
        if func_upper == "SIZE" and len(arg_fns) == 1:
            return lambda b, fn=arg_fns[0]: len(fn(b)) if fn(b) is not None else 0
        if func_upper == "COALESCE" and len(arg_fns) >= 1:
            def _coal(b: Dict[str, Dict[str, Any]], fns: List[Any] = arg_fns) -> Any:
                for f in fns:
                    val = f(b)
                    if val is not None:
                        return val
                return None
            return _coal
        raise NotImplementedError(f"Cypher function '{func_upper}()' is not supported by constrained SQLite GraphDriver")

    @staticmethod
    def _compare_vals(op: str, a: Any, b: Any) -> bool:
        if a is None or b is None:
            return False
        if op == "=":
            return bool(a == b)
        if op in ("<>", "!="):
            return bool(a != b)
        try:
            if op == "<":
                return bool(a < b)
            if op == "<=":
                return bool(a <= b)
            if op == ">":
                return bool(a > b)
            if op == ">=":
                return bool(a >= b)
        except TypeError:
            return False
        return False

    @classmethod
    def _eval_single_value_tokens(
        cls,
        expr_tokens: List[Tuple[str, str]],
        binding: Dict[str, Dict[str, Any]],
        bound_vars: set[str],
        params: Dict[str, Any],
    ) -> Any:
        if not expr_tokens:
            raise NotImplementedError("Empty value expression in Cypher query")
        # Reuse the value parser from _compile_where by wrapping in an equality or direct evaluation
        pos = 0

        def peek() -> Optional[Tuple[str, str]]:
            return expr_tokens[pos] if pos < len(expr_tokens) else None

        def consume() -> Tuple[str, str]:
            nonlocal pos
            t = expr_tokens[pos]
            pos += 1
            return t

        tok = peek()
        assert tok is not None
        tt, tv = consume()
        if tt == "STRING":
            val: Any = tv
        elif tt == "INT":
            val = int(tv)
        elif tt == "FLOAT":
            val = float(tv)
        elif tt == "PARAM":
            if tv not in params:
                raise ValueError(f"Missing query parameter '${tv}'")
            val = params[tv]
        elif tt == "OP" and tv == "[":
            arr: List[Any] = []
            cur: List[Tuple[str, str]] = []
            depth = 0
            while peek() is not None:
                pt, pv = consume()
                if pt == "OP" and pv == "]" and depth == 0:
                    if cur:
                        arr.append(cls._eval_single_value_tokens(cur, binding, bound_vars, params))
                        cur = []
                    break
                if pt == "OP" and pv in ("(", "[", "{"):
                    depth += 1
                elif pt == "OP" and pv in (")", "]", "}"):
                    depth -= 1
                if pt == "OP" and pv == "," and depth == 0:
                    arr.append(cls._eval_single_value_tokens(cur, binding, bound_vars, params))
                    cur = []
                else:
                    cur.append((pt, pv))
            val = arr
        elif tt == "WORD":
            up = tv.upper()
            if up == "TRUE":
                val = True
            elif up == "FALSE":
                val = False
            elif up == "NULL":
                val = None
            elif peek() == ("OP", "."):
                consume()
                ptok = peek()
                if ptok is None or ptok[0] != "WORD":
                    raise NotImplementedError(f"Expected property name after '{tv}.'")
                pname = consume()[1]
                if tv not in bound_vars:
                    raise NotImplementedError(f"Unbound variable '{tv}' in '{tv}.{pname}'")
                val = (binding.get(tv) or {}).get(pname)
            elif peek() == ("OP", "("):
                consume()
                inner_toks: List[Tuple[str, str]] = []
                depth = 0
                while peek() is not None:
                    pt, pv = consume()
                    if pt == "OP" and pv == ")" and depth == 0:
                        break
                    if pt == "OP" and pv in ("(", "[", "{"):
                        depth += 1
                    elif pt == "OP" and pv in (")", "]", "}"):
                        depth -= 1
                    inner_toks.append((pt, pv))
                arg_fn = (
                    [lambda b, it=inner_toks: cls._eval_single_value_tokens(it, b, bound_vars, params)]
                    if inner_toks
                    else []
                )
                fn = cls._compile_scalar_func(up, arg_fn)
                val = fn(binding)
            elif tv in bound_vars:
                val = binding.get(tv)
            else:
                raise NotImplementedError(f"Unsupported or unbound expression '{tv}' in Cypher projection")
        else:
            raise NotImplementedError(f"Unsupported expression token '{tv}' in Cypher query")

        if pos != len(expr_tokens):
            raise NotImplementedError(f"Unsupported compound expression in Cypher near '{expr_tokens[pos][1]}'")
        return val

    @classmethod
    def _split_comma_items(cls, tokens: List[Tuple[str, str]]) -> List[List[Tuple[str, str]]]:
        items: List[List[Tuple[str, str]]] = []
        current: List[Tuple[str, str]] = []
        depth = 0
        for tt, tv in tokens:
            if tt == "OP" and tv in ("(", "[", "{"):
                depth += 1
            elif tt == "OP" and tv in (")", "]", "}"):
                depth = max(0, depth - 1)
            if tt == "OP" and tv == "," and depth == 0:
                if not current:
                    raise NotImplementedError("Empty item in comma-separated Cypher clause")
                items.append(current)
                current = []
            else:
                current.append((tt, tv))
        if current:
            items.append(current)
        return items

    @classmethod
    def _parse_return_item(cls, item_tokens: List[Tuple[str, str]]) -> Tuple[List[Tuple[str, str]], str, bool]:
        alias_idx: Optional[int] = None
        depth = 0
        for idx, (tt, tv) in enumerate(item_tokens):
            if tt == "OP" and tv in ("(", "[", "{"):
                depth += 1
            elif tt == "OP" and tv in (")", "]", "}"):
                depth = max(0, depth - 1)
            elif depth == 0 and tt == "WORD" and tv.upper() == "AS":
                alias_idx = idx
        if alias_idx is not None:
            if alias_idx + 1 != len(item_tokens) - 1 or item_tokens[alias_idx + 1][0] != "WORD":
                raise NotImplementedError("Expected single identifier after AS in RETURN clause")
            expr_toks = item_tokens[:alias_idx]
            alias = item_tokens[alias_idx + 1][1]
            return expr_toks, alias, True
        alias = "".join(tv for _, tv in item_tokens)
        return item_tokens, alias, False

    @classmethod
    def _eval_return_only(cls, tokens: List[Tuple[str, str]], params: Dict[str, Any]) -> List[Dict[str, Any]]:
        limit_val: Optional[int] = None
        depth = 0
        limit_idx: Optional[int] = None
        for i, (tt, tv) in enumerate(tokens):
            if tt == "OP" and tv in ("(", "[", "{"):
                depth += 1
            elif tt == "OP" and tv in (")", "]", "}"):
                depth = max(0, depth - 1)
            elif depth == 0 and tt == "WORD" and tv.upper() == "LIMIT":
                limit_idx = i
                break
        ret_tokens = tokens[:limit_idx] if limit_idx is not None else tokens
        if limit_idx is not None:
            lim_toks = tokens[limit_idx + 1 :]
            l_val = cls._eval_single_value_tokens(lim_toks, {}, set(), params)
            if not isinstance(l_val, int) or isinstance(l_val, bool):
                raise ValueError("LIMIT value must be an integer")
            limit_val = max(0, l_val)

        if ret_tokens and ret_tokens[0][0] == "WORD" and ret_tokens[0][1].upper() == "DISTINCT":
            ret_tokens = ret_tokens[1:]

        items = cls._split_comma_items(ret_tokens)
        if not items:
            raise NotImplementedError("Empty RETURN clause")
        row: Dict[str, Any] = {}
        for item in items:
            expr_toks, alias, _ = cls._parse_return_item(item)
            row[alias] = cls._eval_single_value_tokens(expr_toks, {}, set(), params)
        if limit_val == 0:
            return []
        return [row]

    @classmethod
    def _project_return(
        cls,
        bindings_list: List[Dict[str, Dict[str, Any]]],
        return_tokens: List[Tuple[str, str]],
        bound_vars: set[str],
        params: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        distinct = False
        if return_tokens and return_tokens[0][0] == "WORD" and return_tokens[0][1].upper() == "DISTINCT":
            distinct = True
            return_tokens = return_tokens[1:]
        items = cls._split_comma_items(return_tokens)
        if not items:
            raise NotImplementedError("Empty RETURN projection")

        parsed_items = [cls._parse_return_item(it) for it in items]

        # Check for COUNT(...) aggregation
        if len(parsed_items) == 1:
            etoks, alias, _ = parsed_items[0]
            if (
                len(etoks) >= 4
                and etoks[0][0] == "WORD"
                and etoks[0][1].upper() == "COUNT"
                and etoks[1] == ("OP", "(")
                and etoks[-1] == ("OP", ")")
            ):
                inner = etoks[2:-1]
                if inner == [("OP", "*")]:
                    return [{alias: len(bindings_list)}]
                if len(inner) == 1 and inner[0][0] == "WORD" and inner[0][1] in bound_vars:
                    vname = inner[0][1]
                    cnt = sum(1 for b in bindings_list if b.get(vname) is not None)
                    return [{alias: cnt}]
                raise NotImplementedError("Unsupported COUNT() argument in constrained SQLite GraphDriver")

        out_rows: List[Dict[str, Any]] = []
        seen_json: set[str] = set()
        for b in bindings_list:
            # Special compatibility case: `MATCH (n) ... RETURN n` (single bare variable without AS)
            if (
                len(parsed_items) == 1
                and not parsed_items[0][2]
                and len(parsed_items[0][0]) == 1
                and parsed_items[0][0][0][0] == "WORD"
                and parsed_items[0][0][0][1] in bound_vars
            ):
                vname = parsed_items[0][0][0][1]
                entity_dict = dict(b.get(vname) or {})
                row = {**entity_dict, vname: entity_dict}
            else:
                row = {}
                for expr_toks, alias, _ in parsed_items:
                    row[alias] = cls._eval_single_value_tokens(expr_toks, b, bound_vars, params)
            if distinct:
                key = json.dumps(row, sort_keys=True, default=str)
                if key in seen_json:
                    continue
                seen_json.add(key)
            out_rows.append(row)
        return out_rows

    @classmethod
    def _apply_order_by(
        cls,
        bindings_list: List[Dict[str, Dict[str, Any]]],
        order_tokens: List[Tuple[str, str]],
        bound_vars: set[str],
        params: Dict[str, Any],
    ) -> List[Dict[str, Dict[str, Any]]]:
        if not order_tokens:
            return bindings_list
        desc = False
        expr_toks = list(order_tokens)
        if expr_toks[-1][0] == "WORD" and expr_toks[-1][1].upper() in ("ASC", "DESC"):
            desc = expr_toks[-1][1].upper() == "DESC"
            expr_toks = expr_toks[:-1]
        return sorted(
            bindings_list,
            key=lambda b: (cls._eval_single_value_tokens(expr_toks, b, bound_vars, params) is None, cls._eval_single_value_tokens(expr_toks, b, bound_vars, params) or ""),
            reverse=desc,
        )
