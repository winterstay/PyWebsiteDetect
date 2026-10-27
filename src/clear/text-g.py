#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lxml import etree
import re, math, hashlib
import argparse
import sys
from pathlib import Path
from collections import defaultdict
from typing import Optional, Set, Dict, List


def process_text_collapsing(input_path: str, output_path: str):
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse(input_path, parser)
    root = tree.getroot()

    # ---- Build key maps (GraphML key id -> attr.name) ----
    node_keys: Dict[str, str] = {}
    edge_keys: Dict[str, str] = {}
    for k in root.findall("g:key", ns):
        k_for = k.get("for")
        kid = k.get("id")
        if not kid:
            continue
        if k_for == "node":
            node_keys[kid] = k.get("attr.name")
        elif k_for == "edge":
            edge_keys[kid] = k.get("attr.name")

    def data_get(elem, key_id: str) -> Optional[str]:
        for d in elem.findall("g:data", ns):
            if d.get("key") == key_id:
                return d.text
        return None

    def data_set(elem, key_id: str, value: str) -> None:
        # Update existing <data> or add new one
        for d in elem.findall("g:data", ns):
            if d.get("key") == key_id:
                d.text = value
                return
        d = etree.SubElement(elem, f"{{{ns['g']}}}data")
        d.set("key", key_id)
        d.text = value

    # Keys we rely on (from your file)
    NODE_TYPE_KEY = None
    NODE_TEXT_KEY = None
    EDGE_TYPE_KEY = None

    for kid, name in node_keys.items():
        if name == "node type":
            NODE_TYPE_KEY = kid
        if name == "text":
            NODE_TEXT_KEY = kid
    for kid, name in edge_keys.items():
        if name == "edge type":
            EDGE_TYPE_KEY = kid

    assert NODE_TYPE_KEY and NODE_TEXT_KEY and EDGE_TYPE_KEY, "Could not locate required keys in GraphML."

    graph = root.find("g:graph", ns)
    assert graph is not None, "Missing <graph> element"

    nodes = graph.findall("g:node", ns)
    edges = graph.findall("g:edge", ns)

    # Index nodes by id for fast access
    node_by_id = {n.get("id"): n for n in nodes if n.get("id") is not None}

    # Build incoming "document" parent map for DOM containment
    incoming_document_parent = defaultdict(list)

    # Also index in/out edges for rewiring/removal
    in_edges = defaultdict(list)
    out_edges = defaultdict(list)

    def edge_type(e) -> str:
        return (data_get(e, EDGE_TYPE_KEY) or "")

    for e in edges:
        eid = e.get("id")
        assert eid is not None, "Edge is missing id (assumption: edges always have id)"
        src = e.get("source")
        tgt = e.get("target")
        if src is None or tgt is None:
            continue
        etype = edge_type(e)
        in_edges[tgt].append(e)
        out_edges[src].append(e)
        if etype == "document":
            incoming_document_parent[tgt].append(src)

    def find_parent_non_text(node_id: str) -> Optional[str]:
        """Follow 'document' incoming edges to find nearest non-text node parent."""
        seen = set()
        cur = node_id
        while True:
            if cur in seen:
                return None
            seen.add(cur)
            parents = incoming_document_parent.get(cur, [])
            if not parents:
                return None
            p = parents[0]
            pnode = node_by_id.get(p)
            if pnode is None:
                return None
            ptype = data_get(pnode, NODE_TYPE_KEY) or ""
            if ptype != "text node":
                return p
            cur = p

    # ---- Suspicious text heuristics ----
    SUSPICIOUS_PATTERNS = [
        r"eval\s*\(",
        r"Function\s*\(",
        r"setTimeout\s*\(",
        r"setInterval\s*\(",
        r"atob\s*\(",
        r"btoa\s*\(",
        r"fromCharCode",
        r"unescape\s*\(",
        r"decodeURIComponent\s*\(",
        r"<\s*script\b",
        r"javascript\s*:",
        r"data\s*:\s*text/html",
        r"data\s*:\s*application/javascript",
        r"onerror\s*=",
        r"onload\s*=",
        r"srcdoc\s*=",
        r"location\.href",
        r"window\.open",
        r"%3cscript%3e",
        r"&#x3c;script",
        r"\\x3cscript",
    ]

    pat_re = re.compile("|".join(f"(?:{p})" for p in SUSPICIOUS_PATTERNS), re.IGNORECASE)

    base64_re = re.compile(r"^[A-Za-z0-9+/]{80,}={0,2}$")
    hex_re = re.compile(r"^(?:0x)?[0-9a-fA-F]{80,}$")
    urlenc_re = re.compile(r"%[0-9A-Fa-f]{2}")

    def char_entropy(s: str) -> float:
        # Shannon entropy (base 2)
        if not s:
            return 0.0
        from collections import Counter
        c = Counter(s)
        n = len(s)
        ent = 0.0
        for _, v in c.items():
            p = v / n
            ent -= p * math.log(p, 2)
        return ent

    def is_suspicious_text(text: str) -> bool:
        t = (text or "").strip()
        if not t:
            return False

        if len(t) > 4000:
            return True

        if pat_re.search(t):
            return True

        if len(t) >= 80 and base64_re.match(t):
            return True
        if len(t) >= 80 and hex_re.match(t):
            return True

        if len(t) >= 80:
            urlenc = len(urlenc_re.findall(t))
            if urlenc * 3 / max(len(t), 1) > 0.15:
                return True

            uniq_ratio = len(set(t)) / len(t)
            if uniq_ratio > 0.35 and char_entropy(t) > 4.2:
                return True

        return False

    # ---- Add new GraphML keys for aggregation fields (DEDUP) ----
    existing_ids = []
    for k in root.findall("g:key", ns):
        kid = k.get("id")
        m = re.fullmatch(r"d(\d+)", kid or "")
        if m:
            existing_ids.append(int(m.group(1)))
    next_id = (max(existing_ids) + 1) if existing_ids else 100

    def get_or_create_node_key(attr_name: str, attr_type: str = "string") -> str:
        """先查重(attr.name, for=node)，存在复用，否则创建新的 key。"""
        nonlocal next_id
        norm = (attr_name or "").strip()

        for kid, name in node_keys.items():
            if (name or "").strip() == norm:
                return kid

        kid = f"d{next_id}"
        next_id += 1

        k = etree.Element(f"{{{ns['g']}}}key")
        k.set("id", kid)
        k.set("for", "node")
        k.set("attr.name", norm)
        k.set("attr.type", attr_type)

        all_keys = root.findall("g:key", ns)
        if all_keys:
            all_keys[-1].addnext(k)
        else:
            root.insert(0, k)

        node_keys[kid] = norm
        return kid

    K_TEXT_COUNT = get_or_create_node_key("agg_text_count", "int")
    K_TEXT_LEN_SUM = get_or_create_node_key("agg_text_len_sum", "int")
    K_TEXT_PREVIEW = get_or_create_node_key("agg_text_preview", "string")
    K_TEXT_HASHES = get_or_create_node_key("agg_text_hashes", "string")
    K_HAS_SUSP_CHILD = get_or_create_node_key("agg_text_has_suspicious_child", "boolean")

    # ---- Aggregation state per parent ----
    agg = defaultdict(lambda: {
        "count": 0,
        "len_sum": 0,
        "preview_parts": [],
        "hashes": [],
        "has_susp_child": False
    })

    def short_hash(s: str) -> str:
        return hashlib.sha1((s or "").encode("utf-8", errors="ignore")).hexdigest()[:8]

    def update_parent_agg(parent_id: str, text: str, suspicious: bool):
        rec = agg[parent_id]
        rec["count"] += 1
        rec["len_sum"] += len(text)
        if suspicious:
            rec["has_susp_child"] = True
        snippet = (text or "").strip().replace("\n", " ").replace("\r", " ")
        snippet = re.sub(r"\s+", " ", snippet)
        if snippet:
            rec["preview_parts"].append(snippet[:200])
        rec["hashes"].append(short_hash(text))

    # ---- Decide which text nodes to collapse ----
    text_node_ids = []
    for nid, n in node_by_id.items():
        ntype = data_get(n, NODE_TYPE_KEY) or ""
        if ntype == "text node":
            text_node_ids.append(nid)

    collapse_ids = []
    keep_ids = []
    dropped_ids = []

    for nid in text_node_ids:
        n = node_by_id[nid]
        raw = data_get(n, NODE_TEXT_KEY) or ""
        t = raw.strip()

        # Basic drop
        if not t or (len(t) < 3 and not re.search(r"[A-Za-z0-9]", t)):
            dropped_ids.append(nid)
            continue

        suspicious = is_suspicious_text(t)
        if suspicious:
            keep_ids.append(nid)
            continue

        parent = find_parent_non_text(nid)
        if not parent:
            keep_ids.append(nid)
            continue

        collapse_ids.append(nid)
        update_parent_agg(parent, t, suspicious=False)

    # Mark parents that have suspicious kept text children
    for nid in keep_ids:
        parent = find_parent_non_text(nid)
        if parent:
            update_parent_agg(parent, data_get(node_by_id[nid], NODE_TEXT_KEY) or "", suspicious=True)

    # ---- Apply aggregation fields to parent nodes ----
    for pid, rec in agg.items():
        pn = node_by_id.get(pid)
        if not pn:
            continue
        data_set(pn, K_TEXT_COUNT, str(rec["count"]))
        data_set(pn, K_TEXT_LEN_SUM, str(rec["len_sum"]))
        preview = " | ".join(rec["preview_parts"][:10])
        data_set(pn, K_TEXT_PREVIEW, preview[:2000])
        data_set(pn, K_TEXT_HASHES, ",".join(rec["hashes"][:200]))
        data_set(pn, K_HAS_SUSP_CHILD, "true" if rec["has_susp_child"] else "false")

    # ---- Rewire / remove edges and nodes for collapsed/dropped text nodes ----
    SEMANTIC_REWIRE = {"create node", "insert node", "remove node"}

    to_remove_edge_ids: Set[str] = set()
    processed_edge_ids: Set[str] = set()
    rewire_ops = 0

    def process_edge_for_node(e, parent: Optional[str], nid: str) -> None:
        """每条 edge 只处理一次，避免同一 edge 在 fold↔fold 场景被重复处理。"""
        nonlocal rewire_ops
        eid = e.get("id")
        assert eid is not None, "Edge is missing id (assumption: edges always have id)"
        if eid in processed_edge_ids:
            return
        processed_edge_ids.add(eid)

        et = edge_type(e)
        if et == "document":
            to_remove_edge_ids.add(eid)
            return

        if parent and et in SEMANTIC_REWIRE:
            # Decide whether to rewire source or target depending on which side is this nid
            if e.get("target") == nid:
                e.set("target", parent)
                rewire_ops += 1
                return
            if e.get("source") == nid:
                e.set("source", parent)
                rewire_ops += 1
                return

        # Default: remove edge if text node is going away
        to_remove_edge_ids.add(eid)

    # Collapse nodes: can rewire semantic edges to parent
    for nid in collapse_ids:
        parent = find_parent_non_text(nid)
        for e in list(in_edges.get(nid, [])):
            process_edge_for_node(e, parent, nid)
        for e in list(out_edges.get(nid, [])):
            process_edge_for_node(e, parent, nid)

    # Dropped nodes: no parent rewiring, remove all adjacent edges
    for nid in dropped_ids:
        for e in list(in_edges.get(nid, [])):
            process_edge_for_node(e, None, nid)
        for e in list(out_edges.get(nid, [])):
            process_edge_for_node(e, None, nid)

    # Remove edges
    if to_remove_edge_ids:
        for e in list(graph.findall("g:edge", ns)):
            eid = e.get("id")
            assert eid is not None, "Edge is missing id (assumption: edges always have id)"
            if eid in to_remove_edge_ids:
                graph.remove(e)

    # Remove nodes (collapsed + dropped)
    remove_node_ids = set(collapse_ids + dropped_ids)
    for n in list(graph.findall("g:node", ns)):
        nid = n.get("id")
        if nid is not None and nid in remove_node_ids:
            graph.remove(n)

    # ---- Save ----
    tree.write(output_path, encoding="utf-8", xml_declaration=True, pretty_print=True)

    # ---- Report summary ----
    final_nodes = len(graph.findall("g:node", ns))
    final_edges = len(graph.findall("g:edge", ns))

    summary = {
        "input_nodes": len(nodes),
        "input_edges": len(edges),
        "text_nodes_total": len(text_node_ids),
        "text_nodes_kept_suspicious_or_no_parent": len(keep_ids),
        "text_nodes_collapsed": len(collapse_ids),
        "text_nodes_dropped_empty_noise": len(dropped_ids),
        "edges_removed": len(to_remove_edge_ids),
        "edges_rewired": rewire_ops,
        "output_nodes": final_nodes,
        "output_edges": final_edges,
        "output_path": output_path
    }

    return summary


def main():
    parser = argparse.ArgumentParser(
        description="折叠GraphML中的文本节点，检测可疑内容并进行聚合"
    )
    parser.add_argument("input", help="输入的GraphML文件路径")
    parser.add_argument("output", help="输出的GraphML文件路径")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        print(f"错误：输入文件不存在 - {input_path}", file=sys.stderr)
        sys.exit(1)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    try:
        summary = process_text_collapsing(str(input_path), str(output_path))

        print(f"[process] {input_path} -> {output_path}")
        print(f"  input:  nodes={summary['input_nodes']}, edges={summary['input_edges']}")
        print(f"  output: nodes={summary['output_nodes']}, edges={summary['output_edges']}")
        print(f"  text nodes total: {summary['text_nodes_total']}")
        print(f"    kept (suspicious/no parent): {summary['text_nodes_kept_suspicious_or_no_parent']}")
        print(f"    collapsed: {summary['text_nodes_collapsed']}")
        print(f"    dropped (empty/noise): {summary['text_nodes_dropped_empty_noise']}")
        print(f"  edges: removed={summary['edges_removed']}, rewired={summary['edges_rewired']}")

    except Exception as e:
        print(f"错误：{e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
