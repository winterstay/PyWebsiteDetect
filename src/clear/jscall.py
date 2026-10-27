#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import json
import re
from collections import defaultdict
from typing import Optional, Dict, List, Tuple
from lxml import etree

EDGE_TYPE_KEY_NAME = "edge type"
CALL_TYPE = "js call"
RESULT_TYPE = "js result"
MERGED_TYPE = "js call and result"

NS = {"g": "http://graphml.graphdrawing.org/xmlns"}


def _to_int(x, default=None):
    try:
        if x is None:
            return default
        return int(str(x))
    except Exception:
        return default


def _safe_json_dumps(obj):
    return json.dumps(obj, ensure_ascii=False)


def _get_timestamp(edge_attrs: Dict[str, str]) -> Optional[int]:
    return _to_int(edge_attrs.get("timestamp"), default=None)


def _get_frame_id(edge_attrs: Dict[str, str]) -> Optional[int]:
    return _to_int(edge_attrs.get("frame id"), default=None)


def _get_id_num(edge_attrs: Dict[str, str]) -> Optional[int]:
    return _to_int(edge_attrs.get("id"), default=None)


def summarize_call_edge(d):
    return {
        "id": d.get("id"),
        "timestamp": d.get("timestamp"),
        "frame id": d.get("frame id"),
        "args": d.get("args"),
        "script position": d.get("script position"),
    }


def summarize_result_edge(d):
    return {
        "id": d.get("id"),
        "timestamp": d.get("timestamp"),
        "frame id": d.get("frame id"),
        "value": d.get("value"),
    }


def pair_calls_and_results(
    call_edges: List[Tuple[str, str, str, Dict[str, str]]],
    result_edges: List[Tuple[str, str, str, Dict[str, str]]],
):
    """
    Pair strategy:
    1) group results by (frame id, timestamp)
    2) for each call, match same key; if multiple candidates, pick closest by numeric id
    """
    results_by_key = defaultdict(list)
    for re_item in result_edges:
        _, _, _, d = re_item
        key = (_get_frame_id(d), _get_timestamp(d))
        results_by_key[key].append(re_item)

    for key in list(results_by_key.keys()):
        results_by_key[key].sort(key=lambda e: (_get_id_num(e[3]) is None, _get_id_num(e[3]) or 10**18))

    used_results = set()
    pairs = []
    unmatched_calls = []
    unmatched_results = []

    def sig(u, v, eid):
        return (u, v, eid)

    for ce in call_edges:
        cu, cv, ceid, cd = ce
        key = (_get_frame_id(cd), _get_timestamp(cd))
        candidates = [r for r in results_by_key.get(key, []) if sig(r[0], r[1], r[2]) not in used_results]
        if not candidates:
            unmatched_calls.append(ce)
            continue

        call_id = _get_id_num(cd)
        if call_id is None:
            chosen = candidates[0]
        else:
            def score(r):
                rid = _get_id_num(r[3])
                if rid is None:
                    return 10**18
                return abs(rid - call_id)
            chosen = min(candidates, key=score)

        used_results.add(sig(chosen[0], chosen[1], chosen[2]))
        pairs.append((ce, chosen))

    for re_item in result_edges:
        if sig(re_item[0], re_item[1], re_item[2]) not in used_results:
            unmatched_results.append(re_item)

    return pairs, unmatched_calls, unmatched_results


def main():
    if len(sys.argv) != 3:
        print("Usage: python jscall.py input.graphml output.graphml")
        return 1

    in_path = sys.argv[1]
    out_path = sys.argv[2]

    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse(in_path, parser)
    root = tree.getroot()
    graph = root.find("g:graph", NS)
    if graph is None:
        raise RuntimeError("Missing <graph> element")

    # ---- key maps: edge attr.name -> key id, and node id allocation ----
    edge_keyname_to_id: Dict[str, str] = {}
    existing_numeric = []

    for k in root.findall("g:key", NS):
        kid = k.get("id")
        if kid:
            m = re.fullmatch(r"d(\d+)", kid)
            if m:
                existing_numeric.append(int(m.group(1)))

        if k.get("for") == "edge":
            name = (k.get("attr.name") or "").strip()
            if name and name not in edge_keyname_to_id:
                edge_keyname_to_id[name] = k.get("id")

    next_id_num = (max(existing_numeric) + 1) if existing_numeric else 0

    def get_or_create_edge_key(attr_name: str, attr_type: str = "string") -> str:
        """
        ✅ 先检测(for=edge, attr.name)是否已存在，存在则复用
        ✅ 不存在才创建，并插到最后一个<key>后面
        """
        nonlocal next_id_num
        norm = (attr_name or "").strip()
        if norm in edge_keyname_to_id and edge_keyname_to_id[norm]:
            return edge_keyname_to_id[norm]

        kid = f"d{next_id_num}"
        next_id_num += 1

        k = etree.Element(f"{{{NS['g']}}}key")
        k.set("id", kid)
        k.set("for", "edge")
        k.set("attr.name", norm)
        k.set("attr.type", attr_type)

        all_keys = root.findall("g:key", NS)
        if all_keys:
            all_keys[-1].addnext(k)
        else:
            root.insert(0, k)

        edge_keyname_to_id[norm] = kid
        return kid

    # Ensure required edge keys exist (append if missing)
    K_EDGE_TYPE = get_or_create_edge_key(EDGE_TYPE_KEY_NAME, "string")
    K_CALL_COUNT = get_or_create_edge_key("call_count", "int")
    K_RESULT_COUNT = get_or_create_edge_key("result_count", "int")
    K_PAIR_COUNT = get_or_create_edge_key("pair_count", "int")
    K_UNMATCHED_CALL_COUNT = get_or_create_edge_key("unmatched_call_count", "int")
    K_UNMATCHED_RESULT_COUNT = get_or_create_edge_key("unmatched_result_count", "int")
    K_FIRST_TIMESTAMP = get_or_create_edge_key("first_timestamp", "string")
    K_LAST_TIMESTAMP = get_or_create_edge_key("last_timestamp", "string")
    K_CALLS_SAMPLE_JSON = get_or_create_edge_key("calls_sample_json", "string")
    K_RESULTS_SAMPLE_JSON = get_or_create_edge_key("results_sample_json", "string")
    K_PAIRS_SAMPLE_JSON = get_or_create_edge_key("pairs_sample_json", "string")
    K_ORPHAN_CALL_ONLY = get_or_create_edge_key("orphan_call_only", "int")
    K_ORPHAN_RESULT_ONLY = get_or_create_edge_key("orphan_result_only", "int")

    # ---- helpers to read/write <data> by attr.name ----
    # Build reverse map: key id -> attr.name (only need for edges)
    edge_keyid_to_name: Dict[str, str] = {}
    for k in root.findall("g:key", NS):
        if k.get("for") == "edge":
            kid = k.get("id")
            name = (k.get("attr.name") or "").strip()
            if kid and name:
                edge_keyid_to_name[kid] = name

    def edge_attrs(e) -> Dict[str, str]:
        d = {}
        for data in e.findall("g:data", NS):
            kid = data.get("key")
            if not kid:
                continue
            name = edge_keyid_to_name.get(kid)
            if not name:
                continue
            d[name] = data.text if data.text is not None else ""
        return d

    def set_edge_data(e, key_id: str, value: str):
        for data in e.findall("g:data", NS):
            if data.get("key") == key_id:
                data.text = value
                return
        nd = etree.SubElement(e, f"{{{NS['g']}}}data")
        nd.set("key", key_id)
        nd.text = value

    # ---- collect call/result edges by (u, v) ----
    calls_by_uv = defaultdict(list)    # (u,v) -> [(u,v,eid,attrs)]
    results_by_uv = defaultdict(list)  # (u,v) -> [(u,v,eid,attrs)]

    all_edges = graph.findall("g:edge", NS)
    edge_by_id = {}
    for e in all_edges:
        eid = e.get("id")
        if eid is None:
            raise RuntimeError("Edge missing id (you said edges always have id)")
        edge_by_id[eid] = e
        u = e.get("source")
        v = e.get("target")
        if u is None or v is None:
            continue
        attrs = edge_attrs(e)
        et = attrs.get(EDGE_TYPE_KEY_NAME, "")
        if et == CALL_TYPE:
            calls_by_uv[(u, v)].append((u, v, eid, attrs))
        elif et == RESULT_TYPE:
            results_by_uv[(u, v)].append((u, v, eid, attrs))

    # ---- allocate new unique edge ids for merged edges ----
    existing_edge_ids = set(edge_by_id.keys())
    merged_seq = 0

    def new_edge_id() -> str:
        nonlocal merged_seq
        while True:
            merged_seq += 1
            nid = f"merged_{merged_seq}"
            if nid not in existing_edge_ids:
                existing_edge_ids.add(nid)
                return nid

    # ---- merge + mark removals ----
    to_remove_ids = set()

    def add_merged_edge_xml(u: str, v: str, call_edges, result_edges, sample_limit=20):
        pairs, unmatched_calls, unmatched_results = pair_calls_and_results(call_edges, result_edges)

        ts_all = []
        for _, _, _, d in call_edges + result_edges:
            t = _get_timestamp(d)
            if t is not None:
                ts_all.append(t)
        first_ts = min(ts_all) if ts_all else None
        last_ts = max(ts_all) if ts_all else None

        call_samples = [summarize_call_edge(d) for *_, d in call_edges][:sample_limit]
        result_samples = [summarize_result_edge(d) for *_, d in result_edges][:sample_limit]
        pair_samples = []
        for (ce, re_item) in pairs[:sample_limit]:
            _, _, _, cd = ce
            _, _, _, rd = re_item
            pair_samples.append({
                "call": summarize_call_edge(cd),
                "result": summarize_result_edge(rd),
            })

        # Create new <edge>
        e = etree.SubElement(graph, f"{{{NS['g']}}}edge")
        e.set("id", new_edge_id())
        e.set("source", u)
        e.set("target", v)

        # Set merged attrs as <data>
        set_edge_data(e, K_EDGE_TYPE, MERGED_TYPE)
        set_edge_data(e, K_CALL_COUNT, str(len(call_edges)))
        set_edge_data(e, K_RESULT_COUNT, str(len(result_edges)))
        set_edge_data(e, K_PAIR_COUNT, str(len(pairs)))
        set_edge_data(e, K_UNMATCHED_CALL_COUNT, str(len(unmatched_calls)))
        set_edge_data(e, K_UNMATCHED_RESULT_COUNT, str(len(unmatched_results)))
        set_edge_data(e, K_FIRST_TIMESTAMP, "" if first_ts is None else str(first_ts))
        set_edge_data(e, K_LAST_TIMESTAMP, "" if last_ts is None else str(last_ts))
        set_edge_data(e, K_CALLS_SAMPLE_JSON, _safe_json_dumps(call_samples))
        set_edge_data(e, K_RESULTS_SAMPLE_JSON, _safe_json_dumps(result_samples))
        set_edge_data(e, K_PAIRS_SAMPLE_JSON, _safe_json_dumps(pair_samples))

        if len(call_edges) > 0 and len(result_edges) == 0:
            set_edge_data(e, K_ORPHAN_CALL_ONLY, "1")
        if len(call_edges) == 0 and len(result_edges) > 0:
            set_edge_data(e, K_ORPHAN_RESULT_ONLY, "1")

    # 1) Merge based on calls direction: (u->v calls) + (v->u results)
    consumed_results_uv = set()
    for (u, v), call_edges in calls_by_uv.items():
        rev_results = results_by_uv.get((v, u), [])
        add_merged_edge_xml(u, v, call_edges, rev_results)

        for _, _, eid, _ in call_edges:
            to_remove_ids.add(eid)
        for _, _, eid, _ in rev_results:
            to_remove_ids.add(eid)

        consumed_results_uv.add((v, u))

    # 2) Remaining js result edges not consumed => orphan_result_only
    for (u, v), res_edges in results_by_uv.items():
        if (u, v) in consumed_results_uv:
            continue
        add_merged_edge_xml(u, v, [], res_edges)
        for _, _, eid, _ in res_edges:
            to_remove_ids.add(eid)

    # ---- remove old edges by id ----
    if to_remove_ids:
        for e in list(graph.findall("g:edge", NS)):
            eid = e.get("id")
            if eid in to_remove_ids:
                graph.remove(e)

    tree.write(out_path, encoding="utf-8", xml_declaration=True, pretty_print=True)
    print(f"Done. Wrote merged graph to: {out_path}")
    print(f"Removed edges: {len(to_remove_ids)}; Added merged edges: {merged_seq}")


if __name__ == "__main__":
    raise SystemExit(main())
