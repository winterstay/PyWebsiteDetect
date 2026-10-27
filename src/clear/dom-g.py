from lxml import etree
import re
import sys
from collections import defaultdict, deque
from typing import Optional, Set, Dict, List

ns = {"g": "http://graphml.graphdrawing.org/xmlns"}


def main() -> int:
    if len(sys.argv) != 3:
        print("Usage: python dom-g.py <input.graphml> <output.graphml>")
        return 2

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    parser = etree.XMLParser(recover=True, huge_tree=True)
    tree = etree.parse(input_path, parser)
    root = tree.getroot()
    graph = root.find("g:graph", ns)
    if graph is None:
        raise RuntimeError("Missing <graph> element")

    # ---- Build key maps ----
    node_keys: Dict[str, str] = {}
    edge_keys: Dict[str, str] = {}

    for k in root.findall("g:key", ns):
        k_for = k.get("for")
        kid = k.get("id")
        name = k.get("attr.name")
        if not kid:
            continue
        if k_for == "node":
            node_keys[kid] = name
        elif k_for == "edge":
            edge_keys[kid] = name

    def data_get(elem, key_id: str) -> Optional[str]:
        for d in elem.findall("g:data", ns):
            if d.get("key") == key_id:
                return d.text
        return None

    def data_set(elem, key_id: str, value: str) -> None:
        for d in elem.findall("g:data", ns):
            if d.get("key") == key_id:
                d.text = value
                return
        d = etree.SubElement(elem, f"{{{ns['g']}}}data")
        d.set("key", key_id)
        d.text = value

    # Required keys
    NODE_TYPE_KEY = None
    EDGE_TYPE_KEY = None
    for kid, name in node_keys.items():
        if name == "node type":
            NODE_TYPE_KEY = kid
    for kid, name in edge_keys.items():
        if name == "edge type":
            EDGE_TYPE_KEY = kid
    if not NODE_TYPE_KEY or not EDGE_TYPE_KEY:
        raise RuntimeError("Missing required key(s): node type / edge type")

    # Try to locate a tag-name key for HTML element nodes
    TAG_CANDIDATES = [
        "tag", "tag name", "node name", "element tag", "html tag",
        "tagName", "node tag", "element name"
    ]
    TAG_KEY = None
    candset = {t.lower() for t in TAG_CANDIDATES}
    for kid, name in node_keys.items():
        if (name or "").strip().lower() in candset:
            TAG_KEY = kid
            break
    if TAG_KEY is None:
        for kid, name in node_keys.items():
            if name and "tag" in name.lower():
                TAG_KEY = kid
                break

    nodes = graph.findall("g:node", ns)
    edges = graph.findall("g:edge", ns)
    node_by_id = {n.get("id"): n for n in nodes if n.get("id") is not None}

    # Build in/out edges + document parent mapping
    in_edges: Dict[str, List[etree._Element]] = defaultdict(list)
    out_edges: Dict[str, List[etree._Element]] = defaultdict(list)
    incoming_document_parent: Dict[str, List[str]] = defaultdict(list)

    def edge_type(e) -> str:
        return (data_get(e, EDGE_TYPE_KEY) or "")

    for e in edges:
        eid = e.get("id")
        if eid is None:
            raise RuntimeError("Edge is missing id (you said edges always have id)")
        s = e.get("source")
        t = e.get("target")
        if s is None or t is None:
            continue
        in_edges[t].append(e)
        out_edges[s].append(e)
        if edge_type(e) == "document":
            incoming_document_parent[t].append(s)

    def get_node_type(nid: str) -> str:
        n = node_by_id.get(nid)
        return (data_get(n, NODE_TYPE_KEY) or "") if n is not None else ""

    def get_tag(nid: str) -> str:
        if TAG_KEY is None:
            return ""
        n = node_by_id.get(nid)
        if n is None:
            return ""
        v = data_get(n, TAG_KEY) or ""
        return (v or "").strip().upper()

    def nearest_kept_dom_ancestor(nid: str, keep_dom_ids: Set[str]) -> Optional[str]:
        """Follow document parents to find nearest kept DOM node (or None)."""
        seen = set()
        cur = nid
        while True:
            if cur in seen:
                return None
            seen.add(cur)
            parents = incoming_document_parent.get(cur, [])
            if not parents:
                return None
            p = parents[0]
            if p in keep_dom_ids:
                return p
            cur = p

    # ---- DOM folding policy ----
    KEEP_TAGS = {
        "SCRIPT", "IFRAME", "FRAME", "OBJECT", "EMBED",
        "A", "FORM", "INPUT", "BUTTON", "TEXTAREA", "SELECT", "OPTION",
        "IMG", "VIDEO", "AUDIO", "SOURCE",
        "LINK", "STYLE", "META",
        "BASE",
    }

    # Find HTML element nodes
    html_element_ids: List[str] = []
    for nid in node_by_id.keys():
        if get_node_type(nid) == "HTML element":
            html_element_ids.append(nid)

    keep_dom_ids: Set[str] = set()
    fold_dom_ids: Set[str] = set()

    if TAG_KEY is None:
        # If no tag key, can't fold safely: keep all HTML elements
        keep_dom_ids.update(html_element_ids)
    else:
        for nid in html_element_ids:
            if get_tag(nid) in KEEP_TAGS:
                keep_dom_ids.add(nid)

        for nid in html_element_ids:
            if nid in keep_dom_ids:
                continue
            parent_kept = nearest_kept_dom_ancestor(nid, keep_dom_ids)
            if parent_kept is None:
                keep_dom_ids.add(nid)
            else:
                fold_dom_ids.add(nid)

    # ---- Add aggregation keys for DOM folding (dedupe) ----
    existing_ids = []
    for k in root.findall("g:key", ns):
        kid = k.get("id")
        m = re.fullmatch(r"d(\d+)", kid or "")
        if m:
            existing_ids.append(int(m.group(1)))
    next_id = (max(existing_ids) + 1) if existing_ids else 200

    def get_or_create_node_key(attr_name: str, attr_type: str = "string") -> str:
        nonlocal next_id
        norm = (attr_name or "").strip()

        # 1) reuse if same attr.name exists for node
        for kid, name in node_keys.items():
            if (name or "").strip() == norm:
                return kid

        # 2) create new
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

    K_DOM_FOLD_COUNT = get_or_create_node_key("dom_fold_count", "int")
    K_DOM_FOLD_TAGS = get_or_create_node_key("dom_fold_tags", "string")
    K_DOM_FOLD_HAS_SCRIPT_DESC = get_or_create_node_key("dom_fold_has_script_descendant", "boolean")

    # Build children adjacency for subtree checks
    children: Dict[str, List[str]] = defaultdict(list)
    for child, parents in incoming_document_parent.items():
        for p in parents:
            children[p].append(child)

    def subtree_contains_script(root_id: str) -> bool:
        q = deque([root_id])
        seen = set()
        while q:
            x = q.popleft()
            if x in seen:
                continue
            seen.add(x)
            if get_node_type(x) == "HTML element" and get_tag(x) == "SCRIPT":
                return True
            for c in children.get(x, []):
                q.append(c)
        return False

    # Map folded node -> kept parent
    fold_parent: Dict[str, Optional[str]] = {}
    if TAG_KEY is not None:
        for nid in fold_dom_ids:
            fold_parent[nid] = nearest_kept_dom_ancestor(nid, keep_dom_ids)

    # Aggregate folded DOM info into kept parents
    dom_agg = defaultdict(lambda: {"count": 0, "tags": defaultdict(int), "has_script_desc": False})

    if TAG_KEY is not None:
        for nid, pid in fold_parent.items():
            if not pid:
                continue
            dom_agg[pid]["count"] += 1
            tag = get_tag(nid) or "UNKNOWN"
            dom_agg[pid]["tags"][tag] += 1

        for pid in dom_agg.keys():
            dom_agg[pid]["has_script_desc"] = subtree_contains_script(pid)

    # Apply aggregation fields
    for pid, rec in dom_agg.items():
        pn = node_by_id.get(pid)
        if pn is None:
            continue
        data_set(pn, K_DOM_FOLD_COUNT, str(rec["count"]))
        tag_str = ",".join(
            [f"{t}:{c}" for t, c in sorted(rec["tags"].items(), key=lambda kv: (-kv[1], kv[0]))][:30]
        )
        data_set(pn, K_DOM_FOLD_TAGS, tag_str)
        data_set(pn, K_DOM_FOLD_HAS_SCRIPT_DESC, "true" if rec["has_script_desc"] else "false")

    # ---- Rewire/remove edges for folded DOM nodes ----
    SEMANTIC_REWIRE = {
        "create node", "insert node", "remove node",
        "set attribute", "execute from attribute",
        "add event listener", "event listener",
        "js call", "js result",
    }

    to_remove_edge_ids: Set[str] = set()
    processed_edge_ids: Set[str] = set()
    rewired = 0

    def process_edge(e) -> None:
        nonlocal rewired
        eid = e.get("id")
        if eid is None:
            raise RuntimeError("Edge is missing id (you said edges always have id)")
        if eid in processed_edge_ids:
            return
        processed_edge_ids.add(eid)

        s = e.get("source")
        t = e.get("target")
        if s is None or t is None:
            return

        et = edge_type(e)

        # Remove document edges touching folded nodes
        if et == "document":
            to_remove_edge_ids.add(eid)
            return

        # Rewire semantic edges if either endpoint is folded
        if et in SEMANTIC_REWIRE:
            if t in fold_dom_ids:
                pid = fold_parent.get(t)
                if pid:
                    e.set("target", pid)
                    rewired += 1
                else:
                    to_remove_edge_ids.add(eid)
                    return
            if s in fold_dom_ids:
                pid = fold_parent.get(s)
                if pid:
                    e.set("source", pid)
                    rewired += 1
                else:
                    to_remove_edge_ids.add(eid)
                    return
            return

        # Non-semantic edges touching folded nodes -> remove
        if (s in fold_dom_ids) or (t in fold_dom_ids):
            to_remove_edge_ids.add(eid)

    # Process all edges adjacent to folded nodes, each edge only once
    if fold_dom_ids:
        for nid in list(fold_dom_ids):
            for e in in_edges.get(nid, []):
                process_edge(e)
            for e in out_edges.get(nid, []):
                process_edge(e)

    # Remove edges
    if to_remove_edge_ids:
        for e in list(graph.findall("g:edge", ns)):
            eid = e.get("id")
            if eid is None:
                raise RuntimeError("Edge is missing id (you said edges always have id)")
            if eid in to_remove_edge_ids:
                graph.remove(e)

    # Remove folded nodes
    for n in list(graph.findall("g:node", ns)):
        nid = n.get("id")
        if nid is not None and nid in fold_dom_ids:
            graph.remove(n)

    # Save
    tree.write(output_path, encoding="utf-8", xml_declaration=True, pretty_print=True)

    print("Done.")
    print("Tag key detected:", node_keys.get(TAG_KEY) if TAG_KEY else None)
    print("HTML total:", len(html_element_ids), "kept:", len(keep_dom_ids), "folded:", len(fold_dom_ids))
    print("Edges removed:", len(to_remove_edge_ids), "Edges rewired:", rewired)
    print("Output:", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
