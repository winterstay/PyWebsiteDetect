#!/usr/bin/env python3
import argparse
import csv
import hashlib
import re
import textwrap
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse


GRAPHML_NS = {"g": "http://graphml.graphdrawing.org/xmlns"}

ENV_APIS = (
    "Navigator.userAgent",
    "Navigator.plugins",
    "Navigator.mimeTypes",
    "Navigator.javaEnabled",
    "Navigator.platform",
    "Navigator.vendor",
    "Navigator.product",
    "Screen.width",
    "Screen.height",
    "Document.referrer",
    "Location.host",
    "Location.protocol",
    "Location.search",
    "Location.toString",
)

OBFUSCATION_TERMS = (
    "eval",
    "fromCharCode",
    "unescape",
    "atob",
    "parseInt",
    "charAt",
    "substr",
    "String[",
    "document.write",
)

SUSPICIOUS_URL_TERMS = (
    "analytic",
    "stat",
    "counter",
    "jquery",
    "ad",
    "pixel",
    "track",
    "gate",
    "landing",
    "php?",
)

PLUGIN_TERMS = (
    "clsid",
    "CAFEEFAC",
    "CA8A9780",
    "Shockwave",
    "Flash",
    "Silverlight",
    "PDF",
    "AcroPDF",
    "APPLET",
    "OBJECT",
    "EMBED",
)

COMMON_BENIGN_HOSTS = (
    "google-analytics.com",
    "www.google-analytics.com",
    "stats.g.doubleclick.net",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "connect.facebook.net",
    "s7.addthis.com",
    "cache.addthiscdn.com",
    "ajax.googleapis.com",
    "translate.google.com",
)

PHASE_ORDER = (
    "1. 入口与触发",
    "2. 隐藏跳转与 Landing",
    "3. 筛选与环境探测",
    "4. 混淆解码与加载器",
    "5. 利用承载与投递",
    "6. 背景资源与噪声",
)

PHASE_DESCRIPTIONS = {
    "1. 入口与触发": "入口页面、初始执行脚本、动态脚本入口或伪装资源，回答攻击链从哪里开始。",
    "2. 隐藏跳转与 Landing": "iframe/frame、setAttribute(src)、cross DOM 和跨站 landing，回答攻击如何离开正常页面。",
    "3. 筛选与环境探测": "浏览器、插件、屏幕、来源、cookie/storage 等访问，回答攻击如何识别受害者和选择分支。",
    "4. 混淆解码与加载器": "混淆、字符串解码、document.write 和动态生成代码，回答恶意逻辑如何被释放或拼接。",
    "5. 利用承载与投递": "OBJECT/EMBED/APPLET、插件标识、外部可疑请求和载荷候选，回答最终利用或投递依靠什么承载。",
    "6. 背景资源与噪声": "常见第三方服务或低风险外部资源，作为上下文保留，但不直接构成核心攻击链。",
}


@dataclass
class Evidence:
    eid: str
    family: str
    rule: str
    severity: int
    node_id: str = ""
    edge: str = ""
    timestamp: str = ""
    behavior: str = ""
    forensic_meaning: str = ""
    details: str = ""
    labels: tuple = field(default_factory=tuple)


def read_graphml(path):
    root = ET.parse(path).getroot()
    key_name = {
        k.attrib["id"]: k.attrib.get("attr.name", k.attrib["id"])
        for k in root.findall("g:key", GRAPHML_NS)
    }

    nodes = {}
    for node in root.findall(".//g:node", GRAPHML_NS):
        attrs = {
            key_name.get(data.attrib["key"], data.attrib["key"]): data.text or ""
            for data in node.findall("g:data", GRAPHML_NS)
        }
        nodes[node.attrib["id"]] = attrs

    edges = []
    outgoing = defaultdict(list)
    incoming = defaultdict(list)
    for edge in root.findall(".//g:edge", GRAPHML_NS):
        attrs = {
            key_name.get(data.attrib["key"], data.attrib["key"]): data.text or ""
            for data in edge.findall("g:data", GRAPHML_NS)
        }
        item = {
            "source": edge.attrib["source"],
            "target": edge.attrib["target"],
            "attrs": attrs,
        }
        edges.append(item)
        outgoing[item["source"]].append(item)
        incoming[item["target"]].append(item)

    root_url = ""
    desc_url = root.find("g:desc/g:url", GRAPHML_NS)
    if desc_url is not None and desc_url.text:
        root_url = desc_url.text
    if not root_url:
        dom_roots = [
            attrs.get("url", "")
            for attrs in nodes.values()
            if attrs.get("node type") == "DOM root" and attrs.get("url", "").startswith(("http://", "https://"))
        ]
        root_url = dom_roots[0] if dom_roots else ""
    return nodes, edges, outgoing, incoming, root_url


def family_from_path(path):
    if path.parent.name:
        return path.parent.name
    return path.stem.split("_")[0]


def host_of(url):
    parsed = urlparse(url)
    return (parsed.hostname or "").lower()


def same_site(a, b):
    ha = host_of(a)
    hb = host_of(b)
    if not ha or not hb:
        return False
    if ha == hb:
        return True
    return ha.endswith("." + hb) or hb.endswith("." + ha)


def timestamp_for_node(node):
    return node.get("timestamp", "")


def timestamp_for_edge(edge):
    attrs = edge["attrs"]
    return attrs.get("timestamp") or attrs.get("first_timestamp") or attrs.get("last_timestamp") or ""


def node_text(node):
    keys = ("node type", "tag name", "url", "source", "text", "method", "binding", "primary pattern", "secondary pattern")
    return " ".join(node.get(k, "") for k in keys)


def trim(text, limit=180):
    value = re.sub(r"\s+", " ", text or "").strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1] + "…"


def is_cross_origin_url(url, root_url):
    if not url.startswith(("http://", "https://")):
        return False
    return not same_site(url, root_url)


def is_common_benign_external(url):
    host = host_of(url)
    return any(host == item or host.endswith("." + item) for item in COMMON_BENIGN_HOSTS)


def has_plugin_identifier(value):
    low = (value or "").lower()
    if any(term.lower() in low for term in PLUGIN_TERMS):
        return True
    return bool(re.search(r"(application/x-java|java-applet|application/java|x-shockwave-flash)", low))


def add_evidence(items, family, rule, severity, node_id="", edge="", timestamp="", behavior="", meaning="", details="", labels=()):
    digest = hashlib.sha1(f"{family}|{rule}|{node_id}|{edge}|{timestamp}|{details}".encode("utf-8")).hexdigest()[:8]
    items.append(
        Evidence(
            eid=f"E-{digest}",
            family=family,
            rule=rule,
            severity=severity,
            node_id=node_id,
            edge=edge,
            timestamp=timestamp,
            behavior=behavior,
            forensic_meaning=meaning,
            details=details,
            labels=tuple(labels),
        )
    )


def apply_rules(family, nodes, edges, outgoing, incoming, root_url):
    evidence = []

    for nid, node in nodes.items():
        ntype = node.get("node type", "")
        tag = node.get("tag name", "")
        url = node.get("url", "")
        source = node.get("source", "") or node.get("text", "")
        method = node.get("method", "")
        text = node_text(node)
        ts = timestamp_for_node(node)

        if ntype == "DOM root" and url and same_site(url, root_url):
            add_evidence(
                evidence,
                family,
                "入口页面",
                1,
                node_id=nid,
                timestamp=ts,
                behavior="initial DOM root",
                meaning="入口页面 DOM root，作为攻击链取证的起点。",
                details=url,
                labels=("initial_entry",),
            )

        if ntype == "web API" and any(api in method for api in ENV_APIS):
            add_evidence(
                evidence,
                family,
                "环境/受害者探测",
                2,
                node_id=nid,
                timestamp=ts,
                behavior=method,
                meaning="脚本读取浏览器、插件、来源或屏幕信息，可用于筛选受害者或选择利用分支。",
                details=method,
                labels=("environment_detection",),
            )

        if ntype in ("frame owner", "HTML element") and tag.upper() in ("IFRAME", "FRAME"):
            add_evidence(
                evidence,
                family,
                "iframe 节点",
                2,
                node_id=nid,
                timestamp=ts,
                behavior=f"{ntype}/{tag}",
                meaning="图中存在 iframe/frame 承载节点，可能用于隐藏跳转或 landing 加载。",
                details=trim(text),
                labels=("iframe", "redirect_carrier"),
            )

        if tag.upper() in ("OBJECT", "EMBED", "APPLET") or ntype == "frame owner" and tag.upper() in ("OBJECT", "EMBED", "APPLET"):
            add_evidence(
                evidence,
                family,
                "插件利用承载",
                3,
                node_id=nid,
                timestamp=ts,
                behavior=f"{ntype}/{tag}",
                meaning="OBJECT/EMBED/APPLET 常用于 Java、Flash、PDF、Silverlight 等插件利用承载。",
                details=trim(text),
                labels=("plugin_carrier", "exploit_candidate"),
            )

        if ntype == "script":
            lower_source = source.lower()
            if any(term.lower() in lower_source for term in OBFUSCATION_TERMS):
                add_evidence(
                    evidence,
                    family,
                    "脚本混淆/动态生成",
                    3,
                    node_id=nid,
                    timestamp=ts,
                    behavior="混淆解码或动态写入",
                    meaning="脚本包含字符串解码、动态代码生成或 document.write，常见于恶意网页加载器。",
                    details=trim(source),
                    labels=("obfuscation", "loader"),
                )
            if "document.cookie" in lower_source or "cookie.indexof" in lower_source:
                add_evidence(
                    evidence,
                    family,
                    "cookie 去重/访问控制",
                    3,
                    node_id=nid,
                    timestamp=ts,
                    behavior="document.cookie read/write",
                    meaning="脚本读取或写入 cookie，可用于控制重复访问、筛选受害者或避免重复投递。",
                    details=trim(source),
                    labels=("cookie_control", "victim_filtering"),
                )
            if any(term.lower() in lower_source for term in ("createelement(\"iframe", "createelement('iframe", "<iframe", "iframe src")):
                add_evidence(
                    evidence,
                    family,
                    "隐藏 iframe 注入",
                    4,
                    node_id=nid,
                    timestamp=ts,
                    behavior="createElement/document.write iframe",
                    meaning="脚本动态创建或写入 iframe，是 EK 跳转到 landing 的典型入口行为。",
                    details=trim(source),
                    labels=("hidden_iframe", "redirect"),
                )
            if any(term.lower() in lower_source for term in ("left:-1000", "top:-1000", "left:-500", "top: -500", "display:none", "width=\"0", "height=\"0")):
                add_evidence(
                    evidence,
                    family,
                    "隐藏化布局",
                    3,
                    node_id=nid,
                    timestamp=ts,
                    behavior="off-screen/display hidden",
                    meaning="iframe 或容器被放到屏幕外/隐藏，符合隐蔽跳转或静默加载特征。",
                    details=trim(source),
                    labels=("hidden_layout",),
                )

        if url and is_cross_origin_url(url, root_url):
            common_benign = is_common_benign_external(url)
            severity = 1 if common_benign else (3 if ntype in ("DOM root", "resource") else 2)
            add_evidence(
                evidence,
                family,
                "常见第三方资源" if common_benign else "跨站资源/landing 候选",
                severity,
                node_id=nid,
                timestamp=ts,
                behavior=f"{ntype} URL",
                meaning="常见第三方服务资源，作为背景上下文保留。" if common_benign else "节点 URL 与入口页面不同源，可能是中转、landing 或外部载荷资源。",
                details=url,
                labels=("benign_external",) if common_benign else ("external_url", "landing_candidate" if ntype == "DOM root" else "external_resource"),
            )

        if (
            url
            and any(term in url.lower() for term in SUSPICIOUS_URL_TERMS)
            and is_cross_origin_url(url, root_url)
            and not is_common_benign_external(url)
        ):
            add_evidence(
                evidence,
                family,
                "伪装资源命名",
                2,
                node_id=nid,
                timestamp=ts,
                behavior="analytics/jquery/ad-like URL",
                meaning="外部 URL 使用统计、广告或常用库命名，若伴随跳转/探测行为，可能属于伪装入口。",
                details=url,
                labels=("masquerade_resource",),
            )

    for edge in edges:
        src = edge["source"]
        tgt = edge["target"]
        attrs = edge["attrs"]
        etype = attrs.get("edge type", "")
        ts = timestamp_for_edge(edge)
        edge_id = f"{src}->{tgt}"
        src_node = nodes.get(src, {})
        tgt_node = nodes.get(tgt, {})
        value = attrs.get("value", "")
        attr_name = attrs.get("attr name", "")
        rtype = attrs.get("resource type", "")

        if etype == "cross DOM":
            target_url = tgt_node.get("url", "")
            severity = 4 if is_cross_origin_url(target_url, root_url) else 2
            add_evidence(
                evidence,
                family,
                "跨 DOM 跳转",
                severity,
                edge=edge_id,
                timestamp=ts,
                behavior="frame owner -> DOM root",
                meaning="iframe/frame 导航到新的 DOM，上下文切换可还原攻击跳转链。",
                details=target_url or trim(node_text(tgt_node)),
                labels=("cross_dom", "landing_transition"),
            )

        if etype == "set attribute" and value:
            low = value.lower()
            if attr_name.lower() == "src" or value.startswith(("http://", "https://")):
                add_evidence(
                    evidence,
                    family,
                    "资源/跳转目标写入",
                    3 if value.startswith(("http://", "https://")) else 2,
                    edge=edge_id,
                    timestamp=ts,
                    behavior=f"setAttribute {attr_name or 'value'}",
                    meaning="脚本向节点写入 src/URL，给出了动态跳转或资源加载目标。",
                    details=value,
                    labels=("set_src", "dynamic_target"),
                )
            if has_plugin_identifier(value):
                add_evidence(
                    evidence,
                    family,
                    "插件 CLSID/类型写入",
                    4,
                    edge=edge_id,
                    timestamp=ts,
                    behavior="setAttribute plugin identifier",
                    meaning="脚本写入插件 CLSID 或类型标识，指向具体插件利用承载。",
                    details=value,
                    labels=("plugin_identifier", "exploit_candidate"),
                )

        if etype == "request start":
            target_url = tgt_node.get("url", "")
            if target_url and is_cross_origin_url(target_url, root_url) and not is_common_benign_external(target_url):
                add_evidence(
                    evidence,
                    family,
                    "外部网络请求",
                    2,
                    edge=edge_id,
                    timestamp=ts,
                    behavior=f"request {rtype or 'resource'}",
                    meaning="浏览器向外部域发起资源请求，可作为 IOC 和网络侧证据。",
                    details=target_url,
                    labels=("network_request", "ioc"),
                )

        if etype in ("read storage call", "storage set", "storage read result"):
            add_evidence(
                evidence,
                family,
                "存储访问",
                2,
                edge=edge_id,
                timestamp=ts,
                behavior=etype,
                meaning="脚本访问 cookie/local/session storage，可能与会话识别、去重或状态控制有关。",
                details=value or trim(node_text(src_node)) or trim(node_text(tgt_node)),
                labels=("storage_access",),
            )

        if etype == "js call and result":
            method = tgt_node.get("method", "")
            if method and any(api in method for api in ENV_APIS):
                add_evidence(
                    evidence,
                    family,
                    "API 调用证据",
                    2,
                    edge=edge_id,
                    timestamp=ts,
                    behavior=method,
                    meaning="脚本实际调用环境探测 API，边关系证明了调用主体与被调接口。",
                    details=method,
                    labels=("api_call", "environment_detection"),
                )

    return dedupe_evidence(evidence)


def dedupe_evidence(items):
    seen = set()
    result = []
    for item in items:
        key = (item.rule, item.node_id, item.edge, item.behavior, item.details)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return sorted(result, key=lambda x: (safe_int(x.timestamp), -x.severity, x.rule, x.node_id, x.edge))


def safe_int(value):
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return 10**12


def score_nodes(evidence):
    scores = Counter()
    labels = defaultdict(set)
    for ev in evidence:
        ids = []
        if ev.node_id:
            ids.append(ev.node_id)
        if ev.edge:
            ids.extend(ev.edge.split("->", 1))
        for nid in ids:
            scores[nid] += ev.severity
            labels[nid].update(ev.labels)
    return scores, labels


def extract_attack_chain(nodes, edges, outgoing, root_url, evidence, limit=14):
    scores, labels = score_nodes(evidence)
    root_nodes = [
        nid
        for nid, node in nodes.items()
        if node.get("node type") == "DOM root" and same_site(node.get("url", ""), root_url)
    ]
    if not root_nodes:
        root_nodes = [nid for nid, node in nodes.items() if node.get("node type") == "DOM root"]

    preferred_edges = {
        "execute",
        "create node",
        "set attribute",
        "insert node",
        "cross DOM",
        "request start",
        "request complete",
        "request redirect",
        "js call and result",
        "read storage call",
        "storage set",
    }

    candidates = []
    for root in root_nodes:
        queue = deque([(root, [root], 0)])
        seen = {(root, 0)}
        while queue:
            nid, path, depth = queue.popleft()
            path_score = sum(scores[p] for p in path)
            if depth >= 2 and path_score:
                candidates.append((path_score + depth, path))
            if depth >= 8:
                continue
            next_edges = [
                edge
                for edge in outgoing.get(nid, [])
                if edge["attrs"].get("edge type", "") in preferred_edges
            ]
            next_edges.sort(
                key=lambda e: (
                    -scores[e["target"]],
                    safe_int(timestamp_for_edge(e)),
                    e["attrs"].get("edge type", ""),
                )
            )
            for edge in next_edges[:10]:
                nxt = edge["target"]
                state = (nxt, depth + 1)
                if state in seen:
                    continue
                seen.add(state)
                queue.append((nxt, path + [nxt], depth + 1))

    if not candidates:
        top = [nid for nid, _ in scores.most_common(limit)]
        return top

    candidates.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
    best = candidates[0][1]
    # Add high-signal nodes not reached by the best path, so the report remains useful on heavily pruned graphs.
    extras = [
        nid
        for nid, _ in scores.most_common(limit)
        if nid not in best and (scores[nid] >= 4 or labels[nid] & {"plugin_carrier", "environment_detection", "cookie_control"})
    ]
    return (best + extras)[:limit]


def node_summary(nid, nodes, labels):
    node = nodes.get(nid, {})
    title = node.get("node type", "")
    tag = node.get("tag name", "")
    url = node.get("url", "")
    method = node.get("method", "")
    source = node.get("source", "") or node.get("text", "")
    label_text = ", ".join(sorted(labels.get(nid, [])))
    parts = [nid, title]
    if tag:
        parts.append(tag)
    if label_text:
        parts.append(f"[{label_text}]")
    if url:
        parts.append(trim(url, 120))
    elif method:
        parts.append(method)
    elif source:
        parts.append(trim(source, 120))
    return " | ".join(parts)


def classify_pattern(evidence):
    labels = Counter()
    for ev in evidence:
        labels.update(ev.labels)

    patterns = []
    if labels["hidden_iframe"] and labels["cross_dom"]:
        patterns.append("隐藏 iframe / cross DOM landing 链路")
    if labels["environment_detection"] and labels["plugin_carrier"]:
        patterns.append("环境探测后插件利用投递")
    if labels["cookie_control"]:
        patterns.append("cookie 去重与受害者筛选")
    if labels["masquerade_resource"]:
        patterns.append("统计/广告/常用库伪装入口")
    if labels["obfuscation"]:
        patterns.append("混淆脚本加载器")
    if labels["plugin_identifier"]:
        patterns.append("插件 CLSID/类型定向利用")
    if not patterns:
        patterns.append("存在可疑执行链，需要结合剪枝上下文人工复核")
    return patterns


def phase_for_evidence(ev):
    labels = set(ev.labels)
    if labels & {"benign_external"}:
        return "6. 背景资源与噪声"
    if labels & {"initial_entry"}:
        return "1. 入口与触发"
    if labels & {"hidden_iframe", "hidden_layout", "cross_dom", "landing_transition", "set_src", "dynamic_target", "redirect_carrier"}:
        return "2. 隐藏跳转与 Landing"
    if labels & {"cookie_control", "victim_filtering", "storage_access", "environment_detection", "api_call"}:
        return "3. 筛选与环境探测"
    if labels & {"obfuscation", "loader", "masquerade_resource"}:
        return "4. 混淆解码与加载器"
    if labels & {"plugin_carrier", "plugin_identifier", "exploit_candidate", "network_request", "ioc"}:
        return "5. 利用承载与投递"
    if labels & {"iframe", "external_url", "external_resource", "landing_candidate"}:
        return "2. 隐藏跳转与 Landing"
    return "1. 入口与触发"


def evidence_by_phase(evidence):
    phases = {phase: [] for phase in PHASE_ORDER}
    for ev in evidence:
        phases[phase_for_evidence(ev)].append(ev)
    for phase in phases:
        phases[phase].sort(key=lambda ev: (-ev.severity, safe_int(ev.timestamp), ev.rule, ev.node_id, ev.edge))
    return phases


def phase_summary_sentence(phase, items):
    labels = Counter()
    rules = Counter()
    details = []
    for ev in items:
        labels.update(ev.labels)
        rules[ev.rule] += 1
        if ev.details:
            details.append(ev.details.lower())
    text = " ".join(details)

    if not items:
        return "未命中该阶段的高价值规则，可能已在剪枝中被删除，或样本没有体现该行为。"
    if phase == "1. 入口与触发":
        return f"该阶段保留了 {len(items)} 条入口相关证据，主要用于定位初始 DOM、初始脚本和外部入口资源。"
    if phase == "2. 隐藏跳转与 Landing":
        parts = []
        if labels["hidden_iframe"]:
            parts.append("存在动态 iframe 注入")
        if labels["cross_dom"]:
            parts.append("存在 cross DOM 跳转")
        if labels["set_src"]:
            parts.append("脚本写入跳转/资源目标")
        if labels["landing_candidate"]:
            parts.append("出现跨站 landing 候选")
        return "；".join(parts) + f"，共 {len(items)} 条证据支撑跳转链。"
    if phase == "3. 筛选与环境探测":
        parts = []
        if labels["environment_detection"]:
            parts.append("读取浏览器、插件、屏幕或来源信息")
        if labels["cookie_control"] or labels["storage_access"]:
            parts.append("访问 cookie/storage 做状态控制或去重")
        return "；".join(parts) + f"，说明样本存在受害者筛选或利用分支选择。"
    if phase == "4. 混淆解码与加载器":
        parts = []
        if labels["obfuscation"]:
            parts.append("脚本存在混淆、解码或动态写入")
        if labels["masquerade_resource"]:
            parts.append("外部资源命名具有统计/广告/常用库伪装特征")
        return "；".join(parts) + f"，共 {len(items)} 条证据显示加载器行为。"
    if phase == "5. 利用承载与投递":
        parts = []
        if labels["plugin_carrier"] or labels["plugin_identifier"]:
            parts.append("存在插件承载或插件类型标识")
        if labels["network_request"] or labels["ioc"]:
            parts.append("存在外部请求/IOC 候选")
        return "；".join(parts) + f"，用于支撑利用承载或投递判断。"
    if phase == "6. 背景资源与噪声":
        return f"保留 {len(items)} 条常见第三方或低风险外部资源，主要用于解释页面背景噪声。"
    return f"该阶段命中 {len(items)} 条证据。"


def timeline_edges_for_phase(phase, items, limit=6):
    if phase in ("1. 入口与触发", "6. 背景资源与噪声"):
        return sorted(items, key=lambda ev: (safe_int(ev.timestamp), ev.rule))[:limit]
    selected = [
        ev
        for ev in sorted(items, key=lambda ev: (safe_int(ev.timestamp), -ev.severity))
        if ev.severity >= 3 or phase in ("2. 隐藏跳转与 Landing", "3. 筛选与环境探测")
    ]
    return selected[:limit]


def family_hint(family, evidence):
    labels = Counter()
    detail_text = " ".join(ev.details.lower() for ev in evidence)
    for ev in evidence:
        labels.update(ev.labels)

    family_lower = family.lower()
    hints = []
    if "neutrino" in family_lower:
        hints.append("呈现 Neutrino 类统计伪装、指纹参数与隐藏 iframe landing 特征")
    elif "nuclear" in family_lower:
        hints.append("呈现 Nuclear 类广告注入、多跳 iframe 与 cookie 去重特征")
    elif "fiesta" in family_lower:
        hints.append("呈现 Fiesta/插件对象投递类特征")
    else:
        if "realstatistics" in detail_text or "llxfqt" in detail_text:
            hints.append("呈现 Neutrino 类统计伪装、指纹参数与隐藏 iframe landing 特征")
        if "holdencubscouts" in detail_text or "travelforward" in detail_text or labels["cookie_control"]:
            hints.append("呈现 Nuclear 类广告注入、多跳 iframe 与 cookie 去重特征")
        if "serveblog" in detail_text or labels["plugin_identifier"]:
            hints.append("呈现 Fiesta/插件对象投递类特征")
    if not hints:
        hints.append(f"{family} 样本需结合更多家族样本做进一步归因")
    return hints


def stage_narrative(family, evidence):
    labels = Counter()
    detail_text = " ".join(ev.details.lower() for ev in evidence)
    for ev in evidence:
        labels.update(ev.labels)

    family_lower = family.lower()
    if "neutrino" in family_lower or "realstatistics" in detail_text or "llxfqt" in detail_text:
        return (
            "从阶段看，该样本更像 Neutrino 的统计伪装链路：先出现 realstatistics 类外部脚本和客户端签名参数，"
            "随后通过隐藏 iframe 进入 llxfqt landing，并在 landing 中放置 OBJECT/EMBED 承载。"
        )
    if "nuclear" in family_lower or "holdencubscouts" in detail_text or "travelforward" in detail_text:
        return (
            "从阶段看，该样本更像 Nuclear 的多跳筛选链路：广告/第三方脚本先注入隐藏 iframe，"
            "再通过 cookie 去重控制重复触发，经过 holdencubscouts 中转后进入 travelforward landing，并执行插件探测。"
        )
    if "fiesta" in family_lower or "serveblog" in detail_text:
        return (
            "从阶段看，该样本更像 Fiesta 的对象投递链路：隐藏 iframe 进入 serveblog landing 后，"
            "核心混淆脚本进行插件和 Java 环境探测，并创建多个 OBJECT/CLSID 承载节点。"
        )
    if labels["hidden_iframe"] and labels["environment_detection"]:
        return "从阶段看，该样本呈现典型 EK 链路：隐藏跳转进入 landing 后进行环境探测，再进入利用承载或资源投递阶段。"
    return "从阶段看，该样本的核心链路仍需结合剪枝结果人工复核。"


def export_csv(path, evidence):
    with path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                "evidence_id",
                "family",
                "rule",
                "severity",
                "node_id",
                "edge",
                "timestamp",
                "behavior",
                "forensic_meaning",
                "details",
                "labels",
            ]
        )
        for ev in evidence:
            writer.writerow(
                [
                    ev.eid,
                    ev.family,
                    ev.rule,
                    ev.severity,
                    ev.node_id,
                    ev.edge,
                    ev.timestamp,
                    ev.behavior,
                    ev.forensic_meaning,
                    ev.details,
                    ";".join(ev.labels),
                ]
            )


def export_chain(path, family, nodes, evidence, chain):
    _, labels = score_nodes(evidence)
    with path.open("w", encoding="utf-8") as f:
        f.write(f"# {family} 攻击链候选\n\n")
        for i, nid in enumerate(chain, 1):
            f.write(f"{i}. {node_summary(nid, nodes, labels)}\n")


def write_evidence_table(f, items, limit=8):
    f.write("| ID | 规则 | 严重度 | 节点/边 | 时间 | 行为 | 细节 |\n")
    f.write("|---|---|---:|---|---:|---|---|\n")
    if not items:
        f.write("| - | - | - | - | - | - | - |\n")
        return
    for ev in items[:limit]:
        target = ev.node_id or ev.edge
        f.write(
            "| "
            + " | ".join(
                [
                    ev.eid,
                    ev.rule,
                    str(ev.severity),
                    target,
                    ev.timestamp,
                    trim(ev.behavior, 50),
                    trim(ev.details, 120).replace("|", "\\|"),
                ]
            )
            + " |\n"
        )


def export_report(path, graphml_path, family, nodes, edges, root_url, evidence, chain):
    scores, labels = score_nodes(evidence)
    rule_counts = Counter(ev.rule for ev in evidence)
    severity_counts = Counter(ev.severity for ev in evidence)
    patterns = classify_pattern(evidence)
    hints = family_hint(family, evidence)
    phases = evidence_by_phase(evidence)
    top = sorted(evidence, key=lambda ev: (-ev.severity, safe_int(ev.timestamp), ev.rule))[:18]

    with path.open("w", encoding="utf-8") as f:
        f.write(f"# {family} GraphML 取证报告\n\n")
        f.write("## 样本概况\n\n")
        f.write(f"- GraphML: `{graphml_path}`\n")
        f.write(f"- 入口 URL: `{root_url or 'unknown'}`\n")
        f.write(f"- 节点数: {len(nodes)}\n")
        f.write(f"- 边数: {len(edges)}\n")
        f.write(f"- 证据数: {len(evidence)}\n")
        f.write(f"- 严重度分布: {dict(sorted(severity_counts.items()))}\n\n")

        f.write("## 攻击模式判断\n\n")
        for item in patterns:
            f.write(f"- {item}\n")
        f.write("\n")
        f.write("## 家族特征提示\n\n")
        for item in hints:
            f.write(f"- {item}\n")
        f.write("\n")

        f.write("## 阶段化取证视图\n\n")
        f.write(stage_narrative(family, evidence) + "\n\n")
        for phase in PHASE_ORDER:
            items = phases.get(phase, [])
            if not items and phase == "6. 背景资源与噪声":
                continue
            f.write(f"### {phase}\n\n")
            f.write(f"- 阶段含义：{PHASE_DESCRIPTIONS[phase]}\n")
            f.write(f"- 阶段摘要：{phase_summary_sentence(phase, items)}\n")
            f.write(f"- 证据数量：{len(items)}\n\n")
            write_evidence_table(f, timeline_edges_for_phase(phase, items), limit=6)
            f.write("\n")

        f.write("## 主攻击链候选\n\n")
        for i, nid in enumerate(chain, 1):
            f.write(f"{i}. {node_summary(nid, nodes, labels)}\n")
        f.write("\n")

        f.write("## 高价值证据\n\n")
        f.write("| ID | 规则 | 阶段 | 严重度 | 节点/边 | 时间 | 行为 | 取证含义 | 细节 |\n")
        f.write("|---|---|---|---:|---|---:|---|---|---|\n")
        for ev in top:
            target = ev.node_id or ev.edge
            f.write(
                "| "
                + " | ".join(
                    [
                        ev.eid,
                        ev.rule,
                        phase_for_evidence(ev),
                        str(ev.severity),
                        target,
                        ev.timestamp,
                        trim(ev.behavior, 50),
                        trim(ev.forensic_meaning, 80),
                        trim(ev.details, 120).replace("|", "\\|"),
                    ]
                )
                + " |\n"
            )
        f.write("\n")

        f.write("## 规则命中统计\n\n")
        for rule, count in rule_counts.most_common():
            f.write(f"- {rule}: {count}\n")
        f.write("\n")

        f.write("## 结论摘要\n\n")
        f.write(
            textwrap.fill(
                stage_narrative(family, evidence)
                + " 本报告基于 GraphML 中的节点属性和边关系进行规则取证，按入口触发、隐藏跳转、筛选探测、混淆加载、利用投递和背景噪声进行阶段化组织。"
                "阶段化输出的价值在于，它不只列出 IOC，而是说明这些 IOC 和脚本行为处在攻击链的哪个位置；若用于正式取证，应保留原始 GraphML 与剪枝 GraphML 的节点映射，"
                "并结合网络日志、样本哈希和沙箱运行记录交叉验证。",
                width=88,
            )
        )
        f.write("\n")


def process_graphml(path, output_dir):
    family = family_from_path(path)
    nodes, edges, outgoing, incoming, root_url = read_graphml(path)
    evidence = apply_rules(family, nodes, edges, outgoing, incoming, root_url)
    chain = extract_attack_chain(nodes, edges, outgoing, root_url, evidence)

    family_dir = output_dir / family
    family_dir.mkdir(parents=True, exist_ok=True)
    export_csv(family_dir / "evidence.csv", evidence)
    export_chain(family_dir / "attack_chain.md", family, nodes, evidence, chain)
    export_report(family_dir / "forensic_report.md", path, family, nodes, edges, root_url, evidence, chain)
    return family, evidence, chain


def export_index(output_dir, results):
    index = output_dir / "README.md"
    with index.open("w", encoding="utf-8") as f:
        f.write("# GraphML 规则取证结果\n\n")
        f.write("| 家族 | 证据数 | 主模式 | 报告 |\n")
        f.write("|---|---:|---|---|\n")
        for family, evidence, _chain in results:
            patterns = "；".join(classify_pattern(evidence)[:3])
            f.write(f"| {family} | {len(evidence)} | {patterns} | [{family}/forensic_report.md]({family}/forensic_report.md) |\n")


def main():
    parser = argparse.ArgumentParser(description="Rule-based forensic extractor for PageGraph GraphML files.")
    parser.add_argument("inputs", nargs="*", help="GraphML files or directories. Defaults to current directory.")
    parser.add_argument("-o", "--output", default="forensic_output", help="Output directory.")
    args = parser.parse_args()

    roots = [Path(p) for p in args.inputs] if args.inputs else [Path(".")]
    graphml_files = []
    for root in roots:
        if root.is_dir():
            graphml_files.extend(sorted(root.rglob("*.graphml")))
        elif root.suffix.lower() == ".graphml":
            graphml_files.append(root)

    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for graphml in sorted(set(graphml_files)):
        results.append(process_graphml(graphml, output_dir))
    export_index(output_dir, results)
    print(f"Processed {len(results)} graphml files. Output: {output_dir}")


if __name__ == "__main__":
    main()
