#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import xml.etree.ElementTree as ET
import math
import re
from collections import Counter


# =========================
# 可调参数
# =========================
LONG_STRING_THRESHOLD = 80
MAX_MATCHED_ITEMS = 10


# =========================
# 基础工具函数
# =========================
def get_namespace(tag: str):
    """从 {namespace}tag 中提取 namespace"""
    if tag.startswith("{") and "}" in tag:
        return tag[1:tag.index("}")]
    return ""


def calculate_entropy(s: str):
    """计算字符串熵"""
    if not s:
        return 0.0
    counter = Counter(s)
    entropy = 0.0
    total = len(s)
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy


def calculate_url_features(url: str):
    """计算 URL 特征"""
    if not url:
        return {
            "url_length": 0,
            "url_entropy": 0,
            "subdomain_levels": 0,
            "has_at_symbol": False,
            "special_char_count": 0,
            "has_encoding": False,
            "has_parameters": False
        }

    url_length = len(url)
    url_entropy = calculate_entropy(url)

    if "://" in url:
        domain_part = url.split("://", 1)[1]
        if "/" in domain_part:
            domain_part = domain_part.split("/", 1)[0]
        subdomain_levels = len(domain_part.split(".")) - 1
    else:
        subdomain_levels = 0

    has_at_symbol = "@" in url
    special_chars = "!@#$%^&*()_+[]{}|;:,.<>?"
    special_char_count = sum(1 for c in url if c in special_chars)
    has_encoding = "%" in url
    has_parameters = "?" in url

    return {
        "url_length": url_length,
        "url_entropy": round(url_entropy, 4),
        "subdomain_levels": subdomain_levels,
        "has_at_symbol": has_at_symbol,
        "special_char_count": special_char_count,
        "has_encoding": has_encoding,
        "has_parameters": has_parameters
    }


# =========================
# script 特征提取辅助函数
# =========================
STRING_LITERAL_RE = re.compile(
    r'''
    "(?:\\.|[^"\\])*"      |
    '(?:\\.|[^'\\])*'      |
    `(?:\\.|[^`\\])*`
    ''',
    re.VERBOSE | re.DOTALL
)


def extract_string_literals(code: str):
    """提取字符串字面量"""
    if not code:
        return []
    return STRING_LITERAL_RE.findall(code)


def strip_quotes(s: str):
    """去掉字符串首尾引号"""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"', "`"):
        return s[1:-1]
    return s


def strip_comments_keep_strings(code: str):
    """
    去掉注释，但保留字符串。
    防止把字符串中的 // 误删。
    """
    if not code:
        return ""

    saved_strings = []

    def _save_string(m):
        saved_strings.append(m.group(0))
        return f"__STR_PLACEHOLDER_{len(saved_strings) - 1}__"

    tmp = STRING_LITERAL_RE.sub(_save_string, code)

    tmp = re.sub(r"/\*.*?\*/", " ", tmp, flags=re.DOTALL)
    tmp = re.sub(r"//.*?$", " ", tmp, flags=re.MULTILINE)

    for idx, s in enumerate(saved_strings):
        tmp = tmp.replace(f"__STR_PLACEHOLDER_{idx}__", s)

    return tmp


def mask_string_literals(code: str):
    """
    将字符串字面量替换为占位符，避免关键词只在字符串里出现时造成误报。
    """
    if not code:
        return ""
    return STRING_LITERAL_RE.sub('"__STR__"', code)


def regex_any(patterns, text: str):
    """任意一个正则命中即返回 True"""
    for p in patterns:
        if re.search(p, text, flags=re.IGNORECASE):
            return True
    return False


def count_unique_pattern_hits(pattern_dict, text: str):
    """统计命中的 pattern 数量，并返回命中的名字列表"""
    hits = []
    for name, pattern in pattern_dict.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            hits.append(name)
    return len(hits), hits


# =========================
# API 分类设计
# 不再用一个 api_keyword_count
# 而是拆成多个类别特征
# =========================
API_CATEGORY_PATTERNS = {
    # 1. 动态执行类
    "dynamic_execution": {
        "eval": r"\beval\s*\(",
        "new_Function": r"\bnew\s+Function\s*\(",
        "execScript": r"\bexecScript\s*\(",
        "setTimeout_string": r"\bsetTimeout\s*\(\s*['\"]",
        "setInterval_string": r"\bsetInterval\s*\(\s*['\"]",
    },

    # 2. 编码/解码/混淆辅助类
    "obfuscation_decode": {
        "atob": r"\batob\s*\(",
        "btoa": r"\bbtoa\s*\(",
        "unescape": r"\bunescape\s*\(",
        "fromCharCode": r"\bString\s*\.\s*fromCharCode\s*\(",
    },

    # 3. 网络通信/远程加载类
    "network_request": {
        "fetch": r"\bfetch\s*\(",
        "XMLHttpRequest": r"\bnew\s+XMLHttpRequest\s*\(",
        "axios": r"\baxios\s*\.\s*(get|post|put|delete|request)\s*\(",
        "jquery_ajax": r"\$\s*\.\s*(ajax|get|getJSON|post|getScript)\s*\(",
        "sendBeacon": r"\bnavigator\s*\.\s*sendBeacon\s*\(",
        "WebSocket": r"\bnew\s+WebSocket\s*\(",
        "importScripts": r"\bimportScripts\s*\(",
    },

    # 4. 存储访问类
    "storage_access": {
        "localStorage_get": r"\blocalStorage\s*\.\s*getItem\s*\(",
        "localStorage_set": r"\blocalStorage\s*\.\s*setItem\s*\(",
        "sessionStorage_get": r"\bsessionStorage\s*\.\s*getItem\s*\(",
        "sessionStorage_set": r"\bsessionStorage\s*\.\s*setItem\s*\(",
        "indexedDB": r"\bindexedDB\b",
    },

    # 5. 敏感数据访问类
    "sensitive_access": {
        "document_cookie": r"\bdocument\s*\.\s*cookie\b",
        "document_referrer": r"\bdocument\s*\.\s*referrer\b",
        "location_href": r"\blocation\s*\.\s*href\b",
        "navigator_userAgent": r"\bnavigator\s*\.\s*userAgent\b",
    },

    # 6. DOM 注入/页面写入类
    "dom_injection": {
        "document_write": r"\bdocument\s*\.\s*write\s*\(",
        "innerHTML_assign": r"\.\s*innerHTML\s*=",
        "outerHTML_assign": r"\.\s*outerHTML\s*=",
        "insertAdjacentHTML": r"\binsertAdjacentHTML\s*\(",
    },

    # 7. 动态脚本/资源加载类
    "dynamic_resource_loading": {
        "create_script_element": r"\bcreateElement\s*\(\s*['\"]script['\"]\s*\)",
        "script_src_assign": r"\.\s*src\s*=",
        "appendChild": r"\bappendChild\s*\(",
        "create_iframe_element": r"\bcreateElement\s*\(\s*['\"]iframe['\"]\s*\)",
    },

    # 8. 下载/文件生成类
    "download_file_ops": {
        "Blob": r"\bBlob\s*\(",
        "URL_createObjectURL": r"\bURL\s*\.\s*createObjectURL\s*\(",
        "anchor_download_assign": r"\.\s*download\s*=",
        "create_anchor_element": r"\bcreateElement\s*\(\s*['\"]a['\"]\s*\)",
    },

    # 9. 系统命令/本地执行类（主要兼容一些特殊脚本环境）
    "system_execution": {
        "child_process_require": r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)",
        "child_process_exec": r"\bchild_process\s*\.\s*(exec|execFile|spawn|fork)\s*\(",
        "direct_exec": r"\b(exec|execFile|spawn|fork)\s*\(",
        "WScript_Shell": r"\bActiveXObject\s*\(\s*['\"]WScript\.Shell['\"]\s*\)|\bWScript\.Shell\b",
        "system_like_func": r"\b(system|shell_exec|passthru|proc_open|popen|execve)\s*\(",
    }
}


def calculate_script_features(script_content: str, script_type: str):
    """
    计算 script 节点特征（低误报版）

    主特征：
    - calling_method
    - has_eval_exec
    - has_system_command
    - param_length
    - has_download_behavior
    - has_long_string
    - has_string_concatenation
    - entropy

    API 分类特征：
    - dynamic_execution_api_count
    - obfuscation_decode_api_count
    - network_request_api_count
    - storage_access_api_count
    - sensitive_access_api_count
    - dom_injection_api_count
    - dynamic_resource_loading_api_count
    - download_file_ops_api_count
    - system_execution_api_count
    """
    if not script_content:
        return {
            "calling_method": script_type or "unknown",
            "has_eval_exec": False,
            "has_system_command": False,
            "param_length": 0,
            "has_download_behavior": False,
            "has_long_string": False,
            "has_string_concatenation": False,
            "entropy": 0,
            "dynamic_execution_api_count": 0,
            "obfuscation_decode_api_count": 0,
            "network_request_api_count": 0,
            "storage_access_api_count": 0,
            "sensitive_access_api_count": 0,
            "dom_injection_api_count": 0,
            "dynamic_resource_loading_api_count": 0,
            "download_file_ops_api_count": 0,
            "system_execution_api_count": 0,
            "matched_api_categories": {},
            "max_string_length": 0
        }

    calling_method = script_type or "unknown"

    # 1. 去注释
    code_no_comments = strip_comments_keep_strings(script_content)

    # 2. 字符串掩码版，减少误报
    code_masked = mask_string_literals(code_no_comments)

    # 3. 长度与熵
    compact_code = re.sub(r"\s+", "", code_no_comments)
    param_length = len(compact_code)
    entropy = round(calculate_entropy(compact_code), 4)

    # ------------------------------------------------------------
    # A. 动态执行
    # ------------------------------------------------------------
    has_eval_exec = regex_any([
        r"\beval\s*\(",
        r"\bnew\s+Function\s*\(",
        r"\bexecScript\s*\(",
        r"\bsetTimeout\s*\(\s*['\"]",
        r"\bsetInterval\s*\(\s*['\"]",
    ], code_masked)

    # ------------------------------------------------------------
    # B. 系统命令执行
    # ------------------------------------------------------------
    has_child_process_import = bool(re.search(
        r"\brequire\s*\(\s*['\"]child_process['\"]\s*\)",
        code_no_comments,
        flags=re.IGNORECASE
    ))

    has_child_process_dot_call = bool(re.search(
        r"\bchild_process\s*\.\s*(exec|execFile|spawn|fork)\s*\(",
        code_masked,
        flags=re.IGNORECASE
    ))

    has_direct_exec_call = bool(re.search(
        r"\b(exec|execFile|spawn|fork)\s*\(",
        code_masked,
        flags=re.IGNORECASE
    ))

    has_wscript_shell = bool(re.search(
        r"\bActiveXObject\s*\(\s*['\"]WScript\.Shell['\"]\s*\)|\bWScript\.Shell\b",
        code_no_comments,
        flags=re.IGNORECASE
    ))

    has_server_side_exec = bool(re.search(
        r"\b(system|shell_exec|passthru|proc_open|popen|execve)\s*\(",
        code_masked,
        flags=re.IGNORECASE
    ))

    has_system_command = (
        has_child_process_dot_call
        or (has_child_process_import and has_direct_exec_call)
        or has_wscript_shell
        or has_server_side_exec
    )

    # ------------------------------------------------------------
    # C. 下载/远程拉取行为
    # ------------------------------------------------------------
    has_network_pull = regex_any([
        r"\bfetch\s*\(",
        r"\bnew\s+XMLHttpRequest\s*\(",
        r"\baxios\s*\.\s*(get|post|put|delete|request)\s*\(",
        r"\$\s*\.\s*(ajax|get|getJSON|post|getScript)\s*\(",
        r"\bnavigator\s*\.\s*sendBeacon\s*\(",
        r"\bimportScripts\s*\(",
        r"\bnew\s+WebSocket\s*\(",
    ], code_masked)

    has_anchor_download = bool(
        re.search(r"\bcreateElement\s*\(\s*['\"]a['\"]\s*\)", code_no_comments, flags=re.IGNORECASE)
        and re.search(r"\.\s*download\s*=", code_masked, flags=re.IGNORECASE)
    )

    has_blob_download = bool(
        re.search(r"\bBlob\s*\(", code_masked, flags=re.IGNORECASE)
        and re.search(r"\bURL\s*\.\s*createObjectURL\s*\(", code_masked, flags=re.IGNORECASE)
    )

    has_remote_script_load = bool(
        re.search(r"\bcreateElement\s*\(\s*['\"]script['\"]\s*\)", code_no_comments, flags=re.IGNORECASE)
        and re.search(r"\.\s*src\s*=", code_masked, flags=re.IGNORECASE)
    )

    has_download_behavior = (
        has_network_pull
        or has_anchor_download
        or has_blob_download
        or has_remote_script_load
    )

    # ------------------------------------------------------------
    # D. 长字符串
    # ------------------------------------------------------------
    string_literals = extract_string_literals(code_no_comments)
    cleaned_strings = [strip_quotes(s) for s in string_literals]
    max_string_length = max((len(s) for s in cleaned_strings), default=0)
    has_long_string = max_string_length >= LONG_STRING_THRESHOLD

    # ------------------------------------------------------------
    # E. 字符串拼接
    # ------------------------------------------------------------
    concat_patterns = [
        r"['\"][^'\"]{0,200}['\"]\s*\+\s*[A-Za-z_$\(\[\{]",
        r"\b[A-Za-z_$][A-Za-z0-9_$]*\s*\+\s*['\"][^'\"]{0,200}['\"]",
        r"\.\s*concat\s*\(",
    ]
    has_string_concatenation = regex_any(concat_patterns, code_no_comments)

    # ------------------------------------------------------------
    # F. API 分类统计
    # ------------------------------------------------------------
    category_feature_result = {}
    matched_api_categories = {}

    for category_name, pattern_dict in API_CATEGORY_PATTERNS.items():
        count, hits = count_unique_pattern_hits(pattern_dict, code_no_comments)
        category_feature_result[f"{category_name}_api_count"] = count
        matched_api_categories[category_name] = hits[:MAX_MATCHED_ITEMS]

    return {
        "calling_method": calling_method,
        "has_eval_exec": has_eval_exec,
        "has_system_command": has_system_command,
        "param_length": param_length,
        "has_download_behavior": has_download_behavior,
        "has_long_string": has_long_string,
        "has_string_concatenation": has_string_concatenation,
        "entropy": entropy,
        "max_string_length": max_string_length,
        **category_feature_result,
        "matched_api_categories": matched_api_categories
    }


# =========================
# graphml 解析
# =========================
def parse_graphml(path: str):
    """解析 graphml 文件，返回节点和边的信息"""
    tree = ET.parse(path)
    root = tree.getroot()

    ns_uri = get_namespace(root.tag)
    if ns_uri:
        ns = {"g": ns_uri}
        node_xpath = ".//g:node"
        edge_xpath = ".//g:edge"
        data_xpath = "g:data"
    else:
        ns = {}
        node_xpath = ".//node"
        edge_xpath = ".//edge"
        data_xpath = "data"

    nodes = {}
    edges = []
    node_types = {}
    timestamps = {}
    url_features = {}
    script_features = {}
    webapi_features = {}
    frame_owner_features = {}
    html_element_features = {}
    text_node_features = {}

    for node in root.findall(node_xpath, ns):
        nid = node.attrib.get("id")
        if not nid:
            continue

        node_type = None
        timestamp = 0
        url = None
        script_content = None
        script_type = None
        webapi_name = None
        frame_owner_info = None
        text_content = None

        for data in node.findall(data_xpath, ns):
            key = data.attrib.get("key", "")
            text = (data.text or "").strip()

            if key == "d23":      # 节点类型
                node_type = text
            elif key == "d27":    # 时间戳
                try:
                    timestamp = int(text)
                except ValueError:
                    pass
            elif key == "d44":    # URL
                url = text
            elif key == "d41":    # script 内容
                script_content = text
            elif key == "d37":    # script 类型
                script_type = text
            elif key == "d19":    # web api 名称
                webapi_name = text
            elif key == "d21":    # frame owner / html element 信息
                frame_owner_info = text
            elif key == "d22":    # text node 内容
                text_content = text

        nodes[nid] = {
            "type": node_type,
            "timestamp": timestamp
        }
        node_types[nid] = node_type
        timestamps[nid] = timestamp

        if node_type == "DOM root" and url:
            url_features[nid] = calculate_url_features(url)

        elif node_type == "resource" and url:
            url_features[nid] = calculate_url_features(url)

        elif node_type == "script" and script_content:
            script_features[nid] = calculate_script_features(script_content, script_type)

        elif node_type in ("web API", "WebAPI") and webapi_name:
            webapi_features[nid] = {"api_name": webapi_name}

        elif node_type == "frame owner" and frame_owner_info:
            frame_owner_features[nid] = {"frame_owner_info": frame_owner_info}

        elif node_type == "HTML element" and frame_owner_info:
            html_element_features[nid] = {"html_element_info": frame_owner_info}

        elif node_type == "text node" and text_content:
            text_node_features[nid] = {"text_entropy": round(calculate_entropy(text_content), 4)}

    for edge in root.findall(edge_xpath, ns):
        src = edge.attrib.get("source")
        tgt = edge.attrib.get("target")
        if src and tgt:
            edges.append((src, tgt))

    parents = {}
    children = {}
    for src, tgt in edges:
        parents.setdefault(tgt, []).append(src)
        children.setdefault(src, []).append(tgt)

    return (
        nodes, edges, parents, children, node_types, timestamps,
        url_features, script_features, webapi_features,
        frame_owner_features, html_element_features, text_node_features
    )


def parse_aaey(txt_path: str):
    """解析 aaey.txt 文件，返回每个文件的 sink 节点信息"""
    sink_info = {}

    with open(txt_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    for line in lines[5:]:
        line = line.strip()
        if not line:
            continue

        parts = line.split(",", 2)
        if len(parts) < 3:
            continue

        filename = parts[0].strip()

        try:
            _ = int(parts[1].strip())
        except ValueError:
            continue

        sink_nodes = parts[2].split(";") if parts[2].strip() else []
        sinks = []

        for sink in sink_nodes:
            sink = sink.strip()
            if "(" in sink and ")" in sink:
                node_id = sink.split("(", 1)[0].strip()
                node_type = sink.split("(", 1)[1].rstrip(")").strip()
                sinks.append((node_id, node_type))

        sink_info[filename] = sinks

    return sink_info


def get_web_api_nodes(node_types):
    """获取所有 WebAPI 节点"""
    return [
        nid for nid, node_type in node_types.items()
        if node_type in ("WebAPI", "web API")
    ]


def backtrack_path(start_node, parents, children, node_types, visited, web_api_nodes):
    """从 start_node 回溯到根节点，收集路径"""
    path = []
    current = start_node

    def collect_children(node):
        child_nodes = []
        stack = [node]
        while stack:
            n = stack.pop()
            if n not in visited:
                visited.add(n)
                child_nodes.append(n)
                if n in children:
                    for child in children[n]:
                        stack.append(child)
        return child_nodes

    child_nodes = collect_children(current)
    path.extend(child_nodes)

    while current in parents:
        found_parent = False
        for parent in parents[current]:
            if parent not in visited:
                visited.add(parent)
                path.append(parent)

                # 保留你原有逻辑
                for web_api in web_api_nodes:
                    if web_api not in visited:
                        visited.add(web_api)
                        path.append(web_api)

                current = parent
                found_parent = True
                break

        if not found_parent:
            break

    return path


def process_file(graphml_path: str, sink_info, output_dir: str):
    """处理单个 graphml 文件"""
    filename = os.path.basename(graphml_path)

    if filename not in sink_info:
        print(f"警告：文件 {filename} 在 aaey.txt 中没有找到 sink 节点信息")
        return

    sinks = sink_info[filename]
    if not sinks:
        print(f"警告：文件 {filename} 没有 sink 节点")
        return

    (
        nodes, edges, parents, children, node_types, timestamps,
        url_features, script_features, webapi_features,
        frame_owner_features, html_element_features, text_node_features
    ) = parse_graphml(graphml_path)

    web_api_nodes = get_web_api_nodes(node_types)

    sink_with_timestamp = []
    for node_id, node_type in sinks:
        if node_id in timestamps:
            sink_with_timestamp.append((node_id, node_type, timestamps[node_id]))

    if not sink_with_timestamp:
        print(f"警告：文件 {filename} 没有找到带时间戳的 sink 节点")
        return

    sink_with_timestamp.sort(key=lambda x: x[2], reverse=True)

    all_paths = []
    processed_sinks = set()

    for sink_node_id, sink_node_type, sink_timestamp in sink_with_timestamp:
        if sink_node_id in processed_sinks:
            continue

        visited = set()
        path = backtrack_path(
            sink_node_id, parents, children, node_types, visited, web_api_nodes
        )

        processed_sinks.update(visited & {nid for nid, _, _ in sink_with_timestamp})

        path_with_timestamp = [
            (nid, nodes[nid]["type"], nodes[nid]["timestamp"])
            for nid in path if nid in nodes
        ]
        path_with_timestamp.sort(key=lambda x: x[2])

        path_data = []
        for nid, node_type, timestamp in path_with_timestamp:
            node_info = f"{nid}({node_type})"

            if (node_type == "DOM root" or node_type == "resource") and nid in url_features:
                node_info = {
                    "node": node_info,
                    "url_features": url_features[nid]
                }

            elif node_type == "script" and nid in script_features:
                node_info = {
                    "node": node_info,
                    "script_features": script_features[nid]
                }

            elif node_type in ("web API", "WebAPI") and nid in webapi_features:
                node_info = {
                    "node": node_info,
                    "webapi_features": webapi_features[nid]
                }

            elif node_type == "frame owner" and nid in frame_owner_features:
                node_info = {
                    "node": node_info,
                    "frame_owner_features": frame_owner_features[nid]
                }

            elif node_type == "HTML element" and nid in html_element_features:
                node_info = {
                    "node": node_info,
                    "html_element_features": html_element_features[nid]
                }

            elif node_type == "text node" and nid in text_node_features:
                node_info = {
                    "node": node_info,
                    "text_node_features": text_node_features[nid]
                }

            path_data.append(node_info)

        all_paths.append(path_data)

    output_filename = os.path.splitext(filename)[0] + ".json"
    output_path = os.path.join(output_dir, output_filename)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(all_paths, f, ensure_ascii=False, indent=2)

    print(f"处理完成：{filename} -> {output_filename}，生成了 {len(all_paths)} 条路径")


def main():
    if len(sys.argv) != 4:
        print("用法: python pathTQ.py <graphml输入文件夹> <txt节点文件> <输出目录>")
        sys.exit(1)

    input_dir = sys.argv[1]
    txt_file = sys.argv[2]
    output_dir = sys.argv[3]

    if not os.path.isdir(input_dir):
        print(f"错误：输入文件夹 '{input_dir}' 不存在。")
        sys.exit(1)

    if not os.path.isfile(txt_file):
        print(f"错误：节点文件 '{txt_file}' 不存在。")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print("正在解析 aaey.txt 文件...")
    sink_info = parse_aaey(txt_file)
    print(f"解析完成，找到 {len(sink_info)} 个文件的 sink 节点信息")

    graphml_files = []
    for root, _, files in os.walk(input_dir):
        for file in files:
            if file.lower().endswith(".graphml"):
                graphml_files.append(os.path.join(root, file))

    if not graphml_files:
        print(f"错误：输入文件夹 '{input_dir}' 中没有找到 graphml 文件。")
        sys.exit(1)

    print(f"找到 {len(graphml_files)} 个 graphml 文件")
    print()

    for file in graphml_files:
        process_file(file, sink_info, output_dir)

    print()
    print("所有文件处理完成！")


if __name__ == "__main__":
    main()
