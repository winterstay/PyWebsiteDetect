#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sink node detection for PageGraph GraphML files

Usage:
  python sink.py <input_folder> <output_file>

Output format:
  - Overview: Total files processed, files with sinks, files without sinks
  - Per-file: filename, sink_count
"""

import argparse
import os
import xml.etree.ElementTree as ET
from collections import defaultdict


def parse_graphml(file_path):
    """Parse GraphML file and return nodes, edges, and adjacency lists"""
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}
    tree = ET.parse(file_path)
    root = tree.getroot()

    # Build key mapping
    node_key_map = {}
    edge_key_map = {}
    for k in root.findall("g:key", ns):
        kid = k.attrib.get("id")
        kfor = k.attrib.get("for")
        # Try different ways to get attr.name
        attr_name = k.attrib.get("attr.name")
        if not attr_name:
            attr_name = k.attrib.get("{http://graphml.graphdrawing.org/xmlns}attr.name")
        if not attr_name:
            attr_name = kid  # Fallback to key ID if no attr.name
        if kfor == "node":
            node_key_map[kid] = attr_name
        elif kfor == "edge":
            edge_key_map[kid] = attr_name

    # Extract nodes
    nodes = {}
    g_el = root.find("g:graph", ns)
    if g_el is None:
        return {}, {}, {}, {}

    for n in g_el.findall("g:node", ns):
        nid = n.attrib["id"]
        attrs = {}
        for d in n.findall("g:data", ns):
            key_id = d.attrib.get("key")
            name = node_key_map.get(key_id, key_id)
            attrs[name] = (d.text or "").strip()
        nodes[nid] = attrs

    # Extract edges and build adjacency lists
    edges = {}
    out_edges = defaultdict(list)
    in_edges = defaultdict(list)

    for e in g_el.findall("g:edge", ns):
        eid = e.attrib.get("id", "")
        src = e.attrib["source"]
        tgt = e.attrib["target"]
        attrs = {}
        for d in e.findall("g:data", ns):
            key_id = d.attrib.get("key")
            name = edge_key_map.get(key_id, key_id)
            attrs[name] = (d.text or "").strip()
        edges[eid] = {
            "source": src,
            "target": tgt,
            "attrs": attrs
        }
        out_edges[src].append(eid)
        in_edges[tgt].append(eid)

    return nodes, edges, out_edges, in_edges


def is_js_code(text):
    """Check if text contains JavaScript code"""
    js_keywords = [
        "function", "var", "let", "const", "if", "else", "for", "while",
        "return", "console", "document", "window", "eval", "setTimeout"
    ]
    text = text.lower()
    for keyword in js_keywords:
        if keyword in text:
            return True
    return False


def detect_sinks(nodes, edges, out_edges):
    """Detect sink nodes based on the specified criteria"""
    sinks = []

    for node_id, node_attrs in nodes.items():
        node_type = node_attrs.get("node type")
        
        # Check for frame owner with child frame owner
        if node_type == "frame owner":
            # Check if any direct child is also a frame owner
            has_child_frame_owner = False
            for eid in out_edges.get(node_id, []):
                edge = edges.get(eid)
                if edge:
                    target_id = edge["target"]
                    target_attrs = nodes.get(target_id, {})
                    if target_attrs.get("node type") == "frame owner":
                        has_child_frame_owner = True
                        break
            if has_child_frame_owner:
                sinks.append((node_id, "FrameOwner"))
        
        # Check for HTML element with SCRIPT tag and request start edge
        if node_type == "HTML element":
            tag_name = node_attrs.get("tag name", "").upper()
            if tag_name == "SCRIPT":
                # Check for request start edge
                has_request_start = False
                for eid in out_edges.get(node_id, []):
                    edge = edges.get(eid)
                    if edge:
                        edge_type = edge["attrs"].get("edge type", "")
                        if edge_type == "request start":
                            has_request_start = True
                            break
                if has_request_start:
                    sinks.append((node_id, "ScriptRequest"))
        
        # Continue with script node detection
        if node_type != "script":
            continue

        # Check outgoing edges from script node
        connected_nodes = set()
        web_api_attributes = []
        
        for eid in out_edges.get(node_id, []):
            edge = edges.get(eid)
            if edge:
                target_id = edge["target"]
                target_attrs = nodes.get(target_id, {})
                target_type = target_attrs.get("node type")
                connected_nodes.add((target_id, target_type))
                
                # Collect web API attributes
                if target_type == "web API":
                    d19_attr = target_attrs.get("method", "")
                    if d19_attr:
                        web_api_attributes.append(d19_attr)

        # Check if script connects to both HTML element and text node
        has_html_element = any(ntype == "HTML element" for _, ntype in connected_nodes)
        has_text_node = any(ntype == "text node" for _, ntype in connected_nodes)

        if has_html_element and has_text_node:
            # Check text nodes for JS code
            for nid, ntype in connected_nodes:
                if ntype == "text node":
                    text_content = nodes.get(nid, {}).get("text", "")
                    if is_js_code(text_content):
                        sinks.append((node_id, "HTML+Text"))
                        break
        
        # Define suspicious web API attributes
        suspicious_attrs = {
            "Navigator.javaEnabled",
            "Navigator.plugins.get",
            "Navigator.appVersion.get",
            "Navigator.userAgent",
            "Navigator.platform",
            "Navigator.language",
            "Navigator.appName",
            "Navigator.cookieEnabled"
        }
        
        # Define Location-related API attributes
        location_attrs = {
            "Location.href.set",
            "Location.toString",
            "Location.assign",
            "Location.replace",
            "Location.reload",
            "Location.hash.set",
            "Location.pathname.set",
            "Location.search.set"
        }
        
        # Count matches for both types
        matching_attrs = [attr for attr in web_api_attributes if attr in suspicious_attrs]
        location_matches = [attr for attr in web_api_attributes if attr in location_attrs]
        
        # Check if script connects to at least two web API nodes with specific attributes
        if len(web_api_attributes) >= 2:
            # Either 2+ from same category, or 1+ from each category
            if len(matching_attrs) >= 2 or len(location_matches) >= 2 or (len(matching_attrs) >= 1 and len(location_matches) >= 1):
                sinks.append((node_id, "WebAPI"))
            
            # Check for Screen + Location API combination
            screen_attrs = {
                "Screen.width.get",
                "Screen.height.get",
                "Screen.colorDepth.get",
                "Screen.availWidth.get",
                "Screen.availHeight.get",
                "Screen.pixelDepth.get"
            }
            
            screen_matches = [attr for attr in web_api_attributes if attr in screen_attrs]
            location_api_matches = [attr for attr in web_api_attributes if attr in location_attrs]
            
            # If both Screen and Location APIs are present, consider it a sink
            if len(screen_matches) >= 1 and len(location_api_matches) >= 1:
                sinks.append((node_id, "Screen+Location"))
        
        # Check for single Location.replace call (malicious redirect)
        if len(web_api_attributes) == 1 and web_api_attributes[0] == "Location.replace":
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Also check if script source contains location.replace or direct location assignment
        # Try different ways to get script content
        script_content = node_attrs.get("source", "").lower()
        if not script_content:
            script_content = node_attrs.get("d41", "").lower()
        if not script_content:
            script_content = ""
        
        # Check for location.replace and its variants
        if "location.replace" in script_content or "top.location.replace" in script_content or "self.location.replace" in script_content:
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Check for direct location assignment and its variants
        if ("location=" in script_content or "this.location=" in script_content or "top.location=" in script_content or "self.location=" in script_content or "top.location.href=" in script_content or "self.location.href=" in script_content or "window.location.href=" in script_content) and ("http://" in script_content or "https://" in script_content or "/" in script_content):
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Check for obfuscated location assignment (common in malicious scripts)
        # Look for patterns like: this["l"+...+"n"] or similar obfuscation techniques
        if "this[" in script_content and ("l" in script_content and "o" in script_content and "c" in script_content and "a" in script_content and "t" in script_content and "i" in script_content and "o" in script_content and "n" in script_content):
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Check for suspicious script patterns that indicate obfuscated redirects
        if ("charcodeat" in script_content or "fromcharcode" in script_content or "tostring" in script_content):
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Check for complex obfuscation patterns with function calls and string manipulation
        if ("function" in script_content and "return" in script_content and "+" in script_content) and ("this[" in script_content or "this." in script_content):
            sinks.append((node_id, "MaliciousRedirect"))
        
        # Check for Flash SWF delivery sink
        script_content = node_attrs.get("source", "").lower()
        
        # Flash detection and version checking indicators
        flash_detection = [
            "activexobject",
            "flash",
            "flashplayer",
        ]
        
        # SWF loading indicators (more specific to malicious patterns)
        swf_loading = [
            ".swf",
            "embed",
            "object"
        ]
        
        # DOM injection indicators
        dom_injection = [
            "createelement",
            "appendchild"
        ]
        
        # Check if Flash-related indicators exist
        has_flash_detection = any(indicator in script_content for indicator in flash_detection)
        has_swf_loading = any(indicator in script_content for indicator in swf_loading)
        has_dom_injection = any(indicator in script_content for indicator in dom_injection)
        
        # Check for remote SWF loading (more strict)
        has_remote_swf = False
        remote_swf_patterns = ["http://", "https://", "//"]
        for pattern in remote_swf_patterns:
            if pattern in script_content and ".swf" in script_content:
                # Check if it's a direct assignment or manipulation
                if "=" in script_content.split(".swf")[0]:
                    has_remote_swf = True
                    break
        
        # Tighter rules for Flash SWF delivery
        # Require either:
        # 1. Remote SWF loading (more reliable indicator)
        # OR
        # 2. Flash detection + SWF loading + DOM injection (combination of suspicious activities)
        if has_remote_swf or (has_flash_detection and has_swf_loading and has_dom_injection):
            sinks.append((node_id, "FlashSWF"))
        
        # Check for eval with execScript or charCodeAt
        d37_attr = node_attrs.get("script type", "").lower()
        d41_attr = node_attrs.get("source", "")
        
        if d37_attr == "eval" and d41_attr:
            # Check for execScript or charCodeAt usage
            # Remove HTML entities
            clean_code = d41_attr.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
            # Convert to lowercase for case-insensitive matching
            lower_code = clean_code.lower()
            # Check for execScript (including split across multiple lines or with comments)
            has_execscript = "execscript" in lower_code
            # Check for charCodeAt
            has_charcodeat = "charcodeat" in lower_code
            
            if has_execscript or has_charcodeat:
                sinks.append((node_id, "EvalObfuscated"))
        
        # Check for multiple sensitive APIs in script content
        if d41_attr:
            # Define sensitive API categories
            sensitive_apis = {
                # Code execution
                "code_execution": [
                    "eval(", "new function(", "settimeout(", "setinterval(", "execscript("
                ],
                # DOM manipulation
                "dom_manipulation": [
                    "document.write(", "innerhtml", "insertadjacenthtml("
                ],
                # Network requests
                "network": [
                    "xmlhttprequest", "fetch(", "activexobject(", "xmlhttp"
                ],
                # Browser information
                "browser_info": [
                    "navigator.useragent", "navigator.platform", "navigator.language", "navigator.javaenabled"
                ],
                # Storage
                "storage": [
                    "localstorage", "sessionstorage", "document.cookie"
                ],
                # URL manipulation
                "url": [
                    "location.href", "location.replace(", "location.assign("
                ],
                # Obfuscation
                "obfuscation": [
                    "atob(", "btoa(", "encodeuricomponent(", "decodeuricomponent(", "fromcharcode("
                ]
            }
            
            # Count sensitive API usage
            clean_code = d41_attr.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
            lower_code = clean_code.lower()
            api_count = 0
            categories_used = set()
            
            for category, apis in sensitive_apis.items():
                for api in apis:
                    if api in lower_code:
                        api_count += 1
                        categories_used.add(category)
                        break  # Count each category only once
            
            # Consider as sink if using multiple sensitive APIs across different categories
            # This helps distinguish malicious from benign usage
            if api_count >= 3 or (api_count >= 2 and len(categories_used) >= 2):
                sinks.append((node_id, "SensitiveAPI"))

    return sinks


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input_folder", help="Path to folder containing GraphML files")
    ap.add_argument("output_file", help="Path to output summary file")
    args = ap.parse_args()

    input_folder = args.input_folder
    output_file = args.output_file

    if not os.path.isdir(input_folder):
        raise SystemExit(f"Error: {input_folder} is not a valid directory")

    graphml_files = [f for f in os.listdir(input_folder) if f.endswith('.graphml')]

    if not graphml_files:
        raise SystemExit(f"No .graphml files found in {input_folder}")

    print(f"Processing {len(graphml_files)} files...")

    results = []
    files_with_sinks = 0
    files_without_sinks = 0

    for filename in sorted(graphml_files):
        file_path = os.path.join(input_folder, filename)
        print(f"Processing: {filename}")

        try:
            nodes, edges, out_edges, _ = parse_graphml(file_path)
            sinks = detect_sinks(nodes, edges, out_edges)
            sink_count = len(sinks)
            results.append((filename, sink_count, sinks))

            if sink_count > 0:
                files_with_sinks += 1
                # Format sink nodes with rule information
                formatted_sinks = [f"{node_id}({rule})" for node_id, rule in sinks]
                print(f"  Found {sink_count} sink nodes: {formatted_sinks}")
            else:
                files_without_sinks += 1
                print(f"  No sink nodes found")

        except Exception as e:
            print(f"  Error processing file: {e}")
            results.append((filename, 0, []))
            files_without_sinks += 1

    # Write output
    with open(output_file, 'w', encoding='utf-8') as f:
        # Write overview
        f.write(f"Total files processed: {len(graphml_files)}\n")
        f.write(f"Files with sinks: {files_with_sinks}\n")
        f.write(f"Files without sinks: {files_without_sinks}\n\n")
        f.write("Filename,Sink Count,Node IDs\n")
        
        # Write per-file results
        for filename, count, sinks in results:
            formatted_sinks = ";".join([f"{node_id}({rule})" for node_id, rule in sinks]) if sinks else ""
            f.write(f"{filename},{count},{formatted_sinks}\n")

    print(f"\nSummary written to: {output_file}")
    print(f"Total files: {len(graphml_files)}")
    print(f"Files with sinks: {files_with_sinks}")
    print(f"Files without sinks: {files_without_sinks}")


if __name__ == "__main__":
    main()
