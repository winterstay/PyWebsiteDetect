#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import xml.etree.ElementTree as ET


def get_namespace(tag: str):
    """从 {namespace}tag 中提取 namespace 字符串"""
    if tag.startswith("{") and "}" in tag:
        return tag[1:tag.index("}")]
    return ""


def remove_parser_nodes(infile, outfile):
    # 解析 graphml
    tree = ET.parse(infile)
    root = tree.getroot()

    # 自动适配 namespace
    ns_uri = get_namespace(root.tag)
    if ns_uri:
        ns = {"g": ns_uri}
        node_xpath = ".//g:node"
        edge_xpath = ".//g:edge"
        data_xpath = "g:data"
        graph_xpath = ".//g:graph"
    else:
        ns = {}
        node_xpath = ".//node"
        edge_xpath = ".//edge"
        data_xpath = "data"
        graph_xpath = ".//graph"

    graph = root.find(graph_xpath, ns)
    if graph is None:
        print("GraphML 结构错误：找不到 <graph> 标签。")
        sys.exit(1)

    # --- 1. 找所有 parser 节点 ---
    parser_ids = set()
    for node in graph.findall(node_xpath, ns):
        for data in node.findall(data_xpath, ns):
            if data.attrib.get("key") == "d23":
                if (data.text or "").strip() == "parser":
                    parser_ids.add(node.attrib["id"])
                break

    if not parser_ids:
        print("没有发现 parser 节点。无需修改。")
        tree.write(outfile, encoding="utf-8", xml_declaration=True)
        return

    # --- 2. 删除 parser 节点 ---
    removed_nodes = 0
    for node in graph.findall(node_xpath, ns):
        if node.attrib.get("id") in parser_ids:
            graph.remove(node)
            removed_nodes += 1

    # --- 3. 删除所有与 parser 节点相关的边 ---
    removed_edges = 0
    for edge in graph.findall(edge_xpath, ns):
        src = edge.attrib.get("source")
        tgt = edge.attrib.get("target")
        if src in parser_ids or tgt in parser_ids:
            graph.remove(edge)
            removed_edges += 1

    # 保存
    ET.register_namespace("", ns_uri) if ns_uri else None
    tree.write(outfile, encoding="utf-8", xml_declaration=True)

    print("=== gl_parser 处理完成 ===")
    print(f"删除 parser 节点数量: {removed_nodes}")
    print(f"删除相关 edge 数量:   {removed_edges}")
    print(f"输出文件: {outfile}")


def main():
    if len(sys.argv) != 3:
        print("用法: python gl_parser.py input.graphml output.graphml")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    if not os.path.isfile(infile):
        print(f"输入文件不存在: {infile}")
        sys.exit(1)

    remove_parser_nodes(infile, outfile)


if __name__ == "__main__":
    main()
