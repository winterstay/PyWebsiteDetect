#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
import sys

# GraphML 命名空间
NS = {'g': 'http://graphml.graphdrawing.org/xmlns'}


def remove_isolated_and_specific_nodes(in_path: Path, out_path: Path):
    """
    处理 graphml 文件：
    1. 去除孤立节点（没有连接任何边的节点）
    2. 去除 n1 到 n5 的特定节点
    """
    tree = ET.parse(in_path)
    root = tree.getroot()
    graph = root.find('g:graph', NS)
    if graph is None:
        raise RuntimeError(f"{in_path} 中未找到 <graph> 元素")

    # 获取所有节点和边
    nodes = list(graph.findall('g:node', NS))
    edges = list(graph.findall('g:edge', NS))

    before_nodes = len(nodes)
    before_edges = len(edges)

    # === 1. 建立节点连接性索引 ===
    connected_nodes = set()  # 有边连接的节点
    
    for edge in edges:
        src = edge.get('source')
        tgt = edge.get('target')
        if src:
            connected_nodes.add(src)
        if tgt:
            connected_nodes.add(tgt)

    # === 2. 确定要删除的节点 ===
    nodes_to_remove = set()
    
    # 找出孤立节点（没有连接任何边的节点）
    all_node_ids = {node.get('id') for node in nodes if node.get('id')}
    isolated_nodes = all_node_ids - connected_nodes
    nodes_to_remove.update(isolated_nodes)
    
    # 添加特定节点 n1 到 n5
    specific_nodes = {f'n{i}' for i in range(1, 6)}  # n1, n2, n3, n4, n5
    nodes_to_remove.update(specific_nodes)

    # === 3. 找出需要删除的边（指向要删除节点的边） ===
    edges_to_remove = set()
    for edge in edges:
        src = edge.get('source')
        tgt = edge.get('target')
        if src in nodes_to_remove or tgt in nodes_to_remove:
            edges_to_remove.add(edge)

    # === 4. 执行删除 ===
    # 先删除边
    for edge in edges_to_remove:
        try:
            graph.remove(edge)
        except ValueError:
            pass

    # 再删除节点
    for node in nodes:
        node_id = node.get('id')
        if node_id in nodes_to_remove:
            try:
                graph.remove(node)
            except ValueError:
                pass

    # === 5. 统计结果 ===
    after_nodes = len(list(graph.findall('g:node', NS)))
    after_edges = len(list(graph.findall('g:edge', NS)))

    # 写回文件
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    # 注册命名空间以避免 ns0: 前缀
    ET.register_namespace('', NS['g'])
    tree.write(out_path, encoding='utf-8', xml_declaration=True)

    return before_nodes, before_edges, after_nodes, after_edges, len(isolated_nodes), len(specific_nodes & all_node_ids)


def process_path(input_path: Path, output_path: Path):
    if input_path.is_file():
        # 单文件模式
        if output_path.is_dir():
            out_file = output_path / input_path.name
        else:
            out_file = output_path

        b_nodes, b_edges, a_nodes, a_edges, isolated, specific = remove_isolated_and_specific_nodes(input_path, out_file)
        print(f"[process] {input_path} -> {out_file}")
        print(f"  before: nodes={b_nodes}, edges={b_edges}")
        print(f"  after : nodes={a_nodes}, edges={a_edges}")
        print(f"  removed: isolated_nodes={isolated}, specific_nodes(n1-n5)={specific}")

    elif input_path.is_dir():
        # 目录模式
        if output_path.exists() and output_path.is_file():
            raise RuntimeError("当输入为目录时，输出路径不能是文件，请给一个目录作为输出路径。")
        output_path.mkdir(parents=True, exist_ok=True)

        graphml_files = list(input_path.rglob("*.graphml"))
        if not graphml_files:
            print(f"在目录 {input_path} 中未找到任何 .graphml 文件")
            return

        for f in graphml_files:
            rel = f.relative_to(input_path)
            out_file = output_path / rel
            b_nodes, b_edges, a_nodes, a_edges, isolated, specific = remove_isolated_and_specific_nodes(f, out_file)
            print(f"[process] {f} -> {out_file}")
            print(f"  before: nodes={b_nodes}, edges={b_edges}")
            print(f"  after : nodes={a_nodes}, edges={a_edges}")
            print(f"  removed: isolated_nodes={isolated}, specific_nodes(n1-n5)={specific}")
    else:
        raise RuntimeError(f"输入路径不存在：{input_path}")


def main():
    parser = argparse.ArgumentParser(
        description="去除 graphml 中的孤立节点和特定节点(n1-n5)"
    )
    parser.add_argument("input", help="输入文件或目录（.graphml 或包含 .graphml 的目录）")
    parser.add_argument("output", help="输出文件或目录")
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    try:
        process_path(input_path, output_path)
    except Exception as e:
        print(f"错误：{e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()