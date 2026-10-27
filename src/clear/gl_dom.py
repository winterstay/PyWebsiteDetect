#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import xml.etree.ElementTree as ET
from pathlib import Path
from copy import deepcopy
from collections import defaultdict
import re
import sys

# GraphML 命名空间
NS = {'g': 'http://graphml.graphdrawing.org/xmlns'}


def node_type(node):
    """获取节点类型（data key='d23'）"""
    d = node.find("g:data[@key='d23']", NS)
    return d.text if d is not None else None


def edge_type(edge):
    """获取边类型（data key='d9'）"""
    d = edge.find("g:data[@key='d9']", NS)
    return d.text if d is not None else None


def process_graphml_file(in_path: Path, out_path: Path):
    """
    对单个 graphml 文件做折叠处理：
    A --document--> B(HTML element/text node) --XXX--> C
    折叠为：
    A --XXX--> C
    多层 HTML element/text node 连锁时，会一直折叠到最顶层"保留的父节点"。
    """
    tree = ET.parse(in_path)
    root = tree.getroot()
    graph = root.find('g:graph', NS)
    if graph is None:
        raise RuntimeError(f"{in_path} 中未找到 <graph> 元素")

    # 所有节点 & 边（原始）
    nodes = list(graph.findall('g:node', NS))
    edges = list(graph.findall('g:edge', NS))

    before_nodes = len(nodes)
    before_edges = len(edges)

    # === 1. 建立入边 / 出边索引（基于原始图） ===
    incoming = defaultdict(list)  # node_id -> [edges -> node_id]
    outgoing = defaultdict(list)  # node_id -> [edges from node_id]
    for e in edges:
        src = e.get('source')
        tgt = e.get('target')
        if tgt:
            incoming[tgt].append(e)
        if src:
            outgoing[src].append(e)

    # === 2. 找出需要折叠的 HTML element 和 text node 节点 ===
    removable = set()     # 要删除的 HTML element 和 text node 节点 id
    parent_edge = {}      # node_id -> 唯一的 document 入边

    for node in nodes:
        nid = node.get('id')
        if not nid:
            continue

        # 处理 HTML element 和 text node
        if node_type(node) not in ['HTML element', 'text node']:
            continue

        ins = incoming.get(nid, [])
        if len(ins) != 1:
            # 入边不是 1 条，跳过
            continue

        in_edge = ins[0]
        if edge_type(in_edge) != 'document':
            # 唯一入边不是 document 类型，跳过
            continue

        removable.add(nid)
        parent_edge[nid] = in_edge

    # === 3. 计算每个待删节点的"最终父节点" ===
    # 多层 HTML element/text node 连在一起时，要一直往上找，直到遇到一个不再删除的父节点
    final_parent = {}  # node_id -> 最终父节点 id 或 None

    def get_final_parent(nid):
        if nid in final_parent:
            return final_parent[nid]

        in_edge = parent_edge.get(nid)
        if not in_edge:
            final_parent[nid] = None
            return None

        parent_id = in_edge.get('source')
        if not parent_id:
            final_parent[nid] = None
            return None

        if parent_id in removable:
            # 父节点也会被折叠，继续向上找
            fp = get_final_parent(parent_id)
        else:
            # 父节点不会被折叠，它就是最终父节点
            fp = parent_id

        final_parent[nid] = fp
        return fp

    for nid in removable:
        get_final_parent(nid)

    # === 4. 计算当前已有最大 edge id 序号，用于生成新边 id ===
    max_id_num = 0
    for e in edges:
        eid = e.get('id') or ""
        m = re.match(r'e(\d+)$', eid)
        if m:
            max_id_num = max(max_id_num, int(m.group(1)))

    def new_edge_id():
        nonlocal max_id_num
        max_id_num += 1
        return f"e{max_id_num}"

    # === 5. 真正执行折叠：重接边 + 标记待删节点/边 ===
    edges_to_remove = set()
    nodes_to_remove = set()
    edges_to_add = []

    id2node = {n.get('id'): n for n in nodes}

    for nid in removable:
        node = id2node.get(nid)
        if node is None:
            continue

        fp = final_parent.get(nid)
        if not fp:
            # 找不到"活着的"最终父节点，就不折这个点
            continue

        # 删除唯一 document 入边：A --document--> B
        in_edge = parent_edge.get(nid)
        if in_edge is not None:
            edges_to_remove.add(in_edge)

        # 所有从 B 出发的边：B --XXX--> C
        outs = outgoing.get(nid, [])
        for out_edge in outs:
            child_id = out_edge.get('target')
            if not child_id:
                continue

            # 新建一条边：FinalParent(B) --XXX--> C
            new_e = deepcopy(out_edge)
            new_e.set('id', new_edge_id())
            new_e.set('source', fp)
            new_e.set('target', child_id)
            edges_to_add.append(new_e)

            # 原有的 B --XXX--> C 标记删除
            edges_to_remove.add(out_edge)

        # B(HTML element 或 text node 节点) 本身要删除
        nodes_to_remove.add(node)

    # === 6. 从 graph 中删除旧边和旧节点 ===
    for e in edges_to_remove:
        try:
            graph.remove(e)
        except ValueError:
            # 已被删过就忽略
            pass

    for n in nodes_to_remove:
        try:
            graph.remove(n)
        except ValueError:
            pass

    # === 7. 添加新边 ===
    for e in edges_to_add:
        graph.append(e)

    # === 8. 收尾：清理所有指向"已删除节点"的边（防止悬挂边） ===
    removed_ids = {n.get('id') for n in nodes_to_remove if n.get('id')}
    if removed_ids:
        for e in list(graph.findall('g:edge', NS)):
            src = e.get('source')
            tgt = e.get('target')
            if src in removed_ids or tgt in removed_ids:
                try:
                    graph.remove(e)
                except ValueError:
                    pass

    # === 9. 统计处理后的节点和边数量 ===
    after_nodes = len(list(graph.findall('g:node', NS)))
    after_edges = len(list(graph.findall('g:edge', NS)))

    # 写回文件（确保目录存在）
    out_path.parent.mkdir(parents=True, exist_ok=True)
    tree.write(out_path, encoding='utf-8', xml_declaration=True)

    return before_nodes, before_edges, after_nodes, after_edges


def process_path(input_path: Path, output_path: Path):
    if input_path.is_file():
        # 单文件模式
        if output_path.is_dir():
            # 输出是目录，则在目录下用同名文件
            out_file = output_path / input_path.name
        else:
            out_file = output_path

        b_nodes, b_edges, a_nodes, a_edges = process_graphml_file(input_path, out_file)
        print(f"[process] {input_path} -> {out_file}")
        print(f"  before: nodes={b_nodes}, edges={b_edges}")
        print(f"  after : nodes={a_nodes}, edges={a_edges}")

    elif input_path.is_dir():
        # 目录模式：递归处理所有 .graphml
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
            b_nodes, b_edges, a_nodes, a_edges = process_graphml_file(f, out_file)
            print(f"[process] {f} -> {out_file}")
            print(f"  before: nodes={b_nodes}, edges={b_edges}")
            print(f"  after : nodes={a_nodes}, edges={a_edges}")
    else:
        raise RuntimeError(f"输入路径不存在：{input_path}")


def main():
    parser = argparse.ArgumentParser(
        description="对 graphml 中 HTML element 和 text node 节点做折叠：A--document-->B--XXX-->C => A--XXX-->C（支持多层折叠）"
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
