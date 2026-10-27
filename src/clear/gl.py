import xml.etree.ElementTree as ET
import sys

def is_empty(text):
    return text is None or text.strip() == ""

def filter_graphml(input_file, output_file):
    # 注册默认namespace，避免 ns0 前缀
    ET.register_namespace("", "http://graphml.graphdrawing.org/xmlns")

    tree = ET.parse(input_file)
    root = tree.getroot()

    # GraphML namespace处理
    ns = {"g": "http://graphml.graphdrawing.org/xmlns"}

    graph = root.find("g:graph", ns)

    # 收集需要删除的节点ID
    remove_nodes = set()

    for node in graph.findall("g:node", ns):
        d23 = node.find('g:data[@key="d23"]', ns)
        d22 = node.find('g:data[@key="d22"]', ns)

        if d23 is not None and d23.text == "text node" and is_empty(d22.text):
            node_id = node.attrib["id"]
            remove_nodes.add(node_id)

    # 删除节点
    for node_id in remove_nodes:
        for node in graph.findall("g:node", ns):
            if node.attrib["id"] == node_id:
                graph.remove(node)

    # 删除相关边
    for edge in graph.findall("g:edge", ns):
        if edge.attrib.get("source") in remove_nodes or edge.attrib.get("target") in remove_nodes:
            graph.remove(edge)

    # 保存
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    print(f"过滤完成，已写入 {output_file}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("用法：python filter_graphml.py 输入文件.graphml 输出文件.graphml")
    else:
        filter_graphml(sys.argv[1], sys.argv[2])
