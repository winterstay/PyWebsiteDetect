from html import escape
from pathlib import Path


W, H = 1672, 941


def text_width_units(text):
    total = 0
    for ch in text:
        total += 2 if ord(ch) > 127 else 1
    return total


def wrap_text(text, max_units):
    lines = []
    for raw in text.split("\n"):
        if not raw:
            lines.append("")
            continue
        line = ""
        units = 0
        for token in raw.split(" "):
            token_units = text_width_units(token)
            spacer = 1 if line else 0
            if line and units + spacer + token_units > max_units:
                lines.append(line)
                line = token
                units = token_units
            else:
                line = token if not line else line + " " + token
                units += spacer + token_units
        if text_width_units(line) <= max_units:
            lines.append(line)
            continue
        current = ""
        current_units = 0
        for ch in line:
            ch_units = 2 if ord(ch) > 127 else 1
            if current and current_units + ch_units > max_units:
                lines.append(current)
                current = ch
                current_units = ch_units
            else:
                current += ch
                current_units += ch_units
        if current:
            lines.append(current)
    return lines


def marker():
    return (
        '<defs>'
        '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
        'markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#111"/>'
        '</marker>'
        '<filter id="soft" x="-8%" y="-8%" width="116%" height="116%">'
        '<feDropShadow dx="0" dy="1" stdDeviation="2" flood-color="#000" flood-opacity=".10"/>'
        '</filter>'
        '</defs>'
    )


def box(x, y, w, h, title, bullets=None, dashed=False, small=False):
    bullets = bullets or []
    dash = ' stroke-dasharray="10 7"' if dashed else ""
    font = 16 if small else 18
    title_font = 18 if small else 21
    max_units = max(10, int(w / (font * 0.60)))
    out = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="9" ry="9" '
        f'fill="#fff" stroke="#111" stroke-width="2.2"{dash} filter="url(#soft)"/>'
    ]
    cy = y + 31
    for idx, line in enumerate(wrap_text(title, max_units)):
        weight = "700" if idx == 0 else "600"
        out.append(
            f'<text x="{x + w / 2}" y="{cy}" text-anchor="middle" '
            f'font-size="{title_font}" font-weight="{weight}">{escape(line)}</text>'
        )
        cy += 29
    if bullets:
        cy += 2
        for bullet in bullets:
            for idx, line in enumerate(wrap_text(bullet, max_units - 3)):
                prefix = "• " if idx == 0 else "  "
                out.append(
                    f'<text x="{x + 26}" y="{cy}" font-size="{font}" '
                    f'font-weight="400">{escape(prefix + line)}</text>'
                )
                cy += 22
    return "\n".join(out)


def arrow(x1, y1, x2, y2, dashed=False, width=2.2):
    dash = ' stroke-dasharray="9 7"' if dashed else ""
    return (
        f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="#111" '
        f'stroke-width="{width}"{dash} marker-end="url(#arrow)"/>'
    )


def poly(points, dashed=False, width=2.2):
    dash = ' stroke-dasharray="9 7"' if dashed else ""
    pts = " ".join(f"{x},{y}" for x, y in points)
    return (
        f'<polyline points="{pts}" fill="none" stroke="#111" stroke-width="{width}"'
        f'{dash} marker-end="url(#arrow)"/>'
    )


def label(x, y, text, size=21, weight=400, anchor="middle"):
    lines = text.split("\n")
    out = []
    for i, line in enumerate(lines):
        out.append(
            f'<text x="{x}" y="{y + i * (size + 5)}" text-anchor="{anchor}" '
            f'font-size="{size}" font-weight="{weight}">{escape(line)}</text>'
        )
    return "\n".join(out)


def phase_bar(phases):
    x, y, h = 18, 857, 62
    w = W - 36
    out = [
        f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="8" ry="8" '
        f'fill="#fff" stroke="#111" stroke-width="2.1"/>'
    ]
    step = w / len(phases)
    for i, phase in enumerate(phases):
        if i:
            sx = x + step * i
            out.append(f'<line x1="{sx}" y1="{y}" x2="{sx}" y2="{y + h}" stroke="#111" stroke-width="1.8"/>')
        out.append(label(x + step * (i + 0.5), y + 39, phase, size=22, weight=500))
    return "\n".join(out)


def draw_family(name, subtitle, boxes, arrows, phases, note=None):
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}">',
        marker(),
        '<rect width="100%" height="100%" fill="#fafafa"/>',
        '<style>text{font-family:"PingFang SC","Heiti SC","Microsoft YaHei",Arial,sans-serif;letter-spacing:0}</style>',
        f'<text x="28" y="55" font-size="45" font-weight="800">{escape(name)} 家族</text>',
        f'<text x="29" y="99" font-size="25" font-weight="700">{escape(subtitle)}</text>',
    ]
    for a in arrows:
        parts.append(a)
    for item in boxes:
        parts.append(box(**item))
    parts.append(phase_bar(phases))
    if note:
        parts.append(label(836, 934, note, size=18, weight=400))
    parts.append("</svg>")
    return "\n".join(parts)


def diagram_fiesta():
    boxes = [
        dict(x=641, y=19, w=320, h=60, title="落地页 / DOM root (n47)", bullets=[]),
        dict(x=579, y=113, w=428, h=121, title="frame owner (n232)\n隐藏 iframe / 跳转入口", bullets=[
            "cross DOM: about:blank",
            "指向 serveblog landing",
            "站点正常资源作为背景噪声",
        ]),
        dict(x=554, y=273, w=480, h=122, title="EK landing DOM (n1234)", bullets=[
            "host = xmjqxjfsub.serveblog.net",
            "serveblog 随机路径",
            "执行混淆脚本 n1320",
        ]),
        dict(x=538, y=435, w=512, h=142, title="script (n1320)\n混淆解码 / 主控制器", bullets=[
            "dash1 / gets35 解码",
            "plugins / userAgent",
            "创建 OBJECT 与片段",
        ]),
        dict(x=70, y=615, w=248, h=145, title="web API (n1322/n1325)", bullets=[
            "plugins.get",
            "userAgent.get",
            "浏览器/插件指纹",
        ]),
        dict(x=358, y=615, w=248, h=145, title="web API (n1344)", bullets=[
            "javaEnabled",
            "Java 环境探测",
            "决定后续对象分支",
        ]),
        dict(x=646, y=615, w=255, h=145, title="OBJECT (n1333/n1341)", bullets=[
            "CAFEEFAC CLSID",
            "两个 Java 对象版本",
            "Applet/插件投递承载",
        ]),
        dict(x=940, y=615, w=255, h=145, title="OBJECT (n1354)", bullets=[
            "CA8A9780 / PDF",
            "对象属性写入",
            "PDF 插件利用候选",
        ]),
        dict(x=1235, y=615, w=300, h=145, title="iframe (n3129) / 第三方服务", bullets=[
            "b2b-booking ObjectList",
            "站点业务脚本并行路径",
            "非核心攻击噪声",
        ], dashed=True),
        dict(x=1055, y=153, w=150, h=75, title="script\n(n195)", bullets=[], dashed=True, small=True),
        dict(x=1235, y=153, w=165, h=75, title="resource\n(n141/n169)", bullets=[], dashed=True, small=True),
        dict(x=1430, y=153, w=150, h=75, title="event / css\nresources", bullets=[], dashed=True, small=True),
    ]
    arrows = [
        arrow(791, 79, 791, 113),
        arrow(793, 234, 793, 273),
        arrow(794, 395, 794, 435),
        poly([(794, 577), (194, 615)]),
        poly([(794, 577), (482, 615)]),
        poly([(794, 577), (773, 615)]),
        poly([(794, 577), (1068, 615)]),
        poly([(794, 577), (1385, 615)]),
        poly([(835, 79), (1130, 153)], dashed=True),
        poly([(849, 79), (1318, 153)], dashed=True),
        poly([(863, 79), (1505, 153)], dashed=True),
    ]
    note = "注：节点和 URL 来自 Fiesta GraphML 样本；虚线框为站点正常资源或非核心路径。"
    return draw_family("Fiesta", "基于执行图的网页攻击模式示意", boxes, arrows, [
        "1. 入口触发",
        "2. 隐藏 iframe 跳转",
        "3. 混淆解码与环境探测",
        "4. OBJECT 分支投递",
    ], note)


def diagram_neutrino():
    boxes = [
        dict(x=641, y=19, w=300, h=60, title="落地页 / DOM root (n47)", bullets=[]),
        dict(x=544, y=105, w=495, h=118, title="script/resource (n968/n973)", bullets=[
            "加载 realstatistics.info/js/analytic.php?id=4",
            "伪装统计脚本入口",
            "位于 Joomla 正常资源之后",
        ]),
        dict(x=529, y=260, w=525, h=132, title="script (n976)\n客户端签名与二次脚本请求", bullets=[
            "Date / timezone 签名",
            "Screen.width + Screen.height = 800x600",
            "追加 analytic.php?tz&rs",
        ]),
        dict(x=546, y=430, w=490, h=134, title="script (n998)\n隐藏容器 + iframe 注入", bullets=[
            "left/top=-500px 容器",
            "iframe width/height = 250",
            "指向 llxfqt.xyz landing",
        ]),
        dict(x=620, y=624, w=420, h=120, title="EK landing DOM (n1063)", bullets=[
            "llxfqt.xyz .../brandy.html",
            "执行随机变量混淆脚本 n1092",
            "含 OBJECT / EMBED 插件承载",
        ]),
        dict(x=54, y=631, w=262, h=126, title="web API (n984/n987)", bullets=[
            "Screen.width.get",
            "Screen.height.get",
            "分辨率指纹 / 请求参数",
        ]),
        dict(x=340, y=632, w=250, h=130, title="script (n1034)", bullets=[
            "referrer / host / search 判断",
            "请求 consultlevy.com",
            "关键词/来源拼接",
        ]),
        dict(x=1054, y=631, w=250, h=126, title="OBJECT (n1102)", bullets=[
            "landing 内对象节点",
            "插件利用承载",
            "与 EMBED 子节点相连",
        ]),
        dict(x=1335, y=631, w=250, h=126, title="EMBED (n1143)", bullets=[
            "插件内容嵌入",
            "与 OBJECT 配套",
            "后续利用载荷位置",
        ]),
        dict(x=965, y=151, w=145, h=72, title="CSS / fonts", bullets=[], dashed=True, small=True),
        dict(x=1148, y=151, w=170, h=72, title="Joomla\nscripts", bullets=[], dashed=True, small=True),
        dict(x=1355, y=151, w=160, h=72, title="analytics\nresources", bullets=[], dashed=True, small=True),
    ]
    arrows = [
        arrow(791, 79, 791, 105),
        arrow(791, 223, 791, 260),
        poly([(791, 392), (791, 410), (791, 430)]),
        arrow(791, 564, 791, 624),
        poly([(700, 565), (185, 631)]),
        poly([(720, 565), (465, 632)]),
        poly([(1040, 684), (1179, 631)]),
        poly([(1040, 684), (1460, 631)]),
        poly([(837, 79), (1038, 151)], dashed=True),
        poly([(849, 79), (1233, 151)], dashed=True),
        poly([(861, 79), (1435, 151)], dashed=True),
    ]
    note = "注：Neutrino 样本主链为 realstatistics 统计伪装到隐藏 iframe；consultlevy 请求在图中作为中转/归因支路保留。"
    return draw_family("Neutrino", "基于执行图的网页攻击模式示意", boxes, arrows, [
        "1. 入口触发",
        "2. 统计脚本伪装",
        "3. 指纹与中转",
        "4. 隐藏 iframe 落地与插件承载",
    ], note)


def diagram_nuclear():
    boxes = [
        dict(x=641, y=19, w=300, h=60, title="落地页 / DOM root (n47)", bullets=[]),
        dict(x=540, y=104, w=500, h=132, title="script (n266/n274)\n广告脚本注入入口", bullets=[
            "document.write 写入脚本/iframe",
            "读取 protocol、location、referrer",
            "dreamscapermurals 早期候选",
        ]),
        dict(x=551, y=268, w=478, h=136, title="script (n570)\nCookie 去重 + 隐藏 iframe", bullets=[
            "检查 _epel，写入 max-age=25000",
            "创建 100x100 隐藏 iframe",
            "指向 chef.holdencubscouts.org",
        ]),
        dict(x=550, y=435, w=480, h=124, title="中转 DOM (n1144)", bullets=[
            "chef.holdencubscouts.org",
            "伪装 jquery-1.3.1.min.js",
            "执行二跳脚本 n1169",
        ]),
        dict(x=551, y=602, w=480, h=136, title="script (n1169)\n二次 cookie 与 landing iframe", bullets=[
            "检查 pidd，写入 max-age=270000",
            "创建隐藏 iframe n1173",
            "跳转 travelforward landing",
        ]),
        dict(x=1110, y=604, w=345, h=134, title="EK landing (n8933/n9442)", bullets=[
            "混淆变量与动态字符串拼接",
            "执行 PluginDetect n9444",
            "进入浏览器/插件探测",
        ]),
        dict(x=96, y=610, w=300, h=134, title="cookie jar (n11)", bullets=[
            "_epel / pidd 访问记录",
            "read storage call",
            "storage set 防重复触发",
        ]),
        dict(x=1112, y=286, w=335, h=132, title="PluginDetect (n9444)", bullets=[
            "Navigator.platform / userAgent",
            "javaEnabled / mimeTypes / plugins",
            "cc_on IE 条件编译探测",
        ]),
        dict(x=1112, y=445, w=335, h=112, title="利用分支候选", bullets=[
            "Java / Flash / MIME 插件",
            "按探测结果选择投递",
            "后续载荷执行",
        ]),
        dict(x=999, y=151, w=140, h=72, title="analytics\nscripts", bullets=[], dashed=True, small=True),
        dict(x=1172, y=151, w=158, h=72, title="social/ad\nresources", bullets=[], dashed=True, small=True),
        dict(x=1366, y=151, w=180, h=72, title="site lazy-load\nscripts", bullets=[], dashed=True, small=True),
    ]
    arrows = [
        arrow(791, 79, 791, 104),
        arrow(791, 228, 791, 268),
        arrow(791, 396, 791, 435),
        arrow(791, 559, 791, 602),
        poly([(551, 666), (396, 666)], dashed=False),
        poly([(1031, 671), (1110, 671)]),
        arrow(1283, 604, 1283, 557),
        arrow(1283, 445, 1283, 418),
        poly([(837, 79), (1069, 151)], dashed=True),
        poly([(849, 79), (1251, 151)], dashed=True),
        poly([(861, 79), (1456, 151)], dashed=True),
    ]
    note = "注：Nuclear 样本突出广告注入、cookie 去重和二跳 landing；正常统计/社交脚本以虚线噪声路径表示。"
    return draw_family("Nuclear", "基于执行图的网页攻击模式示意", boxes, arrows, [
        "1. 入口触发",
        "2. 广告注入与去重",
        "3. 多跳隐藏 iframe",
        "4. 插件探测与利用投递",
    ], note)


def main():
    diagrams = {
        "Fiesta": diagram_fiesta(),
        "Neutrino": diagram_neutrino(),
        "Nuclear": diagram_nuclear(),
    }
    for name, svg in diagrams.items():
        Path(f"{name}.svg").write_text(svg, encoding="utf-8")


if __name__ == "__main__":
    main()
