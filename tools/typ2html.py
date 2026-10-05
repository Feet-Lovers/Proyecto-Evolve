#!/usr/bin/env python3
"""tools/typ2html.py — genera el artefacto HTML de revisión desde la fuente única .typ (R4).

Uso:  ~/.venvs/hooksuite-tools/bin/python tools/typ2html.py   (el venv aporta Pillow, R6;
      sin Pillow funciona igual pero no reduce las imágenes rasterizadas del artefacto)
Entrada: docs/informe/P3-memoria.typ   Salida: docs/informe/P3-memoria.artefacto.html

Soporta el dialecto que usa la memoria: encabezados (=,==,===), párrafos, listas "- ",
*negrita*, `codigo`, las funciones #hueco("resp","que") y #estado("tipo","txt"), y
tablas #tabla((anchos), "cab|cab\nfila|fila") -> dentro del bloque, toda línea con "|"
es una fila y la primera es la cabecera; el bloque termina en la línea ")"; e imágenes
#imagen("../capturas/x.png|.svg", "pie") -> SVG inline, PNG/JPG reducido (Pillow) a data URI.
El HTML se REGENERA de la fuente; no se edita a mano.
"""
import re, html, pathlib, datetime, base64, io
try:
    from PIL import Image
    _HAS_PIL = True
except Exception:
    _HAS_PIL = False
ART_MAXW = 1100  # ancho máx. de las imágenes rasterizadas en el artefacto (R6: copia reducida)

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "docs/informe/P3-memoria.typ"
OUT = ROOT / "docs/informe/P3-memoria.artefacto.html"

text = SRC.read_text(encoding="utf-8")
body = text.split("// === CUERPO ===", 1)[1]

def inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*([^*]+)\*", r"<strong>\1</strong>", s)
    def chip(m):
        t, txt = m.group(1), html.escape(m.group(2), quote=False)
        return f'<span class="chip chip-{t}">{txt}</span>'
    s = re.sub(r'#estado\("([^"]*)",\s*"([^"]*)"\)', chip, s)
    return s

# --- embebido de imágenes (R6: SVG inline, raster reducido a data URI) ---
fig_n = [0]
def _embebe_imagen(ruta, pie):
    fig_n[0] += 1
    cap = f"Figura {fig_n[0]}. " + inline(pie)
    fpath = (SRC.parent / ruta).resolve()
    if not fpath.exists():
        return (f'<figure class="imagen"><div class="img-falta">⚠️ imagen no encontrada: '
                f'{html.escape(str(ruta))}</div><figcaption>{cap}</figcaption></figure>')
    ext = fpath.suffix.lower()
    if ext == ".svg":
        svg = fpath.read_text(encoding="utf-8")
        svg = re.sub(r"<\?xml[^>]*\?>", "", svg).strip()
        return f'<figure class="imagen">{svg}<figcaption>{cap}</figcaption></figure>'
    data = fpath.read_bytes(); mime = "image/png"
    if _HAS_PIL:
        try:
            im = Image.open(fpath)
            if im.width > ART_MAXW:
                h = round(im.height * ART_MAXW / im.width)
                im = im.resize((ART_MAXW, h), Image.LANCZOS)
            if im.mode == "RGBA":
                buf = io.BytesIO(); im.save(buf, "PNG", optimize=True); data = buf.getvalue()
            else:
                buf = io.BytesIO(); im.convert("RGB").save(buf, "JPEG", quality=82); data = buf.getvalue(); mime = "image/jpeg"
        except Exception:
            pass
    b64 = base64.b64encode(data).decode("ascii")
    return (f'<figure class="imagen"><img src="data:{mime};base64,{b64}" '
            f'alt="{html.escape(pie)}"><figcaption>{cap}</figcaption></figure>')

# --- parseo agrupado por apartado (nivel 1) ---
apartados, cur, para, in_ul = [], None, [], False
in_tabla, tabla_filas = False, []
def flush_para():
    global para
    if cur is not None and para:
        cur["html"].append("<p>" + " ".join(inline(x) for x in para) + "</p>")
    para = []
def close_ul():
    global in_ul
    if cur is not None and in_ul:
        cur["html"].append("</ul>")
    in_ul = False
def flush_tabla():
    """Vuelca las filas recogidas como <table> con contenedor que hace scroll propio."""
    global tabla_filas
    if cur is not None and tabla_filas:
        cab, cuerpo = tabla_filas[0], tabla_filas[1:]
        th = "".join(f"<th>{inline(c)}</th>" for c in cab)
        trs = "".join("<tr>" + "".join(f"<td>{inline(c)}</td>" for c in f) + "</tr>"
                      for f in cuerpo)
        cur["html"].append(f'<div class="tabla-wrap"><table><thead><tr>{th}</tr>'
                           f"</thead><tbody>{trs}</tbody></table></div>")
    tabla_filas = []

for raw in body.splitlines():
    s = raw.strip()
    if in_tabla:
        if s.startswith(")"):
            flush_tabla(); in_tabla = False
        elif "|" in s:
            tabla_filas.append([c.strip() for c in s.split("|")])
        continue
    if s.startswith("#tabla(") and cur is not None:
        flush_para(); close_ul()
        in_tabla, tabla_filas = True, []
        continue
    if not s:
        flush_para(); close_ul(); continue
    m = re.match(r"^(=+)\s+(.*)$", s)
    if m:
        flush_para(); close_ul()
        lvl, txt = len(m.group(1)), m.group(2)
        if lvl == 1:
            num = (txt.split(".", 1)[0].strip() if "." in txt else "")
            cur = {"num": num, "titulo": txt, "html": [], "hueco": False, "ok": False}
            apartados.append(cur)
        elif cur is not None:
            cur["html"].append(f"<h{lvl+1}>{inline(txt)}</h{lvl+1}>")
        continue
    m = re.match(r'^#hueco\("([^"]*)",\s*"([^"]*)"\)$', s)
    if m and cur is not None:
        flush_para(); close_ul(); cur["hueco"] = True
        resp, que = html.escape(m.group(1), quote=False), inline(m.group(2))
        cur["html"].append(
            f'<div class="hueco"><div class="hueco-head"><span class="hueco-tag">Hueco</span>'
            f'<span class="hueco-resp">{resp}</span></div><p>{que}</p></div>')
        continue
    m = re.match(r'^#imagen\("([^"]*)",\s*"([^"]*)"\)$', s)
    if m and cur is not None:
        flush_para(); close_ul()
        cur["html"].append(_embebe_imagen(m.group(1), m.group(2)))
        continue
    if re.match(r'^#estado\("[^"]*",\s*"[^"]*"\)$', s) and cur is not None:
        flush_para(); close_ul()
        if '"ok"' in s: cur["ok"] = True
        cur["html"].append('<p class="estado-line">' + inline(s) + "</p>")
        continue
    if s.startswith("- ") and cur is not None:
        flush_para()
        if not in_ul:
            cur["html"].append("<ul>"); in_ul = True
        cur["html"].append("<li>" + inline(s[2:]) + "</li>")
        continue
    close_ul(); para.append(s)
flush_para(); close_ul()

# --- TOC con estado por apartado ---
def estado_apartado(a):
    if a["ok"]: return ("con-evidencia", "Con evidencia")
    if a["hueco"] and len(a["html"]) <= 2: return ("pendiente", "Pendiente")
    if a["hueco"]: return ("en-curso", "En curso")
    return ("en-curso", "En curso")

toc, secciones = [], []
n_ok = sum(1 for a in apartados if a["ok"])
n_pend = sum(1 for a in apartados if estado_apartado(a)[0] == "pendiente")
for a in apartados:
    cls, label = estado_apartado(a)
    anchor = "ap-" + (a["num"] or re.sub(r"\W+", "-", a["titulo"]).lower())
    toc.append(f'<li><a href="#{anchor}"><span class="toc-num">{a["num"]}</span>'
               f'<span class="toc-tit">{inline(a["titulo"].split(".",1)[-1].strip())}</span>'
               f'<span class="dot dot-{cls}" title="{label}"></span></a></li>')
    secciones.append(
        f'<section id="{anchor}"><h2 class="apartado"><span class="ap-num">{a["num"]}</span>'
        f'{inline(a["titulo"].split(".",1)[-1].strip())}'
        f'<span class="ap-estado estado-{cls}">{label}</span></h2>'
        + "\n".join(a["html"]) + "</section>")

hoy = datetime.date.today().isoformat()
CSS = """
:root{
  --bg:#F2F4F7; --surface:#FFFFFF; --ink:#1B2430; --muted:#5B6675;
  --accent:#1A6FBF; --accent-soft:#E9F1FA; --border:#E3E7ED;
  --rojo:#C0392B; --verde:#1E8449; --ambar:#B9770E; --ambar-bg:#FBF0DC;
  --serif:"Iowan Old Style","Palatino Linotype",Palatino,Georgia,"Times New Roman",serif;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  --mono:ui-monospace,"SF Mono","Cascadia Code","Roboto Mono",Menlo,Consolas,monospace;
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  --bg:#0E131A; --surface:#161D27; --ink:#E6EAF0; --muted:#98A4B3;
  --accent:#5AA7E6; --accent-soft:#17283A; --border:#28313F;
  --rojo:#E07466; --verde:#5FBF86; --ambar:#E0A94A; --ambar-bg:#2A2412;
}}
:root[data-theme="dark"]{
  --bg:#0E131A; --surface:#161D27; --ink:#E6EAF0; --muted:#98A4B3;
  --accent:#5AA7E6; --accent-soft:#17283A; --border:#28313F;
  --rojo:#E07466; --verde:#5FBF86; --ambar:#E0A94A; --ambar-bg:#2A2412;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:var(--sans);
  font-size:16px;line-height:1.6;-webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:32px 20px 80px}
header.doc{border-bottom:2px solid var(--accent);padding-bottom:18px;margin-bottom:8px}
.eyebrow{font-size:12px;letter-spacing:.14em;text-transform:uppercase;color:var(--accent);font-weight:700}
h1.title{font-family:var(--serif);font-size:34px;line-height:1.1;margin:.2em 0 .1em;
  text-wrap:balance;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:15px;margin:0}
.meta{color:var(--muted);font-size:13px;margin-top:10px}
.panel{background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:16px 18px;margin:22px 0}
.panel h2{font-family:var(--sans);font-size:13px;letter-spacing:.08em;text-transform:uppercase;
  color:var(--muted);margin:0 0 10px}
.counts{display:flex;gap:18px;flex-wrap:wrap;font-size:14px;margin-bottom:14px}
.counts b{font-size:22px;font-variant-numeric:tabular-nums;display:block;color:var(--ink)}
.counts span{color:var(--muted)}
ul.toc{list-style:none;margin:0;padding:0;display:grid;grid-template-columns:1fr 1fr;gap:2px 22px}
ul.toc a{display:flex;align-items:center;gap:10px;padding:6px 6px;border-radius:6px;
  text-decoration:none;color:var(--ink)}
ul.toc a:hover{background:var(--accent-soft)}
.toc-num{font-variant-numeric:tabular-nums;color:var(--muted);width:1.4em;text-align:right;font-size:13px}
.toc-tit{flex:1;font-size:14px}
.dot{width:9px;height:9px;border-radius:50%;flex:none}
.dot-con-evidencia{background:var(--verde)}
.dot-en-curso{background:var(--ambar)}
.dot-pendiente{background:var(--border);border:1px solid var(--muted)}
@media(max-width:620px){ul.toc{grid-template-columns:1fr}}
section{margin:30px 0;padding-top:6px}
h2.apartado{font-family:var(--serif);font-size:23px;line-height:1.2;margin:0 0 12px;
  padding-bottom:8px;border-bottom:1px solid var(--border);display:flex;align-items:baseline;
  gap:12px;flex-wrap:wrap;text-wrap:balance}
.ap-num{color:var(--accent);font-weight:700;font-variant-numeric:tabular-nums}
.ap-estado{margin-left:auto;font-family:var(--sans);font-size:11px;font-weight:700;
  letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:20px}
.estado-con-evidencia{background:var(--verde);color:#fff}
.estado-en-curso{color:var(--ambar);border:1px solid var(--ambar)}
.estado-pendiente{color:var(--muted);border:1px solid var(--border)}
h3{font-size:17px;margin:20px 0 6px}
h4{font-size:15px;margin:16px 0 4px;color:var(--muted)}
p{margin:8px 0;max-width:68ch}
li{margin:4px 0;max-width:66ch}
code{font-family:var(--mono);font-size:.88em;background:var(--accent-soft);
  padding:1px 5px;border-radius:4px}
strong{font-weight:700}
.chip{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;
  padding:2px 8px;border-radius:20px;color:#fff;vertical-align:middle}
.chip-rojo{background:var(--rojo)} .chip-ok{background:var(--verde)}
.chip-curso{background:var(--ambar)} .chip-info{background:var(--accent)}
.estado-line{margin:10px 0}
.tabla-wrap{overflow-x:auto;margin:14px 0;border:1px solid var(--border);
  border-radius:8px;background:var(--surface);-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:13.5px;line-height:1.45}
thead th{background:var(--accent-soft);color:var(--ink);text-align:left;font-weight:700;
  font-size:12px;letter-spacing:.03em;text-transform:uppercase;white-space:nowrap;
  padding:8px 10px;border-bottom:1px solid var(--border);position:sticky;top:0}
tbody td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-soft)}
tbody td:first-child{white-space:nowrap;font-weight:600}
table code{font-size:.85em}
figure.imagen{margin:18px 0;text-align:center}
figure.imagen img,figure.imagen svg{max-width:100%;height:auto;border:1px solid var(--border);
  border-radius:8px;background:#fff}
figure.imagen figcaption{font-size:12.5px;color:var(--muted);margin-top:7px;font-style:italic;
  text-align:center;max-width:60ch;margin-left:auto;margin-right:auto}
.img-falta{padding:18px;border:1px dashed var(--rojo);border-radius:8px;color:var(--rojo);font-size:13px}
.hueco{background:var(--ambar-bg);border:1px solid var(--ambar);border-left:4px solid var(--ambar);
  border-radius:6px;padding:10px 14px;margin:12px 0}
.hueco-head{display:flex;align-items:center;gap:10px;margin-bottom:2px}
.hueco-tag{font-size:11px;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
  color:#fff;background:var(--ambar);padding:2px 8px;border-radius:4px}
.hueco-resp{font-size:13px;font-weight:700;color:var(--ambar)}
.hueco p{margin:0;font-size:14.5px}
a{color:var(--accent)}
footer{margin-top:50px;padding-top:16px;border-top:1px solid var(--border);
  color:var(--muted);font-size:12.5px}
"""
HTML = f"""<title>Memoria técnica HookSuite</title>
<style>{CSS}</style>
<div class="wrap">
<header class="doc">
  <div class="eyebrow">Práctica 3 · Evolve Academy</div>
  <h1 class="title">HookSuite — Memoria técnica</h1>
  <p class="sub">Esqueleto vivo de la memoria (13 apartados). Los huecos marcan qué falta y quién lo rellena.</p>
  <p class="meta">Fuente única: <code>docs/informe/P3-memoria.typ</code> · regenerado el {hoy} · entrega 16-oct-2026</p>
</header>
<div class="panel">
  <h2>Estado del documento</h2>
  <div class="counts">
    <span><b>{len(apartados)}</b>apartados</span>
    <span><b>{n_ok}</b>con evidencia</span>
    <span><b>{n_pend}</b>pendientes</span>
  </div>
  <ul class="toc">{''.join(toc)}</ul>
</div>
{''.join(secciones)}
<footer>Generado desde la fuente Typst por <code>tools/typ2html.py</code>. No editar este HTML a mano: se regenera (R4).</footer>
</div>
"""
OUT.write_text(HTML, encoding="utf-8")
print(f"OK -> {OUT}  ({len(apartados)} apartados, {n_ok} con evidencia, {n_pend} pendientes, {OUT.stat().st_size} bytes)")
