# Evidencia · Spider: trampa de araña + SSRF (ANTES de arreglar) — 2026-10-04

Capturado por Claude como TEXTO (R6), ejercitando la lógica real de `backend/services/spider_service.py`
(`normalize_url`, `is_same_domain`) dentro del contenedor backend de la cocina. SIN lanzar el Spider contra
ningún objetivo (RNF-07): es una demostración unitaria del fallo.

## Trampa de araña (normalize_url no canonicaliza)
base_domain = 'dvwa'
- `vuln.php?id=1&amp;page=2`  -> `http://dvwa/vuln.php?id=1&amp;page=2`   (⚠️ `&amp;` NO decodificado)
- `vuln.php?id=1&page=2`      -> `http://dvwa/vuln.php?id=1&page=2`       (≠ la anterior: mismo recurso, 2 URLs)
- `vuln.php?page=2&id=1`      -> `http://dvwa/vuln.php?page=2&id=1`       (≠ `?id=1&page=2`: query sin ordenar)
- `vuln.php?id=1#x`           -> `http://dvwa/vuln.php?id=1`              (fragmento sí se quita, bien)
→ el mismo recurso produce varias URLs distintas → cola infinita (martillea el objetivo).

## SSRF (is_same_domain no bloquea destinos internos)
- objetivo `http://127.0.0.1:8000/`  acepta `http://127.0.0.1:8000/admin`              -> True
- objetivo `http://169.254.169.254/` acepta `http://169.254.169.254/latest/meta-data/` -> True
- objetivo `http://localhost/`       acepta `http://localhost/x`                        -> True
→ si el objetivo que mete el auditor es interno (backend propio, metadata de cloud, loopback),
  el Spider lo rastrea → SSRF. No hay lista de bloqueo de destinos internos.

## Arreglo propuesto (un solo cambio cierra ambos)
1. Decodificar entidades HTML (`html.unescape`) + canonicalizar la query (ordenar params) + quitar fragmento
   -> colapsa las variantes del mismo recurso (cierra la trampa).
2. Rechazar destinos internos (loopback/link-local/privadas/el backend) -> cierra el SSRF.
   DECISIÓN pendiente: en la cocina DVWA es interno y objetivo legítimo del lab -> cómo conciliarlo.

## DESPUÉS del arreglo (verificado en el contenedor, mismo juego de casos)
Trampa — todas las variantes del mismo recurso colapsan:
- `?id=1&amp;page=2`, `?id=1&page=2`, `?page=2&id=1`  -> todas `http://dvwa/vuln.php?id=1&page=2`
- `?id=1#x` -> `?id=1` (fragmento fuera)
SSRF — destinos internos peligrosos bloqueados, privada del lab permitida:
- `127.0.0.1:8000` -> False · `169.254.169.254` (metadata) -> False · `localhost` -> False · `dvwa` -> True
