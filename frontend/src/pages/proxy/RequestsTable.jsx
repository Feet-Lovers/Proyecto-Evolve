import { Fragment, useState } from 'react'
import { Badge } from '@/components/ui'

const METHOD_VARIANTS = {
  GET: 'get', POST: 'post', PUT: 'put', DELETE: 'delete', PATCH: 'patch',
}

const STATUS_COLOR = (status) => {
  if (status === 'FORM') return 'text-[#8a8a9a]'
  if (status >= 200 && status < 300) return 'text-[#4a9a5a]'
  if (status >= 300 && status < 400) return 'text-[#6aafef]'
  if (status >= 400 && status < 500) return 'text-[#dfc050]'
  return 'text-[#ef5a5a]'
}

function groupRequests(requests) {
  const groups = {}
  const order = []
  requests.forEach(r => {
    if (r.source === 'spider-form') return
    const key = r.url
    if (!groups[key]) {
      groups[key] = { main: r, forms: [] }
      order.push(key)
    } else {
      if (!groups[key].main || r.status !== 'FORM') {
        groups[key].main = r
      }
    }
  })
  requests.forEach(r => {
    if (r.source === 'spider-form') {
      // El backend dice de que pagina sale cada formulario (pagina_origen).
      // Antes se adivinaba por prefijo de URL y colgaba formularios de paginas ajenas:
      // un action='/' casaba con CUALQUIER fila por startsWith.
      const matchKey = r.pagina_origen
      if (matchKey && groups[matchKey]) {
        groups[matchKey].forms.push(r)
      }
    }
  })
  return order.map(k => groups[k])
}

export function RequestsTable({ requests, onSelect, selectedId }) {
  const [filter, setFilter] = useState('')
  const [methodFilter, setMethodFilter] = useState('ALL')
  const [expanded, setExpanded] = useState({})

  const casa = (r) =>
    r.url.toLowerCase().includes(filter.toLowerCase()) &&
    (methodFilter === 'ALL' || r.method === methodFilter)

  // El filtro se aplica DESPUES de agrupar. Al reves -como estaba- un formulario
  // cuya pagina no pasaba el filtro se quedaba sin grupo donde colgar y
  // desaparecia de la tabla entera: filtrar por POST la vaciaba, porque las
  // paginas son GET y se llevaban por delante a sus formularios POST.
  const groups = groupRequests(requests)
    .map(g => {
      const forms = g.forms.filter(casa)
      // Una pagina puede entrar solo como contenedor de un formulario que si
      // casa; en ese caso se muestra ya desplegada, porque lo que el usuario
      // buscaba es lo de dentro, no ella.
      const soloPorForms = !casa(g.main) && forms.length > 0
      return { ...g, forms, abierto: expanded[g.main.url] ?? soloPorForms }
    })
    .filter(g => casa(g.main) || g.forms.length > 0)

  const toggleExpand = (url) => {
    setExpanded(prev => ({ ...prev, [url]: !prev[url] }))
  }

  const renderRow = (req, isForm = false, extra = null) => (
    <tr
      key={req.id}
      onClick={() => onSelect(req)}
      className="cursor-pointer transition-colors border-b"
      style={{
        borderColor: '#13161c',
        background: selectedId === req.id
          ? '#0d1a14'
          : req.vulnerable ? '#1a0d0d'
          : req.suspicious ? '#161410'
          : isForm ? '#0d0d14'
          : 'transparent',
      }}
    >
      <td
        className="px-3 py-2 whitespace-nowrap text-[9px] uppercase tracking-wider"
        style={{ color: 'var(--hs-text-dim)', paddingLeft: isForm ? '20px' : undefined }}
      >
        {isForm ? '\u2514 form' : 'pagina'}
      </td>
      <td className="px-3 py-2">
        <Badge variant={METHOD_VARIANTS[req.method] || 'default'}>{req.method}</Badge>
      </td>
      <td
        className="px-3 py-2 max-w-[180px] truncate"
        style={{ color: isForm ? 'var(--hs-text-dim)' : 'var(--hs-text-secondary)' }}
      >
        {req.url}
        {isForm && req.num_campos != null && (
          <span style={{ color: 'var(--hs-text-dim)' }}>
            {' \u00b7 ' + req.num_campos + (req.num_campos === 1 ? ' campo' : ' campos')}
          </span>
        )}
      </td>
      <td className={"px-3 py-2 font-semibold " + (isForm ? '' : STATUS_COLOR(req.status))}>
        {isForm ? '\u2014' : req.status}
      </td>
      <td className="px-3 py-2" style={{ color: 'var(--hs-text-dim)' }}>
        {isForm ? '\u2014' : (req.size / 1024).toFixed(1) + 'KB'}
      </td>
      <td className="px-3 py-2" style={{ color: 'var(--hs-text-dim)' }}>
        {isForm ? '\u2014' : req.time + 'ms'}
        {extra}
      </td>
    </tr>
  )

  return (
    <div className="flex flex-col flex-1 min-h-0">
      <div
        className="flex gap-2 p-2 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <input
          type="text"
          placeholder="filtrar por url..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 px-3 py-1.5 rounded border text-[10px] outline-none"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
        <select
          value={methodFilter}
          onChange={e => setMethodFilter(e.target.value)}
          className="px-2 py-1.5 rounded border text-[10px] outline-none cursor-pointer"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-muted)',
          }}
        >
          {['ALL', 'GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => (
            <option key={m} value={m}>{m}</option>
          ))}
        </select>
      </div>

      <div className="flex-1 min-h-0 overflow-auto">
        <table className="w-full text-[10px]" style={{ fontFamily: 'var(--font-mono)' }}>
          <thead
            className="sticky top-0"
            style={{ background: 'var(--hs-surface)', borderBottom: '1px solid var(--hs-border)' }}
          >
            <tr>
              {['tipo', 'método', 'url', 'status', 'size', 'ms'].map(h => (
                <th
                  key={h}
                  className="px-3 py-2 text-left text-[9px] font-semibold tracking-widest uppercase"
                  style={{ color: 'var(--hs-text-dim)' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {groups.map(group => (
              <Fragment key={group.main.id}>
                {renderRow(group.main, false, group.forms.length > 0 && (
                  <span
                    onClick={e => { e.stopPropagation(); toggleExpand(group.main.url) }}
                    className="ml-2 cursor-pointer"
                    style={{ color: 'var(--hs-accent)', fontSize: '9px' }}
                  >
                    {'[' + group.forms.length + (group.forms.length === 1 ? ' formulario · visto aqui primero ' : ' formularios · vistos aqui primero ') + (expanded[group.main.url] ? '\u25b2' : '\u25bc') + ']'}
                  </span>
                ))}
                {group.abierto && group.forms.map(form => renderRow(form, true))}
              </Fragment>
            ))}
          </tbody>
        </table>

        {groups.length === 0 && (
          <div
            className="flex items-center justify-center h-32 text-[11px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            {requests.length === 0
              ? 'aun no se ha rastreado nada'
              : 'ninguna peticion coincide con el filtro'}
          </div>
        )}
      </div>
    </div>
  )
}
