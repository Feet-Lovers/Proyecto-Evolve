import { useState } from 'react'

const TABS = ['Raw', 'Pretty', 'Preview', 'Headers']

function rewriteUrls(html, baseUrl) {
  try {
    const base = new URL(baseUrl)
    const origin = `${base.protocol}//${base.host}`
    const basePath = baseUrl.substring(0, baseUrl.lastIndexOf('/') + 1)
    return html
      .replace(/(href|src|action)="(?!http|https|\/\/|#|mailto|javascript)([^"]*?)"/gi, (match, attr, url) => {
        if (url.startsWith('/')) return `${attr}="${origin}${url}"`
        return `${attr}="${basePath}${url}"`
      })
      .replace(/(href|src|action)='(?!http|https|\/\/|#|mailto|javascript)([^']*?)'/gi, (match, attr, url) => {
        if (url.startsWith('/')) return `${attr}='${origin}${url}'`
        return `${attr}='${basePath}${url}'`
      })
  } catch {
    return html
  }
}

export function ResponsePanel({ response, requestUrl }) {
  const [tab, setTab] = useState('Pretty')

  if (!response) {
    return (
      <div
        className="flex items-center justify-center h-full text-[11px]"
        style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
      >
        envía una petición para ver la respuesta aquí
      </div>
    )
  }

  // No existe el codigo HTTP 0: un 0 significa que la peticion no llego a tener respuesta
  // (fallo de red o tiempo agotado). Pintarlo como un numero mas lo disfrazaba de respuesta.
  const sinRespuesta = !response.status

  const statusColor = sinRespuesta ? '#ef5a5a'
    : response.status >= 200 && response.status < 300
    ? '#4a9a5a' : response.status >= 400 ? '#ef5a5a' : '#dfc050'

  const previewHtml = requestUrl ? rewriteUrls(response.body || '', requestUrl) : (response.body || '')

  return (
    <div className="flex flex-col h-full">
      {/* Aviso del historial recuperado tras un F5. Va ARRIBA, antes de la barra y de las
          pestanas, por lo mismo que el del Preview: hay que saberlo ANTES de mirar un cuerpo
          vacio, no despues de extranarse. En ambar (no en el gris de los textos tenues) porque
          no es una nota al pie: explica por que falta algo que se esperaba ver. Mismos colores
          que el aviso de 'sin analizar' de VulnerabilitiesPage, para que los dos avisos de la
          aplicacion se parezcan entre si. */}
      {response.cuerpoNoConservado && (
        <div
          className="border-b px-4 py-2"
          style={{ borderColor: '#3d2f10', background: '#1a1405' }}
        >
          <p
            className="text-[10px] tracking-widest uppercase"
            style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a' }}
          >
            {'\u26A0 '}cuerpo no conservado
          </p>
          <p
            className="text-[10px] mt-1 leading-relaxed"
            style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a' }}
          >
            El cuerpo de esta respuesta no se conservó al recargar la página. Se guardan
            el estado, el tiempo y el tamaño. Pulsa <b>enviar</b> para volver a obtenerla.
          </p>
        </div>
      )}
      <div
        className="flex items-center gap-4 px-3 py-2 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <span
          className="text-[11px] font-bold px-2 py-0.5 rounded shrink-0"
          style={{ fontFamily: 'var(--font-mono)', color: statusColor, background: 'var(--hs-bg)' }}
          title={sinRespuesta ? 'La peticion no llego a obtener respuesta: fallo de red o tiempo agotado' : undefined}
        >
          {sinRespuesta ? 'sin respuesta' : response.status}
        </span>
        {/* Tiempo y tamano se ocultan si no hubo respuesta: 0 ms y 0,0 KB no son medidas,
            son la ausencia de ellas, y puestos ahi se leen como si lo fueran. */}
        {!sinRespuesta && (
          <span className="text-[10px] shrink-0" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
            {response.time}ms
          </span>
        )}
        {!sinRespuesta && (
          <span className="text-[10px] shrink-0" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
            {(response.size / 1024).toFixed(1)}KB
          </span>
        )}
        <div className="flex gap-1 ml-auto">
          {TABS.map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className="px-3 py-1 rounded text-[10px] transition-all border"
              style={{
                fontFamily: 'var(--font-mono)',
                background: tab === t ? 'var(--hs-accent-bg)' : 'transparent',
                borderColor: tab === t ? 'var(--hs-accent-border)' : 'transparent',
                color: tab === t ? 'var(--hs-accent)' : 'var(--hs-text-muted)',
              }}
            >
              {t}
            </button>
          ))}
        </div>
      </div>

      {/* A QUE URL se envio, en SU PROPIA LINEA. Estuvo un rato en la barra, compitiendo
          con el estado, el tiempo, el tamano y cuatro pestanas: con `flex-1 truncate` le
          quedaban unos pocos pixeles y solo se leia cuando la peticion FALLABA, porque al
          fallar se ocultan el tiempo y el tamano y queda sitio. Lo destapo una captura de
          josemax, no un recuento: la cadena estaba en el bundle, pero no se veia. */}
      {requestUrl && (
        <div
          className="px-3 py-1 border-b"
          style={{ borderColor: 'var(--hs-border)', background: 'var(--hs-bg)' }}
        >
          <p
            className="truncate text-[10px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
            title={requestUrl}
          >
            {requestUrl}
          </p>
        </div>
      )}

      <div className="flex-1 overflow-auto p-4">
        {tab === 'Raw' && (
          <pre className="text-[10px] whitespace-pre-wrap break-all" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}>
            {response.body}
          </pre>
        )}
        {tab === 'Pretty' && (
          <pre
            className="text-[10px] whitespace-pre-wrap break-all p-3 rounded border"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)', background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
          >
            {(() => { try { return JSON.stringify(JSON.parse(response.body), null, 2) } catch { return response.body } })()}
          </pre>
        )}
        {tab === 'Headers' && (
          <div className="space-y-1">
            {Object.entries(response.headers || {}).length === 0 ? (
              <p className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
                No hay headers disponibles
              </p>
            ) : (
              Object.entries(response.headers || {}).map(([k, v]) => (
                <div key={k} className="flex gap-3 py-1.5 px-3 rounded border" style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}>
                  <span className="min-w-[180px] text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>{k}</span>
                  <span className="text-[10px] break-all" style={{ fontFamily: 'var(--font-mono)', color: k.toLowerCase() === 'set-cookie' ? '#6adf9a' : 'var(--hs-text-secondary)' }}>{v}</span>
                </div>
              ))
            )}
          </div>
        )}
        {tab === 'Preview' && (
          <div className="flex flex-col h-full">
            {/* El aviso va ANTES del marco, no después: quien pulsa Preview tiene que
                saber por qué ve la página a medias antes de verla, no después. */}
            {/* En ambar y como bloque, no en el gris tenue de las notas al pie: es una
                advertencia de SEGURIDAD —que el codigo del sitio auditado no se ejecuta— y
                josemax la vio pasar desapercibida usando la herramienta. Mismo ambar que el
                aviso del historial y que el de 'sin analizar' de VulnerabilitiesPage. */}
            <p
              className="mb-2 text-[10px] leading-relaxed px-3 py-2 rounded border"
              style={{
                fontFamily: 'var(--font-mono)',
                color: '#d9a93a',
                background: '#1a1405',
                borderColor: '#3d2f10',
              }}
            >
              {'\u25B8 '}vista sin JavaScript: el código que venga en la respuesta{' '}
              <b>no se ejecuta</b>. Una página que se construya sola con JavaScript puede
              verse incompleta o en blanco; para eso están las pestañas Raw y Pretty.
            </p>
            {/* sandbox="" = todos los permisos denegados.
                Antes llevaba 'allow-same-origin allow-scripts', y esa pareja se anula: el
                contenido pasa a contar como del mismo origen que HookSuite y su codigo
                alcanzaba el almacenamiento del navegador, donde vive la sesion del
                auditor. Y lo que se pinta aqui viene del sitio AUDITADO, que es
                precisamente del que no te fias. */}
            <iframe
              srcDoc={previewHtml}
              sandbox=""
              className="flex-1 w-full border-0 rounded"
              title="preview"
            />
          </div>
        )}
      </div>
    </div>
  )
}
