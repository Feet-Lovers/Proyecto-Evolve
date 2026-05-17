import { useState } from 'react'

const TABS = ['Raw', 'Pretty', 'Preview']

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

  const statusColor = response.status >= 200 && response.status < 300
    ? '#4a9a5a' : response.status >= 400 ? '#ef5a5a' : '#dfc050'

  const previewHtml = requestUrl ? rewriteUrls(response.body || '', requestUrl) : (response.body || '')

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center gap-4 px-3 py-2 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <span
          className="text-[11px] font-bold px-2 py-0.5 rounded"
          style={{ fontFamily: 'var(--font-mono)', color: statusColor, background: 'var(--hs-bg)' }}
        >
          {response.status}
        </span>
        <span className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
          {response.time}ms
        </span>
        <span className="text-[10px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}>
          {(response.size / 1024).toFixed(1)}KB
        </span>
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
        {tab === 'Preview' && (
          <iframe
            srcDoc={previewHtml}
            sandbox="allow-same-origin allow-scripts"
            className="w-full h-full border-0 rounded"
            title="preview"
          />
        )}
      </div>
    </div>
  )
}
