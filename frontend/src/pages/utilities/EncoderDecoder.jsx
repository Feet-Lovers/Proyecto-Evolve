import { useState } from 'react'

function encodeHTML(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

function decodeJWT(token) {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return 'JWT inválido'
    const header = JSON.parse(atob(parts[0]))
    const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
    return JSON.stringify({ header, payload }, null, 2)
  } catch { return 'no se pudo decodificar el JWT' }
}

export function EncoderDecoder() {
  const [input, setInput] = useState('')
  const [copied, setCopied] = useState(null)

  const copyText = (value, key) => {
    const doCopy = () => {
      const el = document.createElement('textarea')
      el.value = value
      document.body.appendChild(el)
      el.select()
      document.execCommand('copy')
      document.body.removeChild(el)
      setCopied(key)
      setTimeout(() => setCopied(null), 1500)
    }
    try {
      navigator.clipboard.writeText(value).then(() => {
        setCopied(key)
        setTimeout(() => setCopied(null), 1500)
      }).catch(doCopy)
    } catch { doCopy() }
  }

  const outputs = [
    { label: 'base64 encode', value: (() => { try { return btoa(input) } catch { return 'error' } })() },
    { label: 'base64 decode', value: (() => { try { return atob(input) } catch { return 'no es base64 válido' } })() },
    { label: 'url encode',    value: encodeURIComponent(input) },
    { label: 'url decode',    value: (() => { try { return decodeURIComponent(input) } catch { return 'error' } })() },
    { label: 'html encode',   value: encodeHTML(input) },
    { label: 'jwt decode',    value: input.includes('.') ? decodeJWT(input) : 'introduce un JWT' },
  ]

  return (
    <div className="space-y-4">
      <div>
        <label
          className="block text-[9px] tracking-widest uppercase mb-1.5"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          texto de entrada
        </label>
        <textarea
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="introduce el texto a transformar..."
          className="w-full h-24 px-3 py-2 rounded border resize-none outline-none text-[11px]"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
      </div>

      <div className="grid grid-cols-2 gap-3">
        {outputs.map(o => (
          <div
            key={o.label}
            className="rounded border p-3"
            style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
          >
            <div className="flex items-center justify-between mb-1.5">
              <p
                className="text-[9px] tracking-widest uppercase"
                style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
              >
                {o.label}
              </p>
              <button
                onClick={() => copyText(o.value, o.label)}
                className="text-[10px] transition-colors px-2 py-0.5 rounded border"
                style={{
                  fontFamily: 'var(--font-mono)',
                  color: copied === o.label ? '#6adf9a' : '#6aafef',
                  borderColor: copied === o.label ? '#1e3d2a' : 'var(--hs-border)',
                  background: copied === o.label ? '#0f1f17' : 'transparent',
                }}
              >
                {copied === o.label ? '✓ copiado' : 'copiar'}
              </button>
            </div>
            <pre
              className="text-[10px] whitespace-pre-wrap break-all max-h-20 overflow-auto"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
            >
              {o.value || '—'}
            </pre>
          </div>
        ))}
      </div>
    </div>
  )
}