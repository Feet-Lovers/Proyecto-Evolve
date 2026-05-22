import { useState } from 'react'

export default function ProxyConfig({ proxyPort }) {
  const [copied, setCopied] = useState(null)

  const copy = (val, key) => {
    navigator.clipboard.writeText(val)
    setCopied(key)
    setTimeout(() => setCopied(null), 1500)
  }

  const rows = [
    { label: 'host',      value: '91.98.143.219' },
    { label: 'puerto',    value: String(proxyPort) },
    { label: 'usuario',   value: 'hooksuite' },
    { label: 'contraseña',value: 'audit2026' },
  ]

  return (
    <div
      className="rounded-xl border p-4"
      style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
    >
      <h2
        className="text-[12px] font-bold mb-1"
        style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-accent)' }}
      >
        Configuración del Proxy
      </h2>
      <p
        className="text-[10px] mb-3"
        style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
      >
        configura tu navegador con estos datos
      </p>

      <div
        className="rounded-lg p-3 space-y-2 border"
        style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
      >
        {rows.map(({ label, value }) => (
          <div key={label} className="flex items-center justify-between">
            <div className="flex gap-3">
              <span
                className="text-[10px] min-w-[70px]"
                style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
              >
                {label}:
              </span>
              <span
                className="text-[10px]"
                style={{
                  fontFamily: 'var(--font-mono)',
                  color: label === 'puerto' ? 'var(--hs-accent)' : 'var(--hs-text-secondary)',
                }}
              >
                {value}
              </span>
            </div>
            <button
              onClick={() => copy(value, label)}
              className="text-[9px] tracking-wide"
              style={{ fontFamily: 'var(--font-mono)', color: '#6aafef' }}
            >
              {copied === label ? '✓' : 'copiar'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}