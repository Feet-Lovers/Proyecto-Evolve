import { useState } from 'react'
import { Badge } from '@/components/ui'
import { mockVulnerabilities } from '@/services/mockData'
import { config } from '@/services/api'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }

export function VulnerabilitiesPage() {
  const [vulnerabilities] = useState(config.USE_MOCKS ? mockVulnerabilities : [])
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('all')

  const filtered = vulnerabilities
    .filter(v => filter === 'all' || v.severidad === filter)
    .sort((a, b) => (SEVERITY_ORDER[a.severidad] ?? 99) - (SEVERITY_ORDER[b.severidad] ?? 99))

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="flex items-center gap-3">
          <h2
            className="text-[14px] font-bold tracking-wide"
            style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
          >
            Vulnerabilidades
          </h2>
          <span
            className="text-[10px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            {vulnerabilities.length} detectadas
          </span>
        </div>
        <select
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="px-3 py-1.5 rounded border outline-none text-[10px] cursor-pointer"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-muted)',
          }}
        >
          <option value="all">todas</option>
          <option value="critical">crítica</option>
          <option value="high">alta</option>
          <option value="medium">media</option>
          <option value="low">baja</option>
        </select>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div className="w-1/2 border-r overflow-auto" style={{ borderColor: 'var(--hs-border)' }}>
          {filtered.map(v => (
            <div
              key={v.id}
              onClick={() => setSelected(v)}
              className="p-4 border-b cursor-pointer transition-colors"
              style={{
                borderColor: '#13161c',
                background: selected?.id === v.id ? '#0d1a14' : 'transparent',
              }}
            >
              <div className="flex items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <p
                    className="text-[12px] font-semibold truncate"
                    style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
                  >
                    {v.titulo}
                  </p>
                  <p
                    className="text-[10px] mt-0.5 truncate"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
                  >
                    {v.url}
                  </p>
                </div>
                <Badge variant={v.severidad}>{SEVERITY_LABEL[v.severidad]}</Badge>
              </div>
              <p
                className="text-[10px] mt-1"
                style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
              >
                {v.tipo}
              </p>
            </div>
          ))}
          {filtered.length === 0 && (
            <div
              className="flex items-center justify-center h-32 text-[11px]"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              no se han detectado vulnerabilidades todavía
            </div>
          )}
        </div>

        <div className="w-1/2 overflow-auto p-5">
          {selected ? (
            <div className="space-y-5">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Badge variant={selected.severidad}>{SEVERITY_LABEL[selected.severidad]}</Badge>
                  <span
                    className="text-[10px]"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                  >
                    {selected.tipo}
                  </span>
                </div>
                <h3
                  className="text-[13px] font-bold"
                  style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
                >
                  {selected.titulo}
                </h3>
                <p
                  className="text-[10px] mt-1"
                  style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
                >
                  {selected.url}
                </p>
              </div>

              {[
                { label: 'descripción', value: selected.descripcion, mono: false },
                { label: 'recomendación', value: selected.recomendacion, mono: false },
              ].map(({ label, value }) => (
                <div key={label}>
                  <p
                    className="text-[9px] tracking-widest uppercase mb-1.5"
                    style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                  >
                    {label}
                  </p>
                  <p
                    className="text-[11px] leading-relaxed"
                    style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-secondary)' }}
                  >
                    {value}
                  </p>
                </div>
              ))}

              <div>
                <p
                  className="text-[9px] tracking-widest uppercase mb-1.5"
                  style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                >
                  payload usado
                </p>
                <code
                  className="block text-[11px] p-3 rounded border"
                  style={{
                    fontFamily: 'var(--font-mono)',
                    color: '#ef7a7a',
                    background: '#1a0d0d',
                    borderColor: '#3d1a1a',
                  }}
                >
                  {selected.payload}
                </code>
              </div>
            </div>
          ) : (
            <div
              className="flex items-center justify-center h-full text-[11px]"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              selecciona una vulnerabilidad para ver el detalle
            </div>
          )}
        </div>
      </div>
    </div>
  )
}