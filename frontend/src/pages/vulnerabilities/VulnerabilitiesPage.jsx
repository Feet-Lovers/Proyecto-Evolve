import { useEffect, useState } from 'react'
import { Badge } from '@/components/ui'
import { mockVulnerabilities } from '@/services/mockData'
import { config, lanzarAuditoria, obtenerNoAnalizados } from '@/services/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useSession } from '@/hooks/useSession'
import { ResizableSplit } from '@/components/layout/ResizableSplit'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }

export function VulnerabilitiesPage() {
  const sessionToken = useSession()
  const { vulnerabilities: wsVulnerabilities, noAnalizados: wsNoAnalizados } =
    useWebSocket(sessionToken)
  const vulnerabilities = config.USE_MOCKS ? mockVulnerabilities : wsVulnerabilities
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('all')

  // RF-08. Hasta el 10-oct no habia forma de arrancar una auditoria: el modulo de IA
  // existia, esperaba ordenes y nadie podia darlas. El objetivo por omision es el
  // laboratorio interno, que es nuestro y no sale de la red interna.
  const [objetivo, setObjetivo] = useState('http://dvwa:80')
  const [lanzando, setLanzando] = useState(false)
  const [aviso, setAviso] = useState(null)

  // RNF-06. Lo ya ocurrido se consulta al entrar; lo que llegue despues, por WebSocket.
  const [previos, setPrevios] = useState([])
  useEffect(() => {
    if (!sessionToken || config.USE_MOCKS) return
    obtenerNoAnalizados(sessionToken).then(setPrevios).catch(() => setPrevios([]))
  }, [sessionToken])
  const noAnalizados = [...(wsNoAnalizados || []), ...previos]

  async function auditar() {
    setLanzando(true)
    setAviso(null)
    try {
      const r = await lanzarAuditoria({ espacio: sessionToken, url: objetivo })
      // Que la orden se encole NO significa que alguien la vaya a atender. Si nadie
      // escucha el bus, se dice; callarlo dejaria al operador esperando un resultado
      // que no va a llegar, que es el fallo silencioso que RNF-06 persigue.
      setAviso(
        r?.ia_avisada === false
          ? { tipo: 'error', texto: r.motivo || 'el modulo de IA no recogio la orden' }
          : { tipo: 'ok', texto: 'auditoria lanzada: los hallazgos iran apareciendo' },
      )
    } catch (e) {
      setAviso({
        tipo: 'error',
        texto: e?.response?.data?.detail || 'no se pudo lanzar la auditoria',
      })
    } finally {
      setLanzando(false)
    }
  }

  const filtered = vulnerabilities
    .filter(v => filter === 'all' || v.severidad === filter)
    .sort((a, b) => (SEVERITY_ORDER[a.severidad] ?? 99) - (SEVERITY_ORDER[b.severidad] ?? 99))

  // RNF-06 hecho visible. Va ARRIBA y en ambar, no al final de la lista, porque es un
  // aviso y no un hallazgo: significa «esto no se ha mirado», y el operador tiene que
  // saberlo antes de concluir que no hay nada. Mezclarlo con las vulnerabilidades
  // obligaria a inventarle severidad a algo que precisamente no se pudo valorar.
  const avisoDegradado = noAnalizados.length > 0 && (
    <div className="border-b" style={{ borderColor: '#3d2f10', background: '#1a1405' }}>
      <div className="px-4 pt-3 pb-1">
        <p
          className="text-[10px] tracking-widest uppercase"
          style={{ fontFamily: 'var(--font-mono)', color: '#d9a93a' }}
        >
          {noAnalizados.length} sin analizar — la IA no pudo valorarlo
        </p>
      </div>
      {noAnalizados.map((n, i) => (
        <div key={`na-${i}`} className="px-4 py-2">
          <p
            className="text-[10px] truncate"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
          >
            {n.origen || 'ia'} · {n.url || 'sin url'}
          </p>
          <p
            className="text-[10px] mt-0.5"
            style={{ fontFamily: 'var(--font-sans)', color: '#d9a93a' }}
          >
            {n.motivo || 'sin motivo declarado'}
          </p>
        </div>
      ))}
    </div>
  )

  const listPanel = (
    <div className="overflow-auto h-full" style={{ background: 'var(--hs-bg)' }}>
      {avisoDegradado}
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
          {noAnalizados.length > 0
            ? 'sin hallazgos — pero hay análisis que no se pudieron completar (arriba)'
            : 'no se han detectado vulnerabilidades todavía'}
        </div>
      )}
    </div>
  )

  const detailPanel = (
    <div className="overflow-auto p-5 h-full" style={{ background: 'var(--hs-bg)' }}>
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
  )

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
            {noAnalizados.length > 0 && (
              <span style={{ color: '#d9a93a' }}> · {noAnalizados.length} sin analizar</span>
            )}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            value={objetivo}
            onChange={e => setObjetivo(e.target.value)}
            placeholder="objetivo a auditar"
            className="px-2 py-1.5 rounded border outline-none text-[10px] w-56"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-bg)',
              borderColor: 'var(--hs-border-hover)',
              color: 'var(--hs-text-muted)',
            }}
          />
          <button
            onClick={auditar}
            disabled={lanzando || !objetivo}
            title="Lanza una auditoria con IA sobre el objetivo"
            className="px-3 py-1.5 rounded border text-[10px] disabled:opacity-50"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-surface)',
              borderColor: 'var(--hs-border-hover)',
              color: 'var(--hs-text-primary)',
              cursor: lanzando ? 'wait' : 'pointer',
            }}
          >
            {lanzando ? 'lanzando…' : 'auditar con IA'}
          </button>
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

      {aviso && (
        <div
          className="px-5 py-2 border-b text-[10px]"
          style={{
            fontFamily: 'var(--font-mono)',
            borderColor: 'var(--hs-border)',
            background: aviso.tipo === 'error' ? '#1a0d0d' : '#0d1a14',
            color: aviso.tipo === 'error' ? '#ef7a7a' : '#7ad99a',
          }}
        >
          {aviso.texto}
        </div>
      )}

      <ResizableSplit
        initial={50}
        left={listPanel}
        right={detailPanel}
      />
    </div>
  )
}