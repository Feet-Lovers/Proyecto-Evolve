import { useEffect, useState } from 'react'
import { Badge } from '@/components/ui'
import { mockVulnerabilities } from '@/services/mockData'
import { config, lanzarAuditoria, limpiarPanel, obtenerNoAnalizados, obtenerResumenIA, obtenerVulnerabilidades } from '@/services/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useSession } from '@/hooks/useSession'
import { useAppContext } from '@/AppContext'
import { ResizableSplit } from '@/components/layout/ResizableSplit'

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 }
const SEVERITY_LABEL = { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }

export function VulnerabilitiesPage() {
  const sessionToken = useSession()
  const { vulnerabilities: wsVulnerabilities, noAnalizados: wsNoAnalizados, resumenIA: wsResumen } =
    useWebSocket(sessionToken)
  const [selected, setSelected] = useState(null)
  const [filter, setFilter] = useState('all')

  // Lo ya detectado se consulta al entrar; lo que llegue despues, por WebSocket. Hasta el
  // 10-oct esta pantalla se alimentaba SOLO del WebSocket, que arranca vacio en cada
  // montaje: los hallazgos de un rastreo hecho desde otra pestana no aparecian nunca,
  // aunque el backend los tuviera. Mismo patron que los no analizados, doce lineas mas
  // abajo, que si lo hacian — eso explica que un panel pudiera acumular 144 "sin
  // analizar" y cero "detectadas".
  const [previasVulns, setPreviasVulns] = useState([])
  useEffect(() => {
    if (!sessionToken || config.USE_MOCKS) return
    obtenerVulnerabilidades(sessionToken)
      .then(setPreviasVulns)
      .catch(() => setPreviasVulns([]))
  }, [sessionToken])

  // Se deduplica por id, al contrario que los no analizados: aqui una entrada repetida
  // seria un hallazgo fantasma en el informe, no una linea de aviso de mas.
  const vulnerabilitiesTodas = config.USE_MOCKS
    ? mockVulnerabilities
    : [...(wsVulnerabilities || []), ...previasVulns].filter(
        (v, i, todas) => todas.findIndex(o => (o?.id ?? o) === (v?.id ?? v)) === i,
      )

  // RF-08. Hasta el 10-oct no habia forma de arrancar una auditoria: el modulo de IA
  // existia, esperaba ordenes y nadie podia darlas.
  //
  // El objetivo HEREDA el del rastreo en curso (arreglado el 10-oct). Antes venia fijo a
  // `http://dvwa:80`, el laboratorio de la practica 1: quien rastreaba otro objetivo y
  // pulsaba sin mirar auditaba un sitio DISTINTO del que habia rastreado, sin un solo
  // aviso — y con clave real eso gasta llamadas para nada. Ademas era un nombre de
  // servicio interno de Docker, que el usuario del entregable no puede conocer.
  //
  // Heredar no arregla solo ese caso: elimina la clase entera de error. Si no hay
  // rastreo, el campo queda VACIO y el boton se deshabilita solo, que es mejor que
  // ofrecer un valor plausible y equivocado. En cuanto el usuario escribe, deja de
  // heredar: lo suyo manda.
  const { activeUrl } = useAppContext()
  const [objetivo, setObjetivo] = useState(activeUrl || '')
  const [objetivoEditado, setObjetivoEditado] = useState(false)
  useEffect(() => {
    if (!objetivoEditado && activeUrl) setObjetivo(activeUrl)
  }, [activeUrl, objetivoEditado])
  const [lanzando, setLanzando] = useState(false)
  const [aviso, setAviso] = useState(null)

  // RNF-06. Lo ya ocurrido se consulta al entrar; lo que llegue despues, por WebSocket.
  const [previos, setPrevios] = useState([])
  useEffect(() => {
    if (!sessionToken || config.USE_MOCKS) return
    obtenerNoAnalizados(sessionToken).then(setPrevios).catch(() => setPrevios([]))
  }, [sessionToken])
  // Filtro por OBJETIVO (10-oct). El backend sella cada hallazgo con el objetivo que se
  // estaba auditando, y aqui se muestra solo lo del objetivo que hay en el campo. Antes el
  // panel mezclaba la tirada de ahora con restos de otra auditoria contra otra web: josemax
  // se encontro 39 avisos pegados que sobrevivian a limpiar el proxy, sin forma de saber de
  // donde salian ni de quitarlos.
  //
  // Los que NO traen objetivo son anteriores a este cambio: se siguen mostrando para no
  // esconder datos de golpe, y se quitan con el boton de limpiar.
  const delObjetivo = lista =>
    lista.filter(x => !x?.objetivo || !objetivo || x.objetivo === objetivo)

  const vulnerabilities = delObjetivo(vulnerabilitiesTodas)
  const noAnalizados = delObjetivo([...(wsNoAnalizados || []), ...previos])

  // Recibo de la ultima auditoria. Se consulta al entrar igual que los no analizados: lo
  // que llego mientras no estabas en esta pestaña tambien cuenta.
  const [resumenPrevio, setResumenPrevio] = useState(null)
  useEffect(() => {
    if (!sessionToken) return
    obtenerResumenIA(sessionToken).then(setResumenPrevio).catch(() => setResumenPrevio(null))
  }, [sessionToken])
  const resumen = wsResumen || resumenPrevio

  // INDICADOR DE PROGRESO (10-oct). Mientras la auditoria corria, el panel enseñaba
  // exactamente lo mismo que si no hubiera pasado nada: el aviso de "lanzada" y cero
  // resultados. Con 54 elementos tarda 2-3 minutos, y en ese rato no habia forma de
  // distinguir "trabajando" de "terminado sin encontrar nada". Lo pidio josemax con el
  // motivo mejor escrito de todo el proyecto: "para evitar la desesperacion del que esta
  // usando la herramienta".
  //
  // La señal de FIN es la llegada del resumen, que el modulo publica solo al terminar: es
  // mas fiable que un temporizador o que suponer una duracion.
  const [auditando, setAuditando] = useState(false)
  const [desde, setDesde] = useState(null)
  const [ahora, setAhora] = useState(Date.now())
  useEffect(() => {
    if (!auditando) return
    const t = setInterval(() => setAhora(Date.now()), 1000)
    return () => clearInterval(t)
  }, [auditando])
  useEffect(() => {
    if (wsResumen) { setAuditando(false); setDesde(null) }
  }, [wsResumen])
  const transcurrido = auditando && desde ? Math.floor((ahora - desde) / 1000) : 0

  const [limpiando, setLimpiando] = useState(false)

  async function limpiar() {
    setLimpiando(true)
    try {
      const r = await limpiarPanel(sessionToken)
      setPrevios([])
      setPreviasVulns([])
      setResumenPrevio(null)
      setAuditando(false)
      setSelected(null)
      setAviso(`panel vaciado (${r?.borrados ?? 0} entradas)`)
    } catch (e) {
      setAviso(`no se pudo vaciar el panel: ${e?.message || e}`)
    } finally {
      setLimpiando(false)
    }
  }

  async function auditar() {
    setLanzando(true)
    setAviso(null)
    try {
      const r = await lanzarAuditoria({ espacio: sessionToken, url: objetivo })
      // Que la orden se encole NO significa que alguien la vaya a atender. Si nadie
      // escucha el bus, se dice; callarlo dejaria al operador esperando un resultado
      // que no va a llegar, que es el fallo silencioso que RNF-06 persigue.
      // "lanzada: los hallazgos iran apareciendo" prometia de mas: suena a que empiezan a
      // caer enseguida, y la realidad son minutos de silencio. Se dice lo que de verdad pasa.
      const recogida = r?.ia_avisada !== false
      setAviso(
        recogida
          ? { tipo: 'ok', texto: 'auditoria en marcha: puede tardar varios minutos' }
          : { tipo: 'error', texto: r.motivo || 'el modulo de IA no recogio la orden' },
      )
      // Solo se marca "auditando" si ALGUIEN recogio la orden. Un indicador girando para
      // siempre porque nadie escucha el bus seria peor que no tener indicador.
      if (recogida) { setAuditando(true); setDesde(Date.now()) }
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
            {/* El recibo: sin esto, "0 detectadas" no distingue "examino 48 y ninguna era
                vulnerable" de "no examino nada". Se muestra SIEMPRE que haya habido
                auditoria, tambien cuando el resultado es cero. */}
            {auditando && (
              <span style={{ color: 'var(--hs-accent, #4ea1d3)' }}>
                {' · '}auditando… {Math.floor(transcurrido / 60)}m {transcurrido % 60}s
              </span>
            )}
            {resumen && !auditando && (
              <span style={{ color: 'var(--hs-text-muted)' }}>
                {' · '}
                {typeof resumen.analisis === 'number'
                  ? `${resumen.analisis} analisis realizados`
                  : 'analisis realizados: desconocido'}
              </span>
            )}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <input
            value={objetivo}
            onChange={e => { setObjetivoEditado(true); setObjetivo(e.target.value) }}
            placeholder="objetivo a auditar (hereda el del rastreo)"
            className="px-2 py-1.5 rounded border outline-none text-[10px] w-56"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-bg)',
              borderColor: 'var(--hs-border-hover)',
              color: 'var(--hs-text-muted)',
            }}
          />
          <button
            onClick={limpiar}
            disabled={limpiando || (vulnerabilities.length === 0 && noAnalizados.length === 0)}
            title="Vacia el panel sin lanzar ninguna auditoria"
            className="px-3 py-1.5 rounded border text-[10px] disabled:opacity-50"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-bg)',
              borderColor: 'var(--hs-border-hover)',
              color: 'var(--hs-text-muted)',
              cursor: limpiando ? 'wait' : 'pointer',
            }}
          >
            {limpiando ? 'vaciando…' : 'limpiar'}
          </button>
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