import { useSession } from '@/hooks/useSession'
import { useWebSocket } from '@/hooks/useWebSocket'
import { Badge } from '@/components/ui'

export function NetworkPage() {
  const sessionToken = useSession()
  const { requests, connected } = useWebSocket(sessionToken)

  const networkPackets = requests.filter(p => !p.request_headers?.['X-HookSuite-Proxy'])

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div>
          <h2
            className="text-[14px] font-bold tracking-wide"
            style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
          >
            Red en tiempo real
          </h2>
          <p
            className="text-[10px] mt-0.5"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            tráfico capturado por Chrome DevTools
          </p>
        </div>
        <span
          className="flex items-center gap-1.5 px-2 py-0.5 rounded border text-[10px]"
          style={{
            fontFamily: 'var(--font-mono)',
            background: connected ? '#0f1f17' : '#13161c',
            borderColor: connected ? '#1e3d2a' : 'var(--hs-border)',
            color: connected ? '#3a7d4f' : 'var(--hs-text-dim)',
          }}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: connected ? '#3a7d4f' : 'var(--hs-text-dim)' }}
          />
          {connected ? 'conectado' : 'sin conexión'}
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full text-[10px]" style={{ fontFamily: 'var(--font-mono)' }}>
          <thead
            className="sticky top-0"
            style={{ background: 'var(--hs-surface)', borderBottom: '1px solid var(--hs-border)' }}
          >
            <tr>
              {['estado', 'método', 'url', 'status', 'tiempo'].map(h => (
                <th
                  key={h}
                  className="px-4 py-2 text-left text-[9px] font-semibold tracking-widest uppercase"
                  style={{ color: 'var(--hs-text-dim)' }}
                >
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {requests.map(p => (
              <tr
                key={p.id}
                className="border-b"
                style={{
                  borderColor: '#13161c',
                  background: p.vulnerable ? '#1a0d0d' : p.suspicious ? '#161410' : 'transparent',
                }}
              >
                <td className="px-4 py-2">
                  {p.vulnerable
                    ? <Badge variant="critical">vulnerable</Badge>
                    : p.suspicious
                    ? <Badge variant="warning">sospechoso</Badge>
                    : <Badge variant="low">limpio</Badge>
                  }
                </td>
                <td className="px-4 py-2">
                  <Badge variant={p.method?.toLowerCase() || 'default'}>{p.method}</Badge>
                </td>
                <td
                  className="px-4 py-2 max-w-xs truncate"
                  style={{ color: 'var(--hs-text-secondary)' }}
                >
                  {p.url}
                </td>
                <td
                  className="px-4 py-2"
                  style={{ color: p.status >= 400 ? '#ef5a5a' : '#4a9a5a' }}
                >
                  {p.status}
                </td>
                <td className="px-4 py-2" style={{ color: 'var(--hs-text-dim)' }}>{p.time}ms</td>
              </tr>
            ))}
          </tbody>
        </table>
        {requests.length === 0 && (
          <div
            className="flex items-center justify-center h-32 text-[11px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            esperando tráfico de red... arranca el módulo DevTools para capturar
          </div>
        )}
      </div>
    </div>
  )
}
