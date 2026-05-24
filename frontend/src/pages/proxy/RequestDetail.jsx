import { useState } from 'react'
import { Button } from '@/components/ui'

const TABS = ['Request', 'Response', 'Headers']

export function RequestDetail({ request, onSendToRepeater, onSendToIntruder }) {
  const [activeTab, setActiveTab] = useState('Request')

  if (!request) {
    return (
      <div
        className="flex items-center justify-center h-full text-[11px]"
        style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
      >
        selecciona una peticion para ver el detalle
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-3 py-2 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="flex gap-1">
          {TABS.map(tab => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className="px-3 py-1 rounded text-[10px] transition-all border"
              style={{
                fontFamily: 'var(--font-mono)',
                background: activeTab === tab ? 'var(--hs-accent-bg)' : 'transparent',
                borderColor: activeTab === tab ? 'var(--hs-accent-border)' : 'transparent',
                color: activeTab === tab ? 'var(--hs-accent)' : 'var(--hs-text-muted)',
              }}
            >
              {tab}
            </button>
          ))}
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="secondary" onClick={() => onSendToIntruder(request)}>
            enviar al intruder →
          </Button>
          <Button size="sm" onClick={() => onSendToRepeater(request)}>
            enviar al repeater →
          </Button>
        </div>
      </div>

      <div
        className="flex-1 overflow-auto p-4 text-[10px] leading-relaxed"
        style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
      >
        {activeTab === 'Request' && (
          <div className="space-y-4">
            <div>
              <p className="text-[9px] tracking-widest uppercase mb-2" style={{ color: 'var(--hs-text-dim)' }}>peticion</p>
              <p>
                <span style={{ color: '#6adf9a' }}>{request.method} </span>
                <span style={{ color: '#6aafef' }}>{request.url}</span>
              </p>
            </div>
            {request.requestBody && (
              <div>
                <p className="text-[9px] tracking-widest uppercase mb-2" style={{ color: 'var(--hs-text-dim)' }}>body</p>
                <pre
                  className="p-3 rounded border whitespace-pre-wrap break-all"
                  style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)', color: 'var(--hs-text-secondary)' }}
                >
                  {request.requestBody}
                </pre>
              </div>
            )}
          </div>
        )}

        {activeTab === 'Response' && (
          <div>
            <p className="text-[9px] tracking-widest uppercase mb-2" style={{ color: 'var(--hs-text-dim)' }}>
              respuesta <span style={{ color: '#4a9a5a' }}>{request.status}</span>
            </p>
            <pre
              className="p-3 rounded border whitespace-pre-wrap break-all"
              style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)', color: 'var(--hs-text-secondary)' }}
            >
              {request.responseBody}
            </pre>
          </div>
        )}

        {activeTab === 'Headers' && (
          <div className="space-y-4">
            <div>
              <p className="text-[9px] tracking-widest uppercase mb-2" style={{ color: 'var(--hs-text-dim)' }}>headers de peticion</p>
              {Object.entries(request.requestHeaders || {}).map(([k, v]) => (
                <div key={k} className="flex gap-3 py-1 border-b" style={{ borderColor: '#13161c' }}>
                  <span className="min-w-[120px]" style={{ color: 'var(--hs-text-dim)' }}>{k}</span>
                  <span style={{ color: 'var(--hs-text-secondary)' }}>{v}</span>
                </div>
              ))}
            </div>
            <div>
              <p className="text-[9px] tracking-widest uppercase mb-2" style={{ color: 'var(--hs-text-dim)' }}>headers de respuesta</p>
              {Object.entries(request.responseHeaders || {}).map(([k, v]) => (
                <div key={k} className="flex gap-3 py-1 border-b" style={{ borderColor: '#13161c' }}>
                  <span className="min-w-[120px]" style={{ color: 'var(--hs-text-dim)' }}>{k}</span>
                  <span style={{ color: 'var(--hs-text-secondary)' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
