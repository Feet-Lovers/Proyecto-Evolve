import { useState } from 'react'
import { EncoderDecoder } from './EncoderDecoder'
import { HashGenerator } from './HashGenerator'
import { RegexTester } from './RegexTester'
import { PayloadGenerator } from './PayloadGenerator'

const TOOLS = [
  { id: 'encoder',  label: 'Encoder / Decoder' },
  { id: 'hash',     label: 'Hash Generator'    },
  { id: 'regex',    label: 'Regex Tester'      },
  { id: 'payloads', label: 'Payload Generator' },
]

export function UtilitiesPage() {
  const [activeTool, setActiveTool] = useState('encoder')

  return (
    <div className="flex flex-col h-full">
      <div
        className="px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h2
          className="text-[14px] font-bold tracking-wide"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          Utilidades
        </h2>
      </div>

      <div className="flex flex-1 overflow-hidden">
        <div
          className="w-44 border-r p-3 flex flex-col gap-0.5"
          style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
        >
          {TOOLS.map(t => (
            <button
              key={t.id}
              onClick={() => setActiveTool(t.id)}
              className="w-full text-left px-3 py-2 rounded text-[11px] transition-all border"
              style={{
                fontFamily: 'var(--font-sans)',
                background: activeTool === t.id ? 'var(--hs-accent-bg)' : 'transparent',
                borderColor: activeTool === t.id ? 'var(--hs-accent-border)' : 'transparent',
                color: activeTool === t.id ? 'var(--hs-accent)' : 'var(--hs-text-muted)',
                fontWeight: 500,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-auto p-6">
          {activeTool === 'encoder'  && <EncoderDecoder />}
          {activeTool === 'hash'     && <HashGenerator />}
          {activeTool === 'regex'    && <RegexTester />}
          {activeTool === 'payloads' && <PayloadGenerator />}
        </div>
      </div>
    </div>
  )
}