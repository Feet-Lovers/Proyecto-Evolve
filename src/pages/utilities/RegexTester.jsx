import { useState, useMemo } from 'react'

export function RegexTester() {
  const [pattern, setPattern] = useState('')
  const [flags, setFlags] = useState('g')
  const [text, setText] = useState('')

  const { matches, error, highlighted } = useMemo(() => {
    if (!pattern || !text) return { matches: [], error: null, highlighted: [] }
    try {
      const gflags = flags.includes('g') ? flags : flags + 'g'
      const found = [...text.matchAll(new RegExp(pattern, gflags))]
      const parts = []
      let last = 0
      found.forEach(m => {
        if (m.index > last) parts.push({ text: text.slice(last, m.index), match: false })
        parts.push({ text: m[0], match: true })
        last = m.index + m[0].length
      })
      if (last < text.length) parts.push({ text: text.slice(last), match: false })
      return { matches: found, error: null, highlighted: parts }
    } catch (e) {
      return { matches: [], error: e.message, highlighted: [] }
    }
  }, [pattern, flags, text])

  const inputStyle = {
    fontFamily: 'var(--font-mono)',
    background: 'var(--hs-bg)',
    borderColor: error ? '#4d1515' : 'var(--hs-border-hover)',
    color: 'var(--hs-text-secondary)',
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <div className="flex-1">
          <label
            className="block text-[9px] tracking-widest uppercase mb-1.5"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            patrón regex
          </label>
          <input
            value={pattern}
            onChange={e => setPattern(e.target.value)}
            placeholder="([a-z]+)\d+"
            className="w-full px-3 py-2 rounded border outline-none text-[11px]"
            style={inputStyle}
          />
          {error && (
            <p className="text-[10px] mt-1" style={{ fontFamily: 'var(--font-mono)', color: '#ef5a5a' }}>{error}</p>
          )}
        </div>
        <div>
          <label
            className="block text-[9px] tracking-widest uppercase mb-1.5"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            flags
          </label>
          <input
            value={flags}
            onChange={e => setFlags(e.target.value)}
            className="w-16 px-3 py-2 rounded border outline-none text-[11px]"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-bg)',
              borderColor: 'var(--hs-border-hover)',
              color: 'var(--hs-text-secondary)',
            }}
          />
        </div>
      </div>

      <div>
        <label
          className="block text-[9px] tracking-widest uppercase mb-1.5"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          texto de prueba
        </label>
        <textarea
          value={text}
          onChange={e => setText(e.target.value)}
          placeholder="texto donde buscar el patrón..."
          className="w-full h-32 px-3 py-2 rounded border resize-none outline-none text-[11px]"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
      </div>

      {highlighted.length > 0 && (
        <div>
          <p
            className="text-[9px] tracking-widest uppercase mb-1.5"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            resultado — {matches.length} match{matches.length !== 1 ? 'es' : ''}
          </p>
          <div
            className="p-3 rounded border text-[11px] whitespace-pre-wrap break-all"
            style={{ fontFamily: 'var(--font-mono)', background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
          >
            {highlighted.map((part, i) => (
              <span
                key={i}
                style={part.match ? { background: '#3a3510', color: '#dfc050', borderRadius: '2px' } : { color: 'var(--hs-text-secondary)' }}
              >
                {part.text}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}