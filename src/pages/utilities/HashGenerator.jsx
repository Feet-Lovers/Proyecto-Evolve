import { useState } from 'react'
import { Button } from '@/components/ui'
import axios from 'axios'
import { config } from '@/services/api'

const MOCK_HASHES = {
  md5:    '5f4dcc3b5aa765d61d8327deb882cf99',
  sha1:   '5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8',
  sha256: '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8',
  sha512: 'b109f3bbbc244eb82441917ed06d618b9008dd09b3befd1b5e07394c706a8bb980b1d7785e5976ec049b46df5f1326af5a2ea6d103fd07c95385ffab0cacbc86',
}

export function HashGenerator() {
  const [input, setInput] = useState('')
  const [hashes, setHashes] = useState(null)
  const [loading, setLoading] = useState(false)

  const generate = async () => {
    if (!input) return
    setLoading(true)
    try {
      if (config.USE_MOCKS) {
        await new Promise(r => setTimeout(r, 300))
        setHashes(MOCK_HASHES)
        return
      }
      const res = await axios.post(`${config.API_BASE}/api/utils/hash`, { text: input })
      setHashes(res.data)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex gap-2">
        <input
          value={input}
          onChange={e => setInput(e.target.value)}
          placeholder="texto a hashear..."
          onKeyDown={e => e.key === 'Enter' && generate()}
          className="flex-1 px-3 py-2 rounded border outline-none text-[11px]"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        />
        <Button onClick={generate} disabled={loading || !input}>
          {loading ? 'generando...' : 'generar'}
        </Button>
      </div>

      {hashes && (
        <div className="space-y-2">
          {Object.entries(hashes).map(([algo, hash]) => (
            <div
              key={algo}
              className="rounded border p-3"
              style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
            >
              <div className="flex items-center justify-between mb-1">
                <p
                  className="text-[9px] tracking-widest uppercase"
                  style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
                >
                  {algo}
                </p>
                <button
                  onClick={() => navigator.clipboard.writeText(hash)}
                  className="text-[10px]"
                  style={{ fontFamily: 'var(--font-mono)', color: '#6aafef' }}
                >
                  copiar
                </button>
              </div>
              <p
                className="text-[10px] break-all"
                style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
              >
                {hash}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}