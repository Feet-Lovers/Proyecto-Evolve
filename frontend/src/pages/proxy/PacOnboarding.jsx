import { useState, useEffect } from 'react'
import { Button } from '@/components/ui'
import { config } from '@/services/api'

const PAC_URL = `${config.API_BASE}/proxy.pac`

function detectBrowserOS() {
  const ua = navigator.userAgent
  const platform = navigator.platform
  if (ua.includes('Firefox')) return { browser: 'Firefox', os: platform.includes('Win') ? 'Windows' : 'Mac' }
  if (ua.includes('Edg')) return { browser: 'Edge', os: 'Windows' }
  return { browser: 'Chrome', os: platform.includes('Win') ? 'Windows' : 'Mac' }
}

const INSTRUCTIONS = {
  'Chrome-Windows': [
    'Abre el menú de Chrome (tres puntos arriba a la derecha)',
    'Ve a Configuración → Sistema → Abrir configuración de proxy',
    'Activa "Usar script de configuración automática"',
    'Pega la URL del PAC en el campo de dirección',
    'Haz clic en Guardar',
  ],
  'Chrome-Mac': [
    'Abre Preferencias del Sistema → Red',
    'Selecciona tu conexión activa y haz clic en Avanzado',
    'Ve a la pestaña Proxies',
    'Activa "Configuración automática de proxy"',
    'Pega la URL del PAC y haz clic en Aceptar',
  ],
  'Firefox-Windows': [
    'Abre Ajustes → General → Configuración de red (al final)',
    'Selecciona "URL de configuración automática de proxy"',
    'Pega la URL del PAC',
    'Haz clic en Aceptar',
  ],
  'Firefox-Mac': [
    'Abre Preferencias → General → Configuración de red',
    'Selecciona "URL de configuración automática de proxy"',
    'Pega la URL del PAC y haz clic en Aceptar',
  ],
}

export function PacOnboarding({ onComplete }) {
  const [copied, setCopied] = useState(false)
  const [checking, setChecking] = useState(false)
  const [proxyActive, setProxyActive] = useState(false)
  const { browser, os } = detectBrowserOS()
  const instructions = INSTRUCTIONS[`${browser}-${os}`] || INSTRUCTIONS['Chrome-Windows']

  const copyPacUrl = async () => {
    await navigator.clipboard.writeText(PAC_URL)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  useEffect(() => {
    if (config.USE_MOCKS) return
    setChecking(true)
    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${config.API_BASE}/check/alive`)
        if (res.ok) {
          setProxyActive(true)
          clearInterval(interval)
          setTimeout(onComplete, 1500)
        }
      } catch {}
    }, 2000)
    return () => clearInterval(interval)
  }, [onComplete])

  return (
    <div className="fixed inset-0 flex items-center justify-center z-50" style={{ background: 'rgba(0,0,0,0.7)' }}>
      <div
        className="w-full max-w-lg p-6 rounded-xl border"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h2
          className="text-[14px] font-bold mb-1"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          Configura el proxy
        </h2>
        <p
          className="text-[11px] mb-4"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}
        >
          Detectado: {browser} en {os}. Sigue estos pasos una sola vez.
        </p>

        <div
          className="rounded-lg p-3 mb-4 border"
          style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
        >
          <p
            className="text-[9px] tracking-widest uppercase mb-1"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            URL del archivo PAC
          </p>
          <div className="flex gap-2 items-center">
            <code
              className="flex-1 text-[11px] break-all"
              style={{ fontFamily: 'var(--font-mono)', color: '#6aafef' }}
            >
              {PAC_URL}
            </code>
            <Button size="sm" onClick={copyPacUrl} variant={copied ? 'secondary' : 'primary'}>
              {copied ? '✓ copiado' : 'copiar'}
            </Button>
          </div>
        </div>

        <ol className="space-y-2 mb-6">
          {instructions.map((step, i) => (
            <li key={i} className="flex gap-3 text-[11px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}>
              <span
                className="flex-shrink-0 w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-bold"
                style={{ background: 'var(--hs-accent-bg)', border: '1px solid var(--hs-accent-border)', color: 'var(--hs-accent)' }}
              >
                {i + 1}
              </span>
              {step}
            </li>
          ))}
        </ol>

        {proxyActive ? (
          <p className="text-[11px]" style={{ fontFamily: 'var(--font-mono)', color: '#4a9a5a' }}>
            ✓ proxy activo. cerrando...
          </p>
        ) : checking ? (
          <p className="text-[11px]" style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-muted)' }}>
            verificando que el proxy está activo...
          </p>
        ) : (
          <Button onClick={onComplete} variant="ghost" size="sm">omitir por ahora</Button>
        )}
      </div>
    </div>
  )
}