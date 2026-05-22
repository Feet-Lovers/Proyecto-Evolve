import { useState } from 'react'

export function LoginPage({ onLogin, loading, error }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const handleSubmit = async () => {
    if (!username || !password) return
    await onLogin(username, password)
  }

  const inputStyle = {
    fontFamily: 'var(--font-mono)',
    background: 'var(--hs-bg)',
    borderColor: 'var(--hs-border-hover)',
    color: 'var(--hs-text-secondary)',
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center"
      style={{ background: 'var(--hs-bg)' }}
    >
      <div
        className="w-full max-w-sm p-8 rounded-xl border"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="mb-8">
          <h1
            className="text-[20px] font-bold tracking-wide"
            style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
          >
            HookSuite
          </h1>
          <p
            className="text-[9px] tracking-widest uppercase mt-1"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-green)' }}
          >
            Web Security Toolkit
          </p>
        </div>

        <div className="space-y-4">
          <div>
            <label
              className="block text-[9px] tracking-widest uppercase mb-1.5"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              usuario
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="admin"
              className="w-full px-3 py-2 rounded border outline-none text-[11px]"
              style={inputStyle}
            />
          </div>

          <div>
            <label
              className="block text-[9px] tracking-widest uppercase mb-1.5"
              style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            >
              contraseña
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleSubmit()}
              placeholder="••••••••"
              className="w-full px-3 py-2 rounded border outline-none text-[11px]"
              style={inputStyle}
            />
          </div>

          {error && (
            <p
              className="text-[10px]"
              style={{ fontFamily: 'var(--font-mono)', color: '#ef5a5a' }}
            >
              ⚠ {error}
            </p>
          )}

          <button
            onClick={handleSubmit}
            disabled={loading || !username || !password}
            className="w-full py-2 rounded border text-[11px] font-medium tracking-wide transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            style={{
              fontFamily: 'var(--font-mono)',
              background: 'var(--hs-accent-bg)',
              borderColor: 'var(--hs-accent-border)',
              color: 'var(--hs-accent)',
            }}
          >
            {loading ? 'conectando...' : 'iniciar sesión'}
          </button>
        </div>

        <p
          className="text-[9px] text-center mt-6 tracking-widest"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          v1.0.0 — módulo de ciberseguridad avanzada 2026
        </p>
      </div>
    </div>
  )
}