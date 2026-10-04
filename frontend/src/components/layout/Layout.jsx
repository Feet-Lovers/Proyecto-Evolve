import { Outlet, NavLink } from 'react-router-dom'
import { useState, useEffect, useRef, createContext } from 'react'

export const ThemeContext = createContext({ dark: true, toggle: () => {} })

const navItems = [
  { path: '/proxy',           label: 'Proxy' },
  { path: '/repeater',        label: 'Repeater' },
  { path: '/intruder',        label: 'Intruder' },
  { path: '/utilities',       label: 'Utilidades' },
  { path: '/vulnerabilities', label: 'Vulnerabilidades' },
  { path: '/network',         label: 'Red' },
]

function SunIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="5"/>
      <line x1="12" y1="1" x2="12" y2="3"/>
      <line x1="12" y1="21" x2="12" y2="23"/>
      <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
      <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
      <line x1="1" y1="12" x2="3" y2="12"/>
      <line x1="21" y1="12" x2="23" y2="12"/>
      <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
      <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
    </svg>
  )
}

function MoonIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
    </svg>
  )
}

const DARK_VARS = `
  --hs-bg:             #0a0c0f;
  --hs-surface:        #0d0f13;
  --hs-bar:            #0d0f13;
  --hs-border:         #1e2128;
  --hs-border-hover:   #2a3040;
  --hs-text-primary:   #d0d8e0;
  --hs-text-secondary: #8a9aab;
  --hs-text-muted:     #5a6a7a;
  --hs-text-dim:       #3a4455;
  --hs-accent:         #6adf9a;
  --hs-accent-bg:      #0d1f17;
  --hs-accent-border:  #1e3d2a;
  --font-mono:         'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --font-sans:         system-ui, -apple-system, sans-serif;
`

const LIGHT_VARS = `
  --hs-bg:             #f2f3f5;
  --hs-surface:        #ffffff;
  --hs-bar:            #ffffff;
  --hs-border:         #e0e4ea;
  --hs-border-hover:   #c8cdd6;
  --hs-text-primary:   #1a1f2a;
  --hs-text-secondary: #4a5568;
  --hs-text-muted:     #718096;
  --hs-text-dim:       #a0aab8;
  --hs-accent:         #1a7a45;
  --hs-accent-bg:      #eaf7f0;
  --hs-accent-border:  #b3e6cc;
  --font-mono:         'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace;
  --font-sans:         system-ui, -apple-system, sans-serif;
`

export function Layout() {
  const [dark, setDark] = useState(true)
  const [showFlash, setShowFlash] = useState(false)
  const flashShownRef = useRef(false)

  const handleToggle = () => {
    setDark(prev => {
      const goingToLight = prev === true
      if (goingToLight && !flashShownRef.current) {
        flashShownRef.current = true
        setShowFlash(true)
        setTimeout(() => setShowFlash(false), 1250)
        const audio = new Audio('/flashbang.mp3')
        audio.play().catch(() => {})
      }
      return !prev
    })
  }

  return (
    <ThemeContext.Provider value={{ dark, toggle: handleToggle }}>
      <style>{`
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

        .hs-root {
          ${dark ? DARK_VARS : LIGHT_VARS}
          display: flex;
          flex-direction: column;
          height: 100vh;
          width: 100vw;
          background: var(--hs-bg);
          color: var(--hs-text-primary);
          font-family: var(--font-mono);
          font-size: 13px;
          overflow: hidden;
        }

        .hs-topbar {
          display: flex;
          align-items: center;
          height: 46px;
          background: var(--hs-bar);
          border-bottom: 1px solid var(--hs-border);
          flex-shrink: 0;
          padding: 0 8px 0 16px;
          gap: 0;
        }

        .hs-logo {
          font-size: 12px;
          font-weight: 700;
          color: var(--hs-accent);
          letter-spacing: 0.12em;
          text-transform: uppercase;
          padding-right: 20px;
          margin-right: 4px;
          border-right: 1px solid var(--hs-border);
          white-space: nowrap;
          flex-shrink: 0;
          font-family: var(--font-mono);
        }

        .hs-tabs {
          display: flex;
          align-items: stretch;
          flex: 1;
          height: 100%;
          margin-left: 4px;
        }

        .hs-tab {
          display: flex;
          align-items: center;
          padding: 0 18px;
          height: 100%;
          font-size: 11px;
          font-weight: 500;
          letter-spacing: 0.06em;
          text-transform: uppercase;
          color: var(--hs-text-muted);
          text-decoration: none;
          background: transparent;
          border: none;
          cursor: pointer;
          white-space: nowrap;
          position: relative;
          transition: color 0.12s, background 0.12s;
          font-family: var(--font-mono);
        }

        .hs-tab:hover {
          color: var(--hs-text-secondary);
          background: ${dark ? 'rgba(255,255,255,0.03)' : 'rgba(0,0,0,0.04)'};
        }

        .hs-tab.active {
          color: var(--hs-text-primary);
          background: ${dark ? 'rgba(255,255,255,0.05)' : 'rgba(0,0,0,0.06)'};
        }

        .hs-tab.active::after {
          content: '';
          position: absolute;
          bottom: 0;
          left: 0;
          right: 0;
          height: 2px;
          background: var(--hs-accent);
        }

        .hs-toggle {
          display: flex;
          align-items: center;
          justify-content: center;
          width: 32px;
          height: 32px;
          border-radius: 6px;
          background: transparent;
          border: 1px solid var(--hs-border);
          color: var(--hs-text-muted);
          cursor: pointer;
          flex-shrink: 0;
          transition: border-color 0.12s, color 0.12s, background 0.12s;
          margin-left: 12px;
        }

        .hs-toggle:hover {
          color: var(--hs-text-primary);
          border-color: var(--hs-border-hover);
          background: ${dark ? 'rgba(255,255,255,0.04)' : 'rgba(0,0,0,0.04)'};
        }

        .hs-content {
          flex: 1;
          overflow: auto;
          background: var(--hs-bg);
          zoom: 1.2;
          padding: 0 16px;
        }

        .hs-content::-webkit-scrollbar { width: 5px; height: 5px; }
        .hs-content::-webkit-scrollbar-track { background: transparent; }
        .hs-content::-webkit-scrollbar-thumb { background: var(--hs-border); border-radius: 3px; }
        .hs-content::-webkit-scrollbar-thumb:hover { background: var(--hs-border-hover); }

        .hs-flash-overlay {
          position: fixed;
          inset: 0;
          z-index: 9999;
          display: flex;
          align-items: center;
          justify-content: center;
          background: rgba(0, 0, 0, 0.6);
          animation: hs-flash-fade 1.25s ease-out forwards;
          pointer-events: none;
        }

        .hs-flash-img {
          width: 420px;
          max-width: 70vw;
          height: auto;
          border-radius: 8px;
        }

        @keyframes hs-flash-fade {
          0%   { opacity: 1; }
          75%  { opacity: 1; }
          100% { opacity: 0; }
        }
      `}</style>

      <div className="hs-root">
        <header className="hs-topbar">
          <span className="hs-logo">HookSuite</span>

          <nav className="hs-tabs">
            {navItems.map(item => (
              <NavLink
                key={item.path}
                to={item.path}
                className={({ isActive }) => isActive ? 'hs-tab active' : 'hs-tab'}
              >
                {item.label}
              </NavLink>
            ))}
          </nav>

          <button
            className="hs-toggle"
            onClick={handleToggle}
            aria-label={dark ? 'Cambiar a modo claro' : 'Cambiar a modo oscuro'}
            title={dark ? 'Modo claro' : 'Modo oscuro'}
          >
            {dark ? <SunIcon /> : <MoonIcon />}
          </button>
        </header>

        <main className="hs-content">
          <Outlet />
        </main>

        {showFlash && (
          <div className="hs-flash-overlay">
            <img src="/flashbang.gif" alt="" className="hs-flash-img" />
          </div>
        )}
      </div>
    </ThemeContext.Provider>
  )
}