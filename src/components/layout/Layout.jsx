import { Outlet, NavLink } from 'react-router-dom'
import ProxyConfig from '@/components/ProxyConfig'

const navItems = [
  { path: '/proxy',           label: 'Proxy',            icon: '⇄' },
  { path: '/repeater',        label: 'Repeater',         icon: '↺' },
  { path: '/intruder',        label: 'Intruder',         icon: '⚡' },
  { path: '/utilities',       label: 'Utilidades',       icon: '#'  },
  { path: '/vulnerabilities', label: 'Vulnerabilidades', icon: '!'  },
  { path: '/network',         label: 'Red',              icon: '~'  },
]

export function Layout({ onLogout, proxyPort }) {
  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'var(--hs-bg)' }}>
      <aside
        className="w-[200px] flex-shrink-0 flex flex-col border-r"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <div className="px-4 py-4 border-b" style={{ borderColor: 'var(--hs-border)' }}>
          <h1
            className="text-[16px] font-bold tracking-wide"
            style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
          >
            HookSuite
          </h1>
          <p
            className="text-[9px] mt-0.5 tracking-widest uppercase"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-green)' }}
          >
            Web Security Toolkit
          </p>
        </div>

        <nav className="flex-1 px-2 py-3 flex flex-col gap-0.5">
          {navItems.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-3 py-[7px] rounded text-[12px] transition-all border ${
                  isActive
                    ? 'border-[#1e3d2a] bg-[#0f1f17] text-[#a8e6bc]'
                    : 'border-transparent text-[#5a6170] hover:bg-[#13161c] hover:text-[#9da8b5]'
                }`
              }
              style={{ fontFamily: 'var(--font-sans)', fontWeight: 500 }}
            >
              <span
                className="w-[18px] text-center text-[11px] opacity-80"
                style={{ fontFamily: 'var(--font-mono)' }}
              >
                {item.icon}
              </span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 pb-3">
          <ProxyConfig proxyPort={proxyPort} />
        </div>

        <div
          className="px-4 py-3 border-t flex items-center justify-between"
          style={{ borderColor: 'var(--hs-border)' }}
        >
          <span
            className="text-[9px] tracking-widest"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            v1.0.0
          </span>
          <button
            onClick={onLogout}
            className="text-[9px] tracking-wide transition-colors"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
            onMouseEnter={e => e.target.style.color = '#ef5a5a'}
            onMouseLeave={e => e.target.style.color = 'var(--hs-text-dim)'}
          >
            logout
          </button>
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}