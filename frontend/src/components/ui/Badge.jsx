const VARIANTS = {
  default:  'bg-[#13161c] border-[#2a3040] text-[#5a6170]',
  get:      'bg-[#0d1a2e] border-[#1a3560] text-[#6aafef]',
  post:     'bg-[#0d1f17] border-[#1a3d2a] text-[#6adf9a]',
  put:      'bg-[#1a1a0a] border-[#3a3510] text-[#dfc050]',
  delete:   'bg-[#1f0d0d] border-[#3d1a1a] text-[#ef7a7a]',
  patch:    'bg-[#1a0d1f] border-[#3d1a5a] text-[#bf7aef]',
  critical: 'bg-[#1f0a0a] border-[#4d1515] text-[#ef5a5a]',
  high:     'bg-[#1f1508] border-[#4d3510] text-[#ef9040]',
  medium:   'bg-[#1a1a08] border-[#3a3510] text-[#dfc050]',
  low:      'bg-[#0d130d] border-[#1a2d1a] text-[#4a9a5a]',
  success:  'bg-[#0d1f17] border-[#1a3d2a] text-[#6adf9a]',
  warning:  'bg-[#1a1a08] border-[#3a3510] text-[#dfc050]',
  danger:   'bg-[#1f0a0a] border-[#4d1515] text-[#ef5a5a]',
}

export function Badge({ children, variant = 'default' }) {
  return (
    <span
      style={{ fontFamily: 'var(--font-mono)' }}
      className={`inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold tracking-wider border ${VARIANTS[variant] ?? VARIANTS.default}`}
    >
      {children}
    </span>
  )
}