export function Button({ children, variant = 'primary', size = 'md', onClick, disabled, className = '' }) {
  const base = 'inline-flex items-center justify-center font-medium rounded transition-all focus:outline-none disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer'

  const variants = {
    primary:   'bg-[#0f1f17] border border-[#1e3d2a] text-[#a8e6bc] hover:bg-[#142a1f]',
    secondary: 'bg-[#0d0f13] border border-[#2a3040] text-[#8a9aab] hover:border-[#3a4255] hover:text-[#9da8b5]',
    danger:    'bg-[#1f0d0d] border border-[#3d1a1a] text-[#ef7a7a] hover:bg-[#2a1010]',
    ghost:     'bg-transparent border border-[#2a3040] text-[#5a6170] hover:border-[#3a4255] hover:text-[#8a9aab]',
  }

  const sizes = {
    sm: 'px-3 py-1 text-[10px] tracking-wide',
    md: 'px-4 py-1.5 text-[11px] tracking-wide',
    lg: 'px-5 py-2 text-xs tracking-wide',
  }

  return (
    <button
      onClick={onClick}
      disabled={disabled}
      style={{ fontFamily: 'var(--font-mono)' }}
      className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
    >
      {children}
    </button>
  )
}