export function EmptyState({ title, description }) {
  return (
    <div className="flex flex-col items-center justify-center h-full py-12 text-center gap-3">
      <div
        className="w-10 h-10 rounded-full flex items-center justify-center text-lg"
        style={{ background: 'var(--hs-surface)', border: '1px solid var(--hs-border)' }}
      >
        <span style={{ color: 'var(--hs-text-dim)' }}>○</span>
      </div>
      <p
        className="text-[12px] font-semibold"
        style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-muted)' }}
      >
        {title}
      </p>
      {description && (
        <p
          className="text-[10px] max-w-xs"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          {description}
        </p>
      )}
    </div>
  )
}