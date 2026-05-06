export function ErrorMessage({ message, onRetry }) {
  return (
    <div
      className="flex items-center gap-3 p-3 rounded border text-[11px]"
      style={{ background: '#1a0d0d', borderColor: '#3d1a1a' }}
    >
      <span style={{ color: '#ef5a5a' }}>⚠</span>
      <p className="flex-1" style={{ fontFamily: 'var(--font-mono)', color: '#ef7a7a' }}>{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="underline text-[10px]"
          style={{ fontFamily: 'var(--font-mono)', color: '#ef5a5a' }}
        >
          reintentar
        </button>
      )}
    </div>
  )
}