export function Panel({ children, className = '' }) {
  return (
    <div className={`bg-[#0d0f13] border border-[#1e2128] rounded-lg ${className}`}>
      {children}
    </div>
  )
}