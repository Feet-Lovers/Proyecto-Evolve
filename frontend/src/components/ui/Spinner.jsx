export function Spinner({ size = 'md' }) {
  const sizes = { sm: 'h-3 w-3', md: 'h-4 w-4', lg: 'h-6 w-6' }
  return (
    <div
      className={`animate-spin rounded-full border border-[#2a3040] border-t-[#a8e6bc] ${sizes[size]}`}
    />
  )
}