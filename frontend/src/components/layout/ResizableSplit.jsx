import { useState, useRef, useCallback, useEffect } from 'react'

export function ResizableSplit({ left, right, initial = 50, min = 20, max = 80 }) {
  const [leftPct, setLeftPct] = useState(initial)
  const containerRef = useRef(null)
  const draggingRef = useRef(false)

  const onMouseDown = useCallback((e) => {
    e.preventDefault()
    draggingRef.current = true
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
  }, [])

  useEffect(() => {
    const onMouseMove = (e) => {
      if (!draggingRef.current || !containerRef.current) return
      const rect = containerRef.current.getBoundingClientRect()
      let pct = ((e.clientX - rect.left) / rect.width) * 100
      pct = Math.max(min, Math.min(max, pct))
      setLeftPct(pct)
    }
    const onMouseUp = () => {
      draggingRef.current = false
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    window.addEventListener('mousemove', onMouseMove)
    window.addEventListener('mouseup', onMouseUp)
    return () => {
      window.removeEventListener('mousemove', onMouseMove)
      window.removeEventListener('mouseup', onMouseUp)
    }
  }, [min, max])

  return (
    <div ref={containerRef} className="flex flex-1 overflow-hidden" style={{ minHeight: 0 }}>
      <div className="overflow-hidden flex flex-col" style={{ width: `${leftPct}%` }}>
        {left}
      </div>

      <div
        onMouseDown={onMouseDown}
        title="arrastra para redimensionar"
        style={{
          width: '5px',
          flexShrink: 0,
          cursor: 'col-resize',
          background: 'var(--hs-border)',
          transition: 'background 0.12s',
        }}
        onMouseEnter={e => { e.currentTarget.style.background = 'var(--hs-accent)' }}
        onMouseLeave={e => { e.currentTarget.style.background = 'var(--hs-border)' }}
      />

      <div className="overflow-hidden flex flex-col" style={{ width: `${100 - leftPct}%` }}>
        {right}
      </div>
    </div>
  )
}