import { useState, useEffect } from 'react'

export function useSession() {
  const [token, setToken] = useState(null)

  useEffect(() => {
    let stored = localStorage.getItem('hooksuite_session')
    if (!stored) {
      stored = crypto.randomUUID()
      localStorage.setItem('hooksuite_session', stored)
    }
    setToken(stored)
  }, [])

  return token
}