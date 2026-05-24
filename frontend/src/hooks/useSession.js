import { useState, useEffect } from 'react'

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0
    const v = c === 'x' ? r : (r & 0x3 | 0x8)
    return v.toString(16)
  })
}

export function useSession() {
  const [sessionToken, setSessionToken] = useState(null)

  useEffect(() => {
    let stored = localStorage.getItem('hooksuite_session')
    if (!stored) {
      stored = generateUUID()
      localStorage.setItem('hooksuite_session', stored)
    }
    setSessionToken(stored)
  }, [])

  return sessionToken
}
