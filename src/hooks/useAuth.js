import { useState, useEffect } from 'react'

export function useAuth() {
  const [uid, setUid] = useState(localStorage.getItem('uid'))
  const [proxyPort, setProxyPort] = useState(localStorage.getItem('proxy_port'))
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const login = async (username, password) => {
    setLoading(true)
    setError('')
    try {
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })
      if (!res.ok) { setError('Usuario o contraseña incorrectos'); return false }
      const data = await res.json()
      localStorage.setItem('uid', data.uid)
      localStorage.setItem('proxy_port', data.proxy_port)
      setUid(data.uid)
      setProxyPort(data.proxy_port)
      return true
    } catch {
      setError('Error de conexión con el servidor')
      return false
    } finally {
      setLoading(false)
    }
  }

  const logout = async () => {
    const storedUid = localStorage.getItem('uid')
    if (storedUid) {
      await fetch('/api/auth/logout', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ uid: storedUid }),
      })
    }
    localStorage.removeItem('uid')
    localStorage.removeItem('proxy_port')
    setUid(null)
    setProxyPort(null)
  }

  const checkSession = async () => {
    const storedUid = localStorage.getItem('uid')
    if (!storedUid) return false
    try {
      const res = await fetch(`/api/auth/session/${storedUid}`)
      if (!res.ok) {
        localStorage.removeItem('uid')
        localStorage.removeItem('proxy_port')
        setUid(null)
        setProxyPort(null)
        return false
      }
      return true
    } catch {
      return false
    }
  }

  useEffect(() => { if (uid) checkSession() }, [])

  return { uid, proxyPort, login, logout, loading, error }
}