import { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { leerToken, quienSoy, entrar, salir, registrar, alPerderSesion } from '@/services/api'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [usuario, setUsuario] = useState(null)
  // 'comprobando' evita el parpadeo del panel de entrada al recargar con sesion
  // valida: sin esto se ve el formulario un instante antes de entrar.
  const [estado, setEstado] = useState('comprobando')

  // Al cargar, se PREGUNTA al servidor si el token guardado sigue valiendo, en vez de
  // suponerlo por que exista en el navegador. Un token caducado existe igual.
  useEffect(() => {
    let cancelado = false
    if (!leerToken()) {
      setEstado('fuera')
      return
    }
    quienSoy()
      .then((datos) => {
        if (!cancelado) {
          setUsuario(datos.usuario)
          setEstado('dentro')
        }
      })
      .catch(() => {
        if (!cancelado) setEstado('fuera')
      })
    return () => { cancelado = true }
  }, [])

  // Si una llamada cualquiera recibe un 401, el cliente avisa y aqui se cierra la
  // sesion. Asi la caducidad se nota en toda la aplicacion, no solo en la pantalla
  // que hizo la peticion.
  useEffect(() => alPerderSesion(() => {
    setUsuario(null)
    setEstado('fuera')
  }), [])

  const iniciarSesion = useCallback(async (credenciales) => {
    const datos = await entrar(credenciales)
    setUsuario(datos.usuario)
    setEstado('dentro')
    return datos
  }, [])

  const cerrarSesion = useCallback(async () => {
    await salir()
    setUsuario(null)
    setEstado('fuera')
  }, [])

  return (
    <AuthContext.Provider value={{
      usuario,
      estado,
      autenticado: estado === 'dentro',
      iniciarSesion,
      cerrarSesion,
      registrar,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth debe usarse dentro de AuthProvider')
  return ctx
}
