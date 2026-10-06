import { useAuth } from '@/AuthContext'

/** Espacio de datos del usuario autenticado.
 *
 *  Antes este hook FABRICABA el identificador en el navegador con `Math.random()` y lo
 *  guardaba en localStorage, y el servidor abría una sesión para cualquier cadena que
 *  recibiera. Dos problemas de distinta gravedad: `Math.random()` no es
 *  criptográficamente seguro, y —lo serio— el cliente no debería poder elegir en qué
 *  espacio de datos escribe.
 *
 *  Se conserva el hook, en vez de borrarlo y tocar sus dos usos, porque así hay un
 *  único sitio que decide esto. Si mañana el espacio deja de ser el nombre del usuario,
 *  se cambia aquí y en `AppContext`, no en cada pantalla.
 */
export function useSession() {
  const { usuario } = useAuth()
  return usuario
}
