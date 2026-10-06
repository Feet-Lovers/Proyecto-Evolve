import axios from 'axios'

const USE_MOCKS = false
const API_BASE = import.meta.env.VITE_API_URL || ''  // '' = mismo origen (via Nginx: /api, /ws)
export const config = { USE_MOCKS, API_BASE }

// --- Token de sesion -------------------------------------------------------------
// Antes cada pagina llamaba a axios o a fetch por su cuenta y no habia ningun sitio
// comun por donde pasara la autenticacion. Esto es ese sitio: si manana cambia la
// forma de autenticar, se cambia aqui y no en siete ficheros.

const CLAVE_TOKEN = 'hooksuite_token'

export function leerToken() {
  return localStorage.getItem(CLAVE_TOKEN) || null
}

export function guardarToken(token) {
  if (token) localStorage.setItem(CLAVE_TOKEN, token)
  else localStorage.removeItem(CLAVE_TOKEN)
}

// Quien quiera enterarse de que la sesion ha caducado se suscribe aqui. Lo usa el
// contexto de autenticacion para sacar al usuario al panel de entrada sin que cada
// pagina tenga que comprobarlo.
const oyentes = new Set()
export function alPerderSesion(fn) {
  oyentes.add(fn)
  return () => oyentes.delete(fn)
}
function avisarSesionPerdida() {
  guardarToken(null)
  oyentes.forEach((fn) => fn())
}

// --- Cliente unico ---------------------------------------------------------------

export const api = axios.create({ baseURL: API_BASE })

// Pone el token en cada peticion. Se lee en el momento de enviar, no al crear el
// cliente: asi un login o un cierre de sesion surten efecto sin recargar la pagina.
api.interceptors.request.use((cfg) => {
  const token = leerToken()
  if (token) cfg.headers.Authorization = `Bearer ${token}`
  return cfg
})

// Un 401 significa que el token ya no vale (caducado o revocado). Se trata en un solo
// sitio: se borra y se avisa, en vez de que cada pantalla decida por su cuenta.
api.interceptors.response.use(
  (r) => r,
  (error) => {
    if (error?.response?.status === 401) avisarSesionPerdida()
    return Promise.reject(error)
  },
)

// Envoltorio para los sitios que usan fetch (las paginas del proxy). Misma cabecera y
// mismo tratamiento del 401, para que no haya dos caminos con reglas distintas.
export async function apiFetch(url, opciones = {}) {
  const token = leerToken()
  const cabeceras = { ...(opciones.headers || {}) }
  if (token) cabeceras.Authorization = `Bearer ${token}`
  const respuesta = await fetch(`${API_BASE}${url}`, { ...opciones, headers: cabeceras })
  if (respuesta.status === 401) avisarSesionPerdida()
  return respuesta
}

// --- Autenticacion ---------------------------------------------------------------

export async function registrar({ usuario, contrasena, codigo }) {
  const { data } = await api.post('/api/auth/registro', {
    username: usuario,
    password: contrasena,
    codigo,
  })
  return data
}

export async function entrar({ usuario, contrasena }) {
  const { data } = await api.post('/api/auth/login', {
    username: usuario,
    password: contrasena,
  })
  guardarToken(data.access_token)
  return data
}

export async function quienSoy() {
  const { data } = await api.get('/api/auth/yo')
  return data
}

export async function salir() {
  try {
    await api.post('/api/auth/logout')
  } finally {
    // Se borra el token local pase lo que pase: si el servidor no responde, el
    // usuario igualmente quiere quedarse fuera.
    guardarToken(null)
  }
}
