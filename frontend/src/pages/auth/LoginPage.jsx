import { useState } from 'react'
import { Button } from '@/components/ui'
import { useAuth } from '@/AuthContext'

const mono = { fontFamily: 'var(--font-mono)' }

function Campo({ etiqueta, tipo = 'text', valor, onChange, autoFocus, pista, autoComplete }) {
  return (
    <label className="block">
      <span style={mono} className="block text-[10px] tracking-wider text-[#5a6170] mb-1 uppercase">
        {etiqueta}
      </span>
      <input
        type={tipo}
        value={valor}
        onChange={(e) => onChange(e.target.value)}
        autoFocus={autoFocus}
        autoComplete={autoComplete}
        style={mono}
        className="w-full px-3 py-2 rounded bg-[#0d0f13] border border-[#2a3040] text-[#c5ccd6]
                   text-[12px] focus:outline-none focus:border-[#3a4255] placeholder-[#3a4255]"
      />
      {pista && (
        <span style={mono} className="block text-[9px] text-[#4a5160] mt-1 leading-relaxed">{pista}</span>
      )}
    </label>
  )
}

/** Traduce el error del servidor a algo que una persona entienda.
 *
 *  Se hace aqui y no en el backend porque el backend debe responder escueto: un
 *  mensaje de error generoso en la API es tambien informacion para quien la ataca.
 */
function mensajeDeError(error, modo) {
  const estado = error?.response?.status
  const detalle = error?.response?.data?.detail
  if (estado === 401) return 'Usuario o contraseña incorrectos.'
  if (estado === 403) return 'El código de invitación no es correcto. Pídelo al equipo.'
  if (estado === 409) return 'Ese nombre de usuario ya está cogido. Elige otro.'
  if (estado === 400) return detalle || 'Hay algún dato que no vale.'
  if (estado === 500) return 'El servidor ha fallado. Avisa al equipo.'
  if (!error?.response) return 'No se puede contactar con el servidor.'
  return detalle || (modo === 'entrar' ? 'No se ha podido entrar.' : 'No se ha podido crear la cuenta.')
}

export function LoginPage() {
  const { iniciarSesion, registrar } = useAuth()
  const [modo, setModo] = useState('entrar')   // 'entrar' | 'registro'
  const [usuario, setUsuario] = useState('')
  const [contrasena, setContrasena] = useState('')
  const [repetir, setRepetir] = useState('')
  const [codigo, setCodigo] = useState('')
  const [error, setError] = useState('')
  const [aviso, setAviso] = useState('')
  const [enviando, setEnviando] = useState(false)

  const cambiarModo = (nuevo) => {
    setModo(nuevo)
    setError('')
    setAviso('')
    setContrasena('')
    setRepetir('')
    setCodigo('')
  }

  const enviar = async (e) => {
    e.preventDefault()
    setError('')
    setAviso('')

    // Se comprueba aqui lo que se puede comprobar aqui, para no gastar una peticion
    // en un error que ya se ve.
    if (modo === 'registro') {
      if (contrasena !== repetir) return setError('Las dos contraseñas no coinciden.')
      if (contrasena.length < 8) return setError('La contraseña debe tener al menos 8 caracteres.')
    }

    setEnviando(true)
    try {
      if (modo === 'entrar') {
        await iniciarSesion({ usuario: usuario.trim(), contrasena })
      } else {
        await registrar({ usuario: usuario.trim(), contrasena, codigo: codigo.trim() })
        // No se entra automaticamente: que la persona escriba su contraseña una vez
        // mas confirma que la recuerda, y es el momento mas barato para descubrir
        // que se ha equivocado.
        setAviso('Cuenta creada. Ya puedes entrar con ella.')
        setModo('entrar')
        setContrasena('')
        setRepetir('')
        setCodigo('')
      }
    } catch (err) {
      setError(mensajeDeError(err, modo))
    } finally {
      setEnviando(false)
    }
  }

  const esRegistro = modo === 'registro'

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#090a0d] px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-6">
          <h1 style={mono} className="text-[#a8e6bc] text-lg font-semibold tracking-wider">HookSuite</h1>
          <p style={mono} className="text-[10px] text-[#5a6170] tracking-wide mt-1">
            Auditoría de seguridad web
          </p>
        </div>

        <div className="rounded-lg border border-[#1e2230] bg-[#0d0f13] p-5">
          <div className="flex gap-1 mb-5 p-0.5 rounded bg-[#090a0d] border border-[#1e2230]">
            {[['entrar', 'Entrar'], ['registro', 'Crear cuenta']].map(([clave, texto]) => (
              <button
                key={clave}
                type="button"
                onClick={() => cambiarModo(clave)}
                style={mono}
                className={`flex-1 py-1.5 rounded text-[10px] tracking-wider transition-colors cursor-pointer ${
                  modo === clave
                    ? 'bg-[#0f1f17] text-[#a8e6bc]'
                    : 'text-[#5a6170] hover:text-[#8a9aab]'
                }`}
              >
                {texto}
              </button>
            ))}
          </div>

          <form onSubmit={enviar} className="space-y-3">
            <Campo
              etiqueta="Usuario"
              valor={usuario}
              onChange={setUsuario}
              autoFocus
              autoComplete="username"
            />
            <Campo
              etiqueta="Contraseña"
              tipo="password"
              valor={contrasena}
              onChange={setContrasena}
              autoComplete={esRegistro ? 'new-password' : 'current-password'}
              pista={esRegistro ? 'Mínimo 8 caracteres. Solo la sabes tú: se guarda cifrada.' : null}
            />
            {esRegistro && (
              <>
                <Campo
                  etiqueta="Repetir contraseña"
                  tipo="password"
                  valor={repetir}
                  onChange={setRepetir}
                  autoComplete="new-password"
                />
                <Campo
                  etiqueta="Código de invitación"
                  valor={codigo}
                  onChange={setCodigo}
                  pista="El registro no es abierto: esta herramienta lanza tráfico contra terceros. Pide el código al equipo."
                />
              </>
            )}

            {error && (
              <div style={mono} className="rounded border border-[#3d1a1a] bg-[#1f0d0d] px-3 py-2 text-[10px] text-[#ef7a7a] leading-relaxed">
                {error}
              </div>
            )}
            {aviso && (
              <div style={mono} className="rounded border border-[#1a3d2a] bg-[#0d1f17] px-3 py-2 text-[10px] text-[#6adf9a] leading-relaxed">
                {aviso}
              </div>
            )}

            <Button size="lg" className="w-full mt-1" disabled={enviando || !usuario || !contrasena}>
              {enviando
                ? (esRegistro ? 'Creando…' : 'Entrando…')
                : (esRegistro ? 'Crear cuenta' : 'Entrar')}
            </Button>
          </form>
        </div>

        <p style={mono} className="text-center text-[9px] text-[#3a4255] mt-4 leading-relaxed">
          Cada usuario ve solo sus propias auditorías.
        </p>
      </div>
    </div>
  )
}
