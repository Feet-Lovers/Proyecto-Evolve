import { useState } from 'react'
import { Badge } from '@/components/ui'

// Manual de uso. Se rellena UNA SECCION POR PESTANA, y solo cuando esa pestana
// se ha pulido y verificado: documentar lo que creemos que hace una pantalla, en
// vez de lo que hemos comprobado que hace, produce un manual que miente.
// Estado a 11-oct-2026: Spider verificado; las otras cuatro, pendientes.
//
// Las capturas viven en public/manual/ y se sirven estaticas. Si una falta, el
// hueco se marca solo (onError) en vez de dejar una imagen rota: el manual se
// puede desplegar incompleto sin parecer averiado.

function Seccion({ titulo, estado, children }) {
  return (
    <section className="mb-10">
      <div className="flex items-center gap-3 mb-2">
        <h3
          className="text-[13px] font-bold tracking-wide"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          {titulo}
        </h3>
        {estado === 'pendiente' && <Badge variant="default">pendiente</Badge>}
      </div>
      {children}
    </section>
  )
}

function P({ children }) {
  return (
    <p
      className="text-[11px] leading-relaxed mb-2 max-w-[70ch]"
      style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
    >
      {children}
    </p>
  )
}

function Lista({ items }) {
  return (
    <ul className="mb-2 max-w-[70ch]">
      {items.map(([clave, texto]) => (
        <li
          key={clave}
          className="text-[11px] leading-relaxed mb-1.5 pl-3"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
        >
          <span style={{ color: 'var(--hs-accent)' }}>{clave}</span>
          {' — '}
          {texto}
        </li>
      ))}
    </ul>
  )
}

function Captura({ src, pie }) {
  const [falta, setFalta] = useState(false)

  if (falta) {
    return (
      <figure className="my-4 max-w-[900px]">
        <div
          className="flex items-center justify-center px-4 py-6 border border-dashed"
          style={{ borderColor: 'var(--hs-border)', background: 'var(--hs-bg)' }}
        >
          <span
            className="text-[10px]"
            style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
          >
            captura pendiente — {pie}
          </span>
        </div>
      </figure>
    )
  }

  return (
    <figure className="my-4 max-w-[900px]">
      <img
        src={src}
        alt={pie}
        onError={() => setFalta(true)}
        className="w-full h-auto border"
        style={{ borderColor: 'var(--hs-border)' }}
      />
      <figcaption
        className="mt-1.5 text-[10px]"
        style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
      >
        {pie}
      </figcaption>
    </figure>
  )
}

function Pendiente({ nombre }) {
  return (
    <P>
      Esta seccion se escribira cuando se revise la pestana {nombre}. No se
      documenta antes a proposito: describir lo que se supone que hace una
      pantalla, en vez de lo que se ha comprobado que hace, produce un manual
      que induce a error.
    </P>
  )
}

export function ManualPage() {
  return (
    <div className="flex flex-col h-full">
      <div
        className="flex items-center justify-between px-5 py-3 border-b"
        style={{ background: 'var(--hs-surface)', borderColor: 'var(--hs-border)' }}
      >
        <h2
          className="text-[14px] font-bold tracking-wide"
          style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
        >
          Manual
        </h2>
        <span
          className="text-[10px]"
          style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-dim)' }}
        >
          como usar cada herramienta
        </span>
      </div>

      <div className="flex-1 min-h-0 overflow-auto px-5 py-4">
        <Seccion titulo="Spider">
          <P>
            Parte de una URL, la descarga, extrae los enlaces que apuntan al mismo
            dominio y los sigue hasta un tope. De cada pagina anota los formularios
            que encuentra, sin enviarlos. Sirve para saber que hay publicado en un
            sitio antes de probar nada: es descubrimiento, no ataque.
          </P>
          <P>
            No es un proxy: no se interpone entre el navegador y el servidor, ni
            hace falta configurar nada en el navegador. Las peticiones las lanza el
            propio servidor de HookSuite.
          </P>
          <Captura src="/manual/spider-general.png" pie="La pestana Spider: barra de control arriba, peticiones capturadas a la izquierda, detalle a la derecha." />

          <P>La barra de control, de izquierda a derecha:</P>
          <Lista items={[
            ['URL objetivo', 'el sitio que se va a rastrear. Al iniciar queda fijado y el campo se bloquea, para no mezclar dos objetivos en el mismo panel. Se libera con «nueva auditoria».'],
            ['alcance', 'maximo de paginas que se visitan (50, 200 o 500). No es velocidad: un alcance menor no va mas rapido, llega menos lejos. Cada pagina puede generar varias filas, una por cada formulario.'],
            ['Iniciar / Detener', 'arranca y para el rastreo. Al detener puede entrar una peticion mas: es la que ya estaba en curso.'],
          ]} />
          <Captura src="/manual/spider-barra.png" pie="Objetivo fijado y bloqueado, alcance en 200 paginas y el boton de detener durante un rastreo en marcha." />
          <Captura src="/manual/spider-alcance.png" pie="La ayuda del selector recuerda que el alcance cuenta paginas, no filas del panel." />

          <P>
            Cada boton explica su alcance al pasar el raton por encima, porque los
            tres de borrado hacen cosas distintas:
          </P>
          <Lista items={[
            ['limpiar', 'vacia la lista y detiene el rastreo. Mantiene la sesion y el objetivo.'],
            ['liberar sesion', 'suelta las cookies. Mantiene las peticiones capturadas y el objetivo.'],
            ['nueva auditoria', 'empieza de cero: vacia la lista, suelta la sesion y libera el campo de URL.'],
          ]} />
          <Captura src="/manual/spider-ayuda-boton.png" pie="La ayuda emergente de un boton indica exactamente que borra y que conserva." />

          <P>
            La tabla distingue dos tipos de fila. Las de tipo <b>pagina</b> son
            paginas descargadas, con su codigo de respuesta, tamano y tiempo. Las de
            tipo <b>form</b> son formularios encontrados en ellas: no se envian, por
            eso no tienen codigo ni tiempo, y en su lugar se indica cuantos campos
            tienen, que es lo que define su superficie de ataque.
          </P>
          <P>
            Un mismo formulario se cataloga una sola vez, aunque aparezca en muchas
            paginas. Por eso el desplegable dice «vistos aqui primero»: un buscador
            de cabecera estara colgado de la primera pagina donde se encontro, no de
            todas en las que existe.
          </P>
          <Captura src="/manual/spider-tabla-jerarquia.png" pie="Una pagina con su desplegable de formularios: cuelgan de la pagina donde se vieron por primera vez." />

          <P>
            El indicador de sesion dice si el rastreo lleva cookies. La sesion se
            comparte con el Repeater y el Intruder, asi que la via para rastrear
            autenticado es enviar una peticion de acceso desde el Repeater: el
            Spider hereda esa sesion.
          </P>
          <Lista items={[
            ['con sesion', 'el servidor ha devuelto cookies y el rastreo las esta usando. Indica presencia de cookies de sesion, no que la autenticacion sea valida.'],
            ['sin cookies de sesion', 'el rastreo va anonimo.'],
          ]} />
          <Captura src="/manual/spider-sesion.png" pie="Los dos estados del indicador de sesion: sin cookies y con sesion heredada del Repeater." />

          <P>
            Al terminar, el mensaje dice como acabo: completado, detenido a mano, o
            detenido por alcanzar el tope — en ese ultimo caso pueden quedar paginas
            sin analizar. Si el numero de URLs visitadas no coincide con el de
            paginas distintas, es que varias URLs redirigian al mismo destino.
          </P>
          <Captura src="/manual/spider-mensaje-final.png" pie="Mensaje de cierre: distingue URLs visitadas de paginas distintas cuando hubo redirecciones." />
        </Seccion>

        <Seccion titulo="Repeater" estado="pendiente"><Pendiente nombre="Repeater" /></Seccion>
        <Seccion titulo="Intruder" estado="pendiente"><Pendiente nombre="Intruder" /></Seccion>
        <Seccion titulo="Utilidades" estado="pendiente"><Pendiente nombre="Utilidades" /></Seccion>
        <Seccion titulo="Vulnerabilidades" estado="pendiente"><Pendiente nombre="Vulnerabilidades" /></Seccion>
      </div>
    </div>
  )
}
