import { Badge } from '@/components/ui'

// Manual de uso. Se rellena UNA SECCION POR PESTANA, y solo cuando esa pestana
// se ha pulido y verificado: documentar lo que creemos que hace una pantalla, en
// vez de lo que hemos comprobado que hace, produce un manual que miente.
// Estado a 11-oct-2026: Spider verificado contra el codigo; las otras, pendientes.
//
// Criterio de redaccion: la prosa va acentuada, pero los nombres de los controles
// se citan LITERALES, tal y como aparecen en pantalla ('nueva auditoria', sin
// tilde), para que se puedan buscar con la vista.

function Seccion({ titulo, estado, children }) {
  return (
    <section className="mb-10">
      <div className="flex items-center gap-3 mb-3">
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

function Sub({ children }) {
  return (
    <h4
      className="text-[11px] font-bold mt-5 mb-2 tracking-wide"
      style={{ fontFamily: 'var(--font-sans)', color: 'var(--hs-text-primary)' }}
    >
      {children}
    </h4>
  )
}

function P({ children }) {
  return (
    <p
      className="text-[11px] leading-relaxed mb-2 max-w-[78ch]"
      style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
    >
      {children}
    </p>
  )
}

function Controles({ children }) {
  return <ul className="mb-2 max-w-[78ch] space-y-2">{children}</ul>
}

// Cada elemento de la interfaz se nombra diciendo QUE ES: un boton no se pulsa
// igual que se rellena un campo, y un aviso no se pulsa en absoluto.
function Control({ tipo, nombre, children }) {
  return (
    <li
      className="text-[11px] leading-relaxed flex gap-2"
      style={{ fontFamily: 'var(--font-mono)', color: 'var(--hs-text-secondary)' }}
    >
      <span
        className="shrink-0 inline-block text-center text-[9px] px-1.5 py-0.5 rounded border uppercase tracking-wider"
        style={{
          minWidth: '86px',
          borderColor: 'var(--hs-border)',
          background: 'var(--hs-surface)',
          color: 'var(--hs-text-dim)',
        }}
      >
        {tipo}
      </span>
      <span>
        <span style={{ color: 'var(--hs-accent)' }}>{nombre}</span>
        {' — '}
        {children}
      </span>
    </li>
  )
}

function Pendiente({ nombre }) {
  return (
    <P>
      Esta sección se escribirá cuando se revise la pestaña {nombre}. No se
      documenta antes a propósito: describir lo que se supone que hace una
      pantalla, en vez de lo que se ha comprobado que hace, produce un manual que
      induce a error.
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
          cómo usar cada herramienta
        </span>
      </div>

      <div className="flex-1 min-h-0 overflow-auto px-5 py-4">
        <Seccion titulo="Spider">
          <P>
            Parte de una URL, la descarga, extrae los enlaces que apuntan al mismo
            dominio y los sigue hasta un tope. De cada página anota los formularios
            que encuentra, <b>sin enviarlos</b>. Sirve para saber qué hay publicado
            en un sitio antes de probar nada: es descubrimiento, no ataque.
          </P>
          <P>
            No es un proxy: no se interpone entre tu navegador y el servidor, y no
            hay que configurar nada en el navegador. Las peticiones las lanza el
            propio servidor de HookSuite, así que lo que veas aquí es lo que ve él,
            no lo que ve tu equipo.
          </P>
          <P>
            La pantalla tiene tres zonas: la <b>barra de control</b> arriba, el{' '}
            <b>panel de peticiones</b> a la izquierda y el <b>panel de detalle</b> a
            la derecha.
          </P>

          <Sub>Barra de control</Sub>
          <Controles>
            <Control tipo="indicador" nombre="conectado">
              estado de la conexión en vivo con el servidor. Si pone{' '}
              <i>sin conexion</i>, el rastreo puede estar corriendo igualmente, pero
              las peticiones no irán apareciendo solas: recarga la página.
            </Control>
            <Control tipo="indicador" nombre="con sesión / sin cookies de sesión">
              dice si el rastreo lleva cookies, y cuáles por su nombre. Ojo al
              matiz: indica que <b>hay</b> cookies de sesión, no que la
              autenticación sea válida ni que siga viva.
            </Control>
            <Control tipo="botón" nombre="liberar sesion">
              suelta las cookies. Conserva las peticiones ya capturadas y el
              objetivo. Úsalo para repetir un rastreo como usuario anónimo y
              comparar qué cambia.
            </Control>
            <Control tipo="campo de texto" nombre="URL objetivo">
              el sitio que se va a rastrear. Al pulsar <i>Iniciar spider</i> queda
              fijado y el campo se bloquea, para que no se mezclen dos objetivos
              distintos en el mismo panel. Se libera con <i>nueva auditoria</i>.
            </Control>
            <Control tipo="desplegable" nombre="hasta N páginas">
              máximo de páginas que se visitan: 50, 200 o 500. <b>No es
              velocidad</b>: un número menor no va más rápido, llega menos lejos. Y
              cuenta páginas, no filas del panel: cada página puede añadir varias
              filas, una por cada formulario que tenga.
            </Control>
            <Control tipo="botón" nombre="Iniciar spider">
              arranca el rastreo. Mientras corre, en su sitio aparece{' '}
              <i>Detener</i>.
            </Control>
            <Control tipo="botón" nombre="Detener">
              para el rastreo. Puede entrar todavía una petición más: es la que ya
              estaba en vuelo cuando pulsaste.
            </Control>
            <Control tipo="aviso" nombre="objetivo fijado">
              texto informativo, no se pulsa. Aparece bajo el campo cuando ya hay
              un objetivo y recuerda cómo cambiarlo.
            </Control>
          </Controles>

          <Sub>Los tres borrados no son lo mismo</Sub>
          <P>
            Es el punto donde más fácil es equivocarse, así que cada botón explica
            su alcance al pasar el ratón por encima:
          </P>
          <Controles>
            <Control tipo="botón" nombre="limpiar">
              vacía la lista de peticiones y detiene el rastreo. <b>Conserva</b> la
              sesión y el objetivo.
            </Control>
            <Control tipo="botón" nombre="liberar sesion">
              suelta las cookies. <b>Conserva</b> las peticiones y el objetivo.
            </Control>
            <Control tipo="botón" nombre="nueva auditoria">
              empieza de cero: vacía la lista, suelta la sesión y libera el campo de
              URL. Es el único que permite cambiar de objetivo.
            </Control>
          </Controles>

          <Sub>Panel de peticiones (izquierda)</Sub>
          <Controles>
            <Control tipo="campo de texto" nombre="filtrar por url...">
              deja a la vista solo las filas cuya URL contenga ese texto. No
              distingue mayúsculas y no hace falta pulsar nada: filtra según
              escribes.
            </Control>
            <Control tipo="desplegable" nombre="ALL">
              filtra por método HTTP: <i>ALL</i>, <i>GET</i>, <i>POST</i>,{' '}
              <i>PUT</i>, <i>DELETE</i> o <i>PATCH</i>.
            </Control>
            <Control tipo="columna" nombre="tipo">
              <i>PAGINA</i> si es una página que se descargó; <i>FORM</i> si es un
              formulario encontrado dentro de una.
            </Control>
            <Control tipo="columna" nombre="status">
              el código de respuesta, coloreado por familia: verde 2xx, azul 3xx
              (redirección), ámbar 4xx (error del cliente), rojo 5xx (error del
              servidor). Las filas <i>FORM</i> lo llevan vacío, porque el formulario
              no se ha enviado.
            </Control>
            <Control tipo="columna" nombre="tamaño y tiempo">
              peso de la respuesta y lo que tardó. También vacíos en las filas{' '}
              <i>FORM</i>; ahí lo que se indica es <b>cuántos campos</b> tiene el
              formulario, que es lo que define su superficie de ataque.
            </Control>
            <Control tipo="desplegable" nombre="[N formularios · vistos aqui primero]">
              despliega los formularios que cuelgan de esa página. Un mismo
              formulario se cataloga <b>una sola vez</b> aunque esté en muchas
              páginas: un buscador de cabecera aparecerá bajo la primera página
              donde se encontró, no bajo todas. Por eso dice «vistos aquí primero».
            </Control>
          </Controles>

          <Sub>Panel de detalle (derecha)</Sub>
          <P>
            Mientras no selecciones una fila muestra{' '}
            <i>selecciona una peticion para ver el detalle</i>. Al pulsar una fila
            del panel izquierdo, se llena:
          </P>
          <Controles>
            <Control tipo="pestaña" nombre="Request">
              el método y la URL de la petición, y debajo el cuerpo enviado, si lo
              hubo.
            </Control>
            <Control tipo="pestaña" nombre="Response">
              el código de respuesta y el cuerpo que devolvió el servidor.
            </Control>
            <Control tipo="pestaña" nombre="Headers">
              las cabeceras, en dos bloques: las que se enviaron y las que
              contestó el servidor.
            </Control>
            <Control tipo="botón" nombre="enviar al repeater">
              lleva esa petición al Repeater para editarla y relanzarla a mano.
            </Control>
            <Control tipo="botón" nombre="enviar al intruder">
              lleva esa petición al Intruder para probar muchos valores sobre ella.
            </Control>
          </Controles>

          <Sub>El mensaje de cierre</Sub>
          <P>
            Al acabar aparece un aviso bajo la barra que dice <b>cómo</b> terminó, y
            los tres finales significan cosas distintas:
          </P>
          <Controles>
            <Control tipo="aviso" nombre="Spider completado">
              se recorrió el sitio entero dentro del alcance. No quedan páginas
              enlazadas sin visitar.
            </Control>
            <Control tipo="aviso" nombre="límite de N páginas alcanzado">
              se paró por el tope del desplegable. <b>Quedan páginas sin ver</b>:
              repítelo con un alcance mayor si necesitas cobertura completa.
            </Control>
            <Control tipo="aviso" nombre="Spider detenido">
              lo paraste tú. El recuento es de lo que dio tiempo a visitar.
            </Control>
          </Controles>
          <P>
            Cuando el mensaje distingue <i>URLs visitadas</i> de <i>páginas
            distintas</i>, la diferencia son redirecciones: varias direcciones
            llevaban al mismo sitio, así que se pidieron más URLs de las páginas
            que realmente hay.
          </P>
        </Seccion>

        <Seccion titulo="Repeater" estado="pendiente"><Pendiente nombre="Repeater" /></Seccion>
        <Seccion titulo="Intruder" estado="pendiente"><Pendiente nombre="Intruder" /></Seccion>
        <Seccion titulo="Utilidades" estado="pendiente"><Pendiente nombre="Utilidades" /></Seccion>
        <Seccion titulo="Vulnerabilidades" estado="pendiente"><Pendiente nombre="Vulnerabilidades" /></Seccion>
      </div>
    </div>
  )
}
