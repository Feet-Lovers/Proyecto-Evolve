import { useState } from 'react'
import { Badge } from '@/components/ui'

// Manual de uso. Se rellena UNA SECCION POR PESTANA, y solo cuando esa pestana
// se ha pulido y verificado: documentar lo que creemos que hace una pantalla, en
// vez de lo que hemos comprobado que hace, produce un manual que miente.
// Estado a 12-oct-2026: Spider y Repeater verificados contra el codigo; las otras,
// pendientes.
//
// Criterio de redaccion: la prosa va acentuada, pero los nombres de los controles
// se citan LITERALES, tal y como aparecen en pantalla ('nueva auditoria', sin
// tilde), para que se puedan buscar con la vista.

function Seccion({ titulo, estado, activa, children }) {
  // Solo se pinta la seccion elegida en las pastillas: el manual entero seguido era una
  // tirada larguisima e imposible de leer.
  if (activa !== titulo) return null
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
function Control({ tipo, nombre, cuando, children }) {
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
        {cuando && (
          <span
            className="block mt-1 text-[10px]"
            style={{ color: 'var(--hs-text-dim)' }}
          >
            {'\u25B8 '}{cuando}
          </span>
        )}
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

const SECCIONES = [
  { id: 'Spider', pendiente: false },
  { id: 'Repeater', pendiente: false },
  { id: 'Intruder', pendiente: true },
  { id: 'Utilidades', pendiente: true },
  { id: 'Vulnerabilidades', pendiente: true },
]

export function ManualPage() {
  const [activa, setActiva] = useState('Spider')
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

      <div
        className="flex items-center gap-2 px-5 py-2 border-b"
        style={{ background: 'var(--hs-bg)', borderColor: 'var(--hs-border)' }}
      >
        {SECCIONES.map(s => (
          <button
            key={s.id}
            onClick={() => setActiva(s.id)}
            className="px-3 py-1 rounded border text-[10px] tracking-wide transition-all"
            style={{
              fontFamily: 'var(--font-mono)',
              background: activa === s.id ? 'var(--hs-accent-bg)' : 'transparent',
              borderColor: activa === s.id ? 'var(--hs-accent-border)' : 'var(--hs-border)',
              color: activa === s.id ? 'var(--hs-accent)' : (s.pendiente ? 'var(--hs-text-dim)' : 'var(--hs-text-muted)'),
            }}
            title={s.pendiente ? 'Sección aún no escrita' : 'Ver el manual de ' + s.id}
          >
            {s.id}{s.pendiente ? ' ·' : ''}
          </button>
        ))}
      </div>

      <div className="flex-1 min-h-0 overflow-auto px-5 py-4">
        <Seccion titulo="Spider" activa={activa}>
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
            <Control
              tipo="indicador"
              nombre="con sesión / sin cookies de sesión"
              cuando="no está desde el principio: aparece al fijar el objetivo, es decir al lanzar el primer rastreo"
            >
              dice si el rastreo lleva cookies, y cuáles por su nombre. Ojo al
              matiz: indica que <b>hay</b> cookies de sesión, no que la
              autenticación sea válida ni que siga viva.
            </Control>
            <Control
              tipo="botón"
              nombre="liberar sesion"
              cuando="solo si hay cookies: sin sesión, el botón no está"
            >
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
            <Control
              tipo="botón"
              nombre="Iniciar spider"
              cuando="apagado mientras no haya una URL escrita o un objetivo ya fijado"
            >
              arranca el rastreo. Mientras corre no desaparece: cambia su texto a{' '}
              <i>Ejecutando...</i> y deja de poder pulsarse.
            </Control>
            <Control
              tipo="botón"
              nombre="Detener"
              cuando="solo mientras el rastreo está en marcha, y aparece AL LADO de «Ejecutando...», no en su lugar"
            >
              para el rastreo. Puede entrar todavía una petición más: es la que ya
              estaba en vuelo cuando pulsaste.
            </Control>
            <Control
              tipo="aviso"
              nombre="objetivo fijado"
              cuando="solo cuando ya hay un objetivo fijado; antes del primer rastreo no está"
            >
              texto informativo, no se pulsa. Recuerda cómo cambiar de objetivo.
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
            <Control
              tipo="botón"
              nombre="liberar sesion"
              cuando="solo si hay cookies"
            >
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
              escribes. Si lo que coincide es un formulario, su página aparece
              también y <b>ya desplegada</b>, para que no pierdas de dónde sale.
            </Control>
            <Control tipo="desplegable" nombre="ALL">
              filtra por método HTTP: <i>ALL</i>, <i>GET</i>, <i>POST</i>,{' '}
              <i>PUT</i>, <i>DELETE</i> o <i>PATCH</i>. Las páginas se piden
              siempre con <i>GET</i> y los formularios suelen ser <i>POST</i>, así
              que filtrar por <i>POST</i> es la forma rápida de quedarte solo con
              los formularios: verás las páginas que los contienen, con el
              formulario ya a la vista.
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
            <Control
              tipo="desplegable"
              nombre="[N formularios · vistos aqui primero]"
              cuando="solo en las páginas que tienen formularios; y las filas de formulario no se ven hasta que lo despliegas"
            >
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
              el método y la URL de la petición, y debajo el cuerpo enviado.
              <span
                className="block mt-1 text-[10px]"
                style={{ color: 'var(--hs-text-dim)' }}
              >
                {'\u25B8 '}el apartado del cuerpo solo sale si la petición llevaba uno: en un GET no aparece
              </span>
            </Control>
            <Control tipo="pestaña" nombre="Response">
              el código de respuesta y el cuerpo que devolvió el servidor.
            </Control>
            <Control tipo="pestaña" nombre="Headers">
              las cabeceras, <b>las que de verdad salieron</b> —incluida la
              <i>Cookie</i> de sesión si el rastreo iba autenticado—, en dos bloques: las
              que se enviaron y las que
              contestó el servidor.
            </Control>
            <Control tipo="botón" nombre="enviar al repeater">
              lleva esa petición al Repeater para editarla y relanzarla a mano.
              <b> El Repeater trabaja con una petición cada vez</b>: si ya tiene una
              cargada, este botón pasa a poner <i>repeater en uso</i> y no deja pulsarlo.
              Para liberarlo, ve al Repeater y pulsa <i>limpiar</i>.
            </Control>
            <Control tipo="botón" nombre="enviar al intruder">
              lleva esa petición al Intruder para probar muchos valores sobre ella.
            </Control>
          </Controles>

          <Sub>El mensaje de cierre</Sub>
          <P>
            Mientras el rastreo corre no hay ningún mensaje. Al acabar aparece un
            aviso bajo la barra que dice <b>cómo</b> terminó, y los tres finales
            significan cosas distintas:
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

        <Seccion titulo="Repeater" activa={activa}>
          <P>
            Coge una petición, la edita y la vuelve a lanzar tantas veces como quieras.
            Es la herramienta para probar <b>una misma petición cambiando una cosa cada
            vez</b>: un parámetro, una cabecera, el método. Lo que se manda es
            exactamente lo que ves en pantalla.
          </P>
          <P>
            Trabaja con <b>una petición cada vez</b>. Mientras tenga una cargada, el
            Spider no deja enviar otra: su botón pasa a poner <i>repeater en uso</i>.
            Para liberarlo, pulsa <i>limpiar</i> aquí.
          </P>
          <P>
            <b>No sigue las redirecciones.</b> Si el servidor responde un 3xx, verás ese
            3xx con sus cabeceras, no la página de destino. Es deliberado: en una
            auditoría interesa la respuesta de <b>tu</b> petición, incluida cualquier
            <i>Set-Cookie</i>, y no la de la última parada.
          </P>
          <P>
            Un aviso sobre lo que llega del Spider: esas peticiones <b>no son capturas
            de tráfico real</b>, son plantillas leídas del HTML. El Spider encuentra un
            formulario, anota sus campos y rellena los vacíos con el nombre del propio
            campo. Nunca se han enviado, y su token lleva la fecha del rastreo. Por eso
            existe <i>preparar</i>.
          </P>

          <Sub>Barra de la petición</Sub>
          <Controles>
            <Control tipo="selector" nombre="método">
              GET, POST, PUT, DELETE, PATCH, HEAD y OPTIONS. Cambiarlo no toca el resto:
              puedes pasar un POST a GET para ver la página del formulario y volver.
            </Control>
            <Control tipo="campo" nombre="URL">
              dirección completa, con <i>https://</i>. Si está vacío, <i>enviar</i> y
              <i>preparar</i> se quedan apagados.
            </Control>
            <Control tipo="botón" nombre="preparar">
              pide la página del formulario y trae de ella lo que caduca: los campos
              ocultos (el token) y, si el servidor la cambia, la cookie. Sustituye en tu
              cuerpo <b>solo los campos que ya estaban</b>, por nombre. Debajo te dice qué
              ha actualizado. Es lo que hace un navegador antes de enviar un formulario, y
              es lo que convierte la plantilla del Spider en una petición que funciona.
            </Control>
            <Control tipo="botón" nombre="enviar" cuando="apagado mientras hay un envío en curso">
              lanza la petición. Si llega una respuesta de un envío anterior cuando ya has
              mandado otra, se descarta: el panel siempre enseña la última que pediste.
            </Control>
            <Control tipo="botón" nombre="limpiar">
              vacía la petición, la respuesta y la página preparada. Es lo que <b>libera
              el Repeater</b> para que el Spider vuelva a dejarte mandar peticiones.
            </Control>
          </Controles>

          <Sub>Avisos de la petición</Sub>
          <Controles>
            <Control
              tipo="aviso"
              nombre="viaja con una sesión heredada"
              cuando="solo si la petición lleva Cookie, Authorization o un token CSRF"
            >
              te recuerda que la respuesta depende de esa sesión y no solo de la URL y el
              método: la misma petición con y sin ella puede dar resultados distintos.
            </Control>
            <Control tipo="botón" nombre="quitar la sesión" cuando="dentro de ese aviso">
              borra <b>solo</b> esas cabeceras. El método, la URL, el cuerpo y las demás
              cabeceras no se tocan. Sirve para comparar la misma petición autenticada y
              anónima.
            </Control>
          </Controles>

          <Sub>Cabeceras y cuerpo</Sub>
          <Controles>
            <Control tipo="lista" nombre="headers">
              nombre y valor, uno por fila. <b>Se pueden repetir</b>: dos cabeceras con el
              mismo nombre viajan las dos. Lo que ves aquí es lo que sale, salvo
              <i>Host</i> y <i>Content-Length</i>, que los calcula el servidor porque
              falsearlos rompe la petición.
            </Control>
            <Control tipo="botón" nombre="+ añadir">añade una fila vacía de cabecera.</Control>
            <Control tipo="botón" nombre="✕" cuando="una por fila de cabecera">
              quita esa cabecera. No pregunta.
            </Control>
            <Control tipo="campo" nombre="body">
              el cuerpo tal cual se envía. Para un formulario va como
              <i>campo=valor&amp;campo=valor</i>. Si viene del Spider, los campos sin valor
              traen su propio nombre puesto: eso <b>no pasa ninguna validación</b>, hay que
              sustituirlo por datos reales.
            </Control>
          </Controles>

          <Sub>Panel de la respuesta</Sub>
          <Controles>
            <Control tipo="indicador" nombre="sin enviar todavía" cuando="antes del primer envío">
              no hay respuesta que enseñar. Si has pulsado <i>preparar</i>, la pestaña
              <i>Formulario</i> sí tiene contenido; las demás no, y es normal.
            </Control>
            <Control tipo="indicador" nombre="código de estado">
              el que devuelve el servidor. Si pone <i>sin respuesta</i>, la petición no
              llegó a obtener ninguna —red caída o tiempo agotado—: no existe el código 0,
              y por eso no se muestra como si fuera uno.
            </Control>
            <Control tipo="indicador" nombre="tiempo y tamaño" cuando="solo si hubo respuesta">
              milisegundos y kilobytes. Se ocultan cuando no hay respuesta, porque 0 ms y
              0,0 KB no son medidas sino su ausencia.
            </Control>
            <Control tipo="indicador" nombre="URL enviada">
              en su propia línea bajo la barra, para saber de qué petición es la respuesta
              que estás mirando.
            </Control>
            <Control
              tipo="aviso"
              nombre="redirección no seguida"
              cuando="si el estado es 3xx"
            >
              dice a dónde te manda la cabecera <i>Location</i>. Para ver esa página, pon
              esa dirección y envía otra vez.
            </Control>
          </Controles>

          <Sub>Pestañas de la respuesta</Sub>
          <Controles>
            <Control tipo="pestaña" nombre="Raw">el cuerpo tal cual llega.</Control>
            <Control tipo="pestaña" nombre="Pretty">
              igual, pero si el cuerpo es JSON lo formatea. Si no lo es, lo deja como está.
            </Control>
            <Control tipo="pestaña" nombre="Preview">
              dibuja la respuesta como una página. <b>No ejecuta JavaScript</b> —lo avisa
              encima—, así que una página que se construya sola puede verse incompleta. El
              contenido viene del sitio auditado, que es precisamente del que no te fías.
            </Control>
            <Control tipo="pestaña" nombre="Headers">las cabeceras de la respuesta.</Control>
            <Control tipo="pestaña" nombre="Formulario" cuando="solo tras pulsar preparar">
              la página que se trajo al preparar, con sus estilos. Se queda ahí, así que
              puedes enviar, mirar la respuesta y volver al formulario <b>sin reenviar
              nada</b>. Tampoco ejecuta JavaScript.
            </Control>
          </Controles>

          <Sub>Cómo probar un formulario</Sub>
          <P>
            1. Manda el POST desde el Spider. 2. Pulsa <i>preparar</i>: trae token y
            cookie frescos y te deja la página en la pestaña <i>Formulario</i>. 3. Mira ahí
            qué campos hay y rellénalos en <i>body</i> con datos reales. 4. <i>enviar</i>.
            5. Cambia una cosa y repite. Si el servidor responde un 3xx, el aviso te dice a
            dónde te manda.
          </P>
          <P>
            <b>Si la respuesta no es un 200 y te redirige, vuelve a pulsar</b> <i>preparar</i>.
            Además de refrescar el token, la página que trae viene con <b>los valores que
            acabas de enviar</b>, así que en la pestaña <i>Formulario</i> ves lo que llegó al
            servidor y los errores que haya marcado. Es la forma de ir corrigiendo campo a
            campo sin salir de aquí.
          </P>
        </Seccion>
        <Seccion titulo="Intruder" estado="pendiente" activa={activa}><Pendiente nombre="Intruder" /></Seccion>
        <Seccion titulo="Utilidades" estado="pendiente" activa={activa}><Pendiente nombre="Utilidades" /></Seccion>
        <Seccion titulo="Vulnerabilidades" estado="pendiente" activa={activa}><Pendiente nombre="Vulnerabilidades" /></Seccion>
      </div>
    </div>
  )
}
