from fastapi import APIRouter, Depends
from models.schemas import RepeaterRequest
from services.proxy_service import forward_request
from services.session_service import session_manager
from services.guardia import usuario_actual

router = APIRouter()

@router.post("/send")
async def send_request(request: RepeaterRequest, espacio: str = Depends(usuario_actual)):
	"""Reenvia la peticion usando la sesion HTTP de QUIEN LLAMA.

	HUECO DE AUTORIZACION CERRADO (6-oct), y esta era la cuarta: el espacio salia del
	CUERPO (`request.session_token`) y el guardian del router solo valida los parametros
	de la RUTA. Aqui el riesgo era doble, porque `forward_request` usa ese espacio para
	elegir la sesion HTTP persistente —la que hereda las cookies del login auditado
	(RF-04)—, asi que con el nombre de otro en el cuerpo se podian reutilizar SUS
	cookies de sesion contra el objetivo. Ahora sale del token firmado.
	"""
	result = await forward_request(
		method=request.method,
		url=request.url,
		headers=request.headers,
		body=request.body,
		session_token=espacio,
		# El Repeater NO sigue las redirecciones, igual que el de Burp: lo que interesa es la
		# respuesta de ESTA peticion -el 302 con su Location y su Set-Cookie-, no la de la
		# ultima parada. Seguirlas en silencio hacia parecer que la herramienta mentia.
		seguir_redirecciones=False,
		# Peticion INDEPENDIENTE, no el cliente compartido. Este mandaba cookies que no estaban
		# en la peticion y se quedaba con las que devolvia el servidor, asi que dos envios
		# identicos daban resultados distintos (comprobado el 12-oct: un POST sin Cookie en las
		# cabeceras recibia igualmente el estado de la sesion del Spider). Un Repeater tiene que
		# ser reproducible: lo que se ve es lo que se manda.
		#
		# La sesion se SIGUE heredando, pero por las cabeceras: desde el 12-oct la Cookie real
		# viaja en ellas, visible y editable. RF-04 se cumple en su proposito -auditoria
		# autenticada- por un canal explicito en vez de uno oculto.
		cliente_compartido=False,
	)
	return result

@router.get("/history/{token}")
async def get_history(token: str):
	session = session_manager.get_session(token)
	return session.get("requests", [])[-100:]