# Evidencia · El cortafuegos de la caja cubre IPv6 (comprobado antes de tocar el DNS)

**Fecha:** 2026-10-08, 07:38:59 UTC · **Entorno:** caja `91.98.143.219`, **solo lectura**
· **Requisito:** RNF-07, apartado 7 · **Quién:** josemax ejecuta, Claude arma

**Por qué se comprueba esto, y por qué ANTES:** el arreglo del 404 por IPv6 pasa por apuntar el registro
`AAAA` del dominio a la caja. El endurecimiento del 5-oct cerró el `:8000` (API) y el `:3000` (frontend),
pero **si esas reglas se hubieran puesto solo en `iptables` y no en `ip6tables`**, apuntar el dominio a la
IPv6 habría expuesto por esa vía justo lo que se cerró — y encima lo habría hecho fácil de encontrar.
Comprobarlo después del cambio habría sido comprobarlo tarde.

---

## Salida literal

```
-- 1) ufw, si esta --
   Status: active
   Default: deny (incoming), allow (outgoing), deny (routed)
   8080                       DENY IN     Anywhere
   22/tcp                     ALLOW IN    Anywhere
   80/tcp                     ALLOW IN    Anywhere
   8080 (v6)                  DENY IN     Anywhere (v6)
   22/tcp (v6)                ALLOW IN    Anywhere (v6)
   80/tcp (v6)                ALLOW IN    Anywhere (v6)
   IPV6 en /etc/default/ufw: IPV6=yes

-- 2) Reglas IPv4 vs IPv6 --
   iptables  filter INPUT: 9 reglas      politica: -P INPUT DROP
   ip6tables filter INPUT: 7 reglas      politica: -P INPUT DROP

-- 3) Que escucha en IPv6 --
   LISTEN  [::]:80   docker-proxy
   LISTEN  [::]:22   sshd

-- 4) Puertos cerrados por el endurecimiento, probados por IPv6 --
   IPv6 de la caja: 2a01:4f8:1c1e:7714::1
   puerto 8000  -> 000 (cerrado/sin respuesta)
   puerto 3000  -> 000 (cerrado/sin respuesta)
   puerto 8080  -> 000 (cerrado/sin respuesta)
   puerto 80    -> 200 RESPONDE
```

## Veredicto

**El cortafuegos cubre las dos familias.** `ufw` tiene `IPV6=yes` y duplica cada regla en v6; `ip6tables`
tiene la misma política de rechazo por defecto (`INPUT DROP`) que `iptables`; por IPv6 solo escuchan el
`:80` y el `:22`; y los tres puertos que el endurecimiento cerró **siguen cerrados también por IPv6**.

El `:80` respondiendo `200` por `2a01:4f8:1c1e:7714::1` prueba además que, en cuanto el `AAAA` apunte ahí,
**el panel se servirá por IPv6 sin tocar nada de la caja**.

→ **Autoriza el arreglo del DNS**: corregir el `AAAA` a `2a01:4f8:1c1e:7714::1`, en vez de retirarlo.

## Lo que esta evidencia NO prueba

Las sondas del punto 4 se lanzan **desde la propia caja**. Un puerto que responde aquí no demuestra por sí
solo que sea alcanzable desde internet (podría haber filtrado aguas arriba); lo que sí es concluyente es el
sentido contrario: **un puerto que no responde ni en local está cerrado**. Por eso el dato fuerte son los
tres `000`, y el `200` del `:80` se apoya además en la regla `80/tcp (v6) ALLOW IN` de `ufw`.

**Diferencia de conteo sin explicar, anotada en vez de redondeada:** `iptables` tiene 9 reglas en INPUT y
`ip6tables` 7. No se ha averiguado cuáles son las dos de diferencia. No cambia el veredicto —lo que importa
se verificó por comportamiento, no por conteo— pero queda dicho que no se miró.
