# Notas: Módulo 1 (Redes)

**Estado:** finalizado

---

## 1. Direccionamiento y subnetting

### Tabla de referencia

| Prefijo | Direcciones | Hosts útiles | Salto de bloque |
|---|---|---|---|
| /24 | 256 | 254 | 256 |
| /25 | 128 | 126 | 128 |
| /26 | 64 | 62 | 64 |
| /27 | 32 | 30 | 32 |
| /28 | 16 | 14 | 16 |
| /29 | 8 | 6 | 8 |
| /30 | 4 | 2 | 4 |

### Método
1. Bits de host = 32 − prefijo.
2. Direcciones totales = 2^(bits de host).
3. Hosts útiles = total − 2 (se descartan red y broadcast).
4. Los bloques avanzan según el tamaño; ubicás la red, el rango y el broadcast.

### Ejemplo resuelto: 10.0.5.0/26
- Red: 10.0.5.0
- Hosts: 10.0.5.1 a 10.0.5.62 (62 hosts)
- Broadcast: 10.0.5.63

---

## 2. Modelo TCP/IP y encapsulación

| Capa | Qué hace | Ejemplos | Unidad de datos |
|---|---|---|---|
| Aplicación | Lo que usa el usuario | HTTP, DNS, SSH | Datos |
| Transporte | Conexión entre procesos (puertos) | TCP, UDP | Segmento / Datagrama |
| Internet | Direccionamiento y ruteo | IP, ICMP | Paquete |
| Acceso a red | Entrega en el medio local | Ethernet, Wi-Fi, ARP | Trama |

**Orden de encapsulación (de arriba hacia abajo):** Datos → Segmento → Paquete → Trama.

**Lo que vi en Wireshark (un dato por capa):**
- Frame: frame 12
- Ethernet (MAC origen): 08:00:27:e2:1e:c2
- IP (origen): 10.0.2.15
- TCP (puerto origen): 57338

---

## 3. TCP vs UDP

| | TCP | UDP |
|---|---|---|
| Conexión | Sí (handshake) | No |
| Fiabilidad | Confirma y retransmite | No garantiza |
| Usos | Web, SSH, correo, SMB | DNS, DHCP, streaming, VoIP |

**¿Por qué DNS usa UDP y cuándo pasa a TCP?**
Usa UDP porque consulta y respuesta son cortas y el handshake sería un costo innecesario. Pasa a TCP con respuestas grandes, transferencias de zona o cuando UDP falla.

---

## 4. Three-way handshake

```
Cliente --- SYN -------------> Servidor
Cliente <-- SYN, ACK --------- Servidor
Cliente --- ACK -------------> Servidor
```

### Flags
| Flag | Significado |
|---|---|
| SYN | Inicia la conexión |
| ACK | Confirma recepción |
| FIN | Cierre ordenado |
| RST | Corte abrupto o puerto cerrado |
| PSH | Enviar datos ya |

### Mi captura (example.com, puerto 80)
- IP origen (mi equipo): 10.0.2.15
- IP destino: 172.66.147.243
- Puerto destino: 80
- Paquetes del handshake (números): 2

### HTTP vs HTTPS
Entre HTTP y HTTPS pude ver que el handshake se ve igual, pero el contenido no es legible, ya que esta cifrado. El contenido cifrado no se puede inspeccionar sin descifrado.

## Notas
Los datos se encapsulan de arriba hacia abajo. 
Cuando un puerto esta cerrado, la flag que responde a un SYN es RST.
Tambien puedo usar el filtro tcp.flags.syn == 1 && tcp.flags.ack == 0 para ver solo los SYN sin ACK
EN EL CASO DE APLICAR EL FILTRO tcp.flags.syn == 1 && tcp.flags.ack == 0 y se ven cientos o miles de SYN desde una misma ip hacia muchos puertos/ip, podria estar tratandose de un escaneo de puertos, por lo que merece ser investigado
