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

---

## 5. DNS (puerto 53)

### 5.1 Qué es y cómo funciona
DNS traduce nombres de dominio a direcciones IP. Antes de conectarse a un dominio, el equipo pregunta a un servidor DNS (en mi red, el router).

```
Cliente --- Query: ¿IP de bravocyberriskconsulting.com? ---> Servidor DNS
Cliente <-- Response: bravocyberriskconsulting.com = X.X.X.X -- Servidor DNS
```

- Usa **UDP/53** por defecto, porque consulta y respuesta son cortas.
- Pasa a **TCP/53** con respuestas grandes, transferencias de zona o si falla UDP.
- Desde seguridad: casi todo (navegación, malware, C2, exfiltración) empieza con una consulta DNS.

### 5.2 Estructura de un mensaje DNS en Wireshark
| Sección | Qué contiene |
|---|---|
| Flags | Tipo de mensaje (consulta/respuesta), recursión y código de respuesta (rcode) |
| Queries | **Lo que preguntó el cliente**: Name (dominio), Type (A, MX, TXT...), Class (casi siempre IN) |
| Answers | **Lo que respondió el servidor**, con su TTL |

### 5.3 Tipos de registro
| Tipo | Qué devuelve | Relevancia en seguridad |
|---|---|---|
| A | IPv4 de un dominio | El más común |
| AAAA | IPv6 de un dominio | Igual que A, en IPv6 |
| CNAME | Alias hacia otro nombre | Cadenas largas pueden ocultar infraestructura |
| MX | Servidor de correo | Análisis de phishing y dominios de correo |
| TXT | Texto libre | Muy usado en tunneling y C2 |
| NS | Servidores de nombres del dominio | Análisis de infraestructura |
| PTR | Nombre a partir de una IP (consulta inversa) | Reconocimiento |

### 5.4 Códigos de respuesta (rcode)
| rcode | Nombre | Significado |
|---|---|---|
| 0 | NOERROR | Consulta resuelta correctamente |
| 2 | SERVFAIL | El servidor no pudo resolver |
| 3 | NXDOMAIN | El dominio no existe |

**Cómo leer el campo Flags (valor hexadecimal):**
- `0x8180` = respuesta normal, rcode 0 (NOERROR).
- `0x8183` = respuesta con rcode 3 (NXDOMAIN).
- El primer dígito `8` indica que es una respuesta, y el último dígito es el rcode.

### 5.5 Filtros de Wireshark para DNS
| Filtro | Para qué sirve |
|---|---|
| `dns` | Todo el tráfico DNS |
| `dns.flags.response == 0` | Solo consultas |
| `dns.flags.response == 1` | Solo respuestas |
| `dns.flags.rcode == 3` | Solo NXDOMAIN |
| `dns.qry.name == "example.com"` | Consultas a un dominio exacto |
| `dns.qry.name contains "google"` | Consultas que incluyen una palabra |
| `dns.qry.type == 15` | Consultas MX |
| `dns.qry.type == 16` | Consultas TXT |
| `dns.qry.type == 2` | Consultas NS |
| `tcp.port == 53` | DNS sobre TCP |

### 5.6 Laboratorio

**Entorno:** captura realizada en Windows, interfaz WiFi Tráfico generado en la misma máquina donde capturé.

**Comandos usados:**
```
ipconfig /flushdns
nslookup bravocyberrisk.com
nslookup bravocyberriskconsulting.com
nslookup dominioquenoexiste12345xyz.com
nslookup -type=MX gmail.com
nslookup -type=TXT google.com
nslookup -type=NS example.com
```

#### Ejercicio 1: consulta DNS
| Dato | Valor |
|---|---|
| IP de origen (mi equipo) | 192.168.1.2 |
| Servidor DNS (router) | 192.168.1.1 |
| Tipo de registro | A (IPv4) |
| IP devuelta | 31.220.110.109 |

#### Ejercicio 2: detalle de una respuesta

**Primera captura (respuesta con error):**
| Dato | Valor |
|---|---|
| Flags | 0x8183 (rcode 3, NXDOMAIN) |
| Answers RRs | 0 |
| TTL | 65 segundos |

Esta respuesta era la del `nslookup` a la IP del router (consulta PTR), y no la de `example.com`. El TTL de 65 s probablemente corresponde al tiempo de caché del error (*negative caching*), que se toma del registro SOA de la zona.

**Repetición con la respuesta de `bravocyberriskconsulting.com`** (filtro `dns.qry.name == "bravocyberriskconsulting.com"`):
| Dato | Valor |
|---|---|
| Flags | 0x8180 |
| rcode | NOERROR |
| Answers RRs | 1 |
| IP devuelta | 31.220.110.109 |
| TTL | 1101 |

#### Ejercicio 3: NXDOMAIN provocado
- Comando: `nslookup dominioquenoexiste12345xyz.com`
- Resultado: rcode **No such name (NXDOMAIN)**, confirmado con el filtro `dns.flags.rcode == 3`.
- Esto es lo que se vería en masa con malware que usa DGA.

### 5.7 Lo que me confundió
Al abrir la captura vi un servidor DNS con la IP **"1.1.168.192"**. No era una IP: era el nombre `1.1.168.192.in-addr.arpa`, una **consulta PTR (inversa)** por la IP 192.168.1.1 escrita al revés. `nslookup` la hace automáticamente al arrancar para averiguar el nombre del servidor DNS que usa. Como el router no tiene nombre inverso registrado, la respuesta fue NXDOMAIN (`0x8183`) con 0 Answers.

**Qué aprendí:** antes de analizar una respuesta hay que confirmar a qué consulta responde (mirar la sección Queries). Si no, se interpretan mal los resultados.

### 5.8 Señales sospechosas en DNS
| Señal | Posible causa |
|---|---|
| Dominios largos o de aspecto aleatorio |Posible DGA o tunneling |
| Muchos NXDOMAIN seguidos desde un mismo host |Posible DGA |
| Muchas consultas TXT o subdominios larguísimos |Posible Tunneling DNS (exfiltración) |
| Consultas a intervalos regulares al mismo dominio | Beaconing |
| Consultas a dominios recién registrados | Posible Infraestructura de malware o phishing |
| Mucho DNS por TCP o respuestas enormes | Posible Tunneling |
| TTL muy bajos (60 s o menos) en dominios sospechosos | Fast-flux (IPs que cambian rápido) |

**Aclaracion MUY importante:** un NXDOMAIN aislado es normal (errores de tipeo, configuraciones viejas). Lo sospechoso es el **patrón**: muchos seguidos, nombres con aspecto aleatorio, desde un mismo equipo y en poco tiempo.

### 5.9 Conceptos clave

**DGA (Domain Generation Algorithm):** el malware genera cientos de dominios aleatorios para encontrar su servidor de control. Casi todos no existen, así que genera ráfagas de NXDOMAIN.

**Tunneling DNS y por qué se usan registros TXT:**
1. Un TXT admite texto libre (hasta unos 255 bytes por cadena), mucho más que una IP.
2. El DNS casi siempre está permitido hacia afuera, aunque la red bloquee casi todo lo demás.
3. El atacante controla el servidor DNS de su dominio: el malware envía datos codificados en el nombre (`dGVzdG8.malo.com`) y el servidor responde comandos dentro de un TXT.

Cómo se ve en Wireshark: muchas consultas TXT a un mismo dominio, subdominios largos y aleatorios, y volumen alto de DNS desde un solo host.

**TTL (Time To Live):** tiempo durante el cual una respuesta puede guardarse en caché.

### 5.10 Ruido vs. sospechoso
Al navegar, cada web dispara consultas a decenas de dominios secundarios (CDNs, trackers, publicidad). Eso es ruido normal. APRENDER A DISTINGUIRLO
- Dominios que vi al navegar unos minutos: ns1.dns-parkingcom; fonts.googleapis.com; ohttp.ads.brave.com

### 5.11 Checkpoint DNS
1. **¿Qué indica un NXDOMAIN y por qué muchos seguidos son sospechosos?** El dominio no existe. Muchos seguidos desde un mismo equipo pueden indicar posible DGA.
2. **Filtro para ver NXDOMAIN:** `dns.flags.rcode == 3`
3. **¿Qué es el TTL?** Tiempo que una respuesta DNS puede permanecer en caché.
