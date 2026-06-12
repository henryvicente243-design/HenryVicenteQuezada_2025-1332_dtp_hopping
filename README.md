 
# Ataque DTP VLAN Hopping: Convierta una interfaz de acceso en una interfaz troncal

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 12 de Junio 2026

---

## 🎬 Video Demostrativo

[Enlace al video](https://youtu.be/TU_LINK_AQUI)

---

## 1. Objetivo del Laboratorio

Demostrar cómo el protocolo DTP (Dynamic Trunking Protocol) puede ser explotado para negociar un enlace trunk con un switch Cisco desde un dispositivo no autorizado conectado a un puerto en modo `dynamic auto`/`dynamic desirable`, obteniendo acceso a tráfico etiquetado 802.1Q de VLANs distintas a la asignada (VLAN Hopping), y documentar la contramedida correspondiente (`switchport nonegotiate`).

---

## 2. Objetivo del Script

Enviar frames DTP "Desirable, 802.1Q" hacia el switch víctima para forzar la negociación de un enlace trunk en el puerto del atacante, y opcionalmente realizar double tagging para alcanzar tráfico de una VLAN distinta a la propia.

### 2.1 Parámetros Usados

| Parámetro         | Descripción                                  | Valor por defecto |
| ----------------- | --------------------------------------------- | ------------------ |
| `-i`, `--iface`   | Interfaz de red del atacante                   | `eth0`              |
| `-n`, `--count`   | Número de frames DTP a enviar                  | 5                   |
| `-t`, `--intervalo` | Intervalo entre frames DTP (segundos)        | 1.0                 |
| `--dst-ip`        | IP destino para la fase de double tagging      | `10.11.85.10`       |
| `--solo-dtp`      | Ejecuta solo la fase de negociación DTP        | —                   |
| `--solo-sniff`    | Ejecuta solo la fase de captura de tráfico     | —                   |
| `--sniff-timeout` | Segundos de captura en la fase de sniff        | 15                  |

### 2.2 Requisitos

- Sistema operativo: **Kali Linux**
- Python 3.x
- Librería Scapy: `pip install scapy`
- Permisos de root: `sudo`
- Puerto del switch conectado al atacante en modo `dynamic auto` o `dynamic desirable` (con `Negotiation of Trunking: On`)

---

## 3. Funcionamiento del Script

1. Verifica privilegios root y disponibilidad de Scapy.
2. Obtiene la MAC de la interfaz del atacante.
3. Construye un frame Ethernet 802.3 + LLC + SNAP con TLVs DTP (`Domain`, `Status=Desirable`, `DTP Type=802.1Q`, `Neighbor=MAC`).
4. Envía N frames DTP al multicast `01:00:0c:cc:cc:cc` para forzar la negociación de trunk.
5. (Opcional) Envía frames con doble etiqueta 802.1Q (`Dot1Q` exterior = VLAN nativa, `Dot1Q` interior = VLAN objetivo) hacia una IP destino.
6. (Opcional) Captura tráfico etiquetado (`Dot1Q`) en la interfaz para verificar acceso a otras VLANs.
7. Limpia subinterfaces creadas durante la prueba.

---

## 4. Pasos de Ejecución

### Preparación

```bash
nano /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py
chmod +x /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py
```

### Paso 1 — SW1: Ver estado del puerto antes del ataque
```bash
show interfaces e0/3 switchport
```
Esperado: `Administrative Mode: dynamic auto`, `Negotiation of Trunking: On`, `Operational Mode: static access`.

### Paso 2 — Kali: Captura inicial (sin trunk)
```bash
sudo tcpdump -i eth0 -n vlan -c 5
```
No debe capturar tráfico etiquetado.

### Paso 3 — Kali: Ejecutar el ataque DTP
```bash
sudo python3 HenryVicenteQuezada_2025-1332_dtp_hopping.py -i eth0 --solo-dtp -n 10 -t 0.5
```

### Paso 4 — SW1: Verificar que el puerto negoció trunk
```bash
show interfaces e0/3 switchport
show interfaces e0/3 trunk
```
Esperado: `Operational Mode: trunk`, `Operational Trunking Encapsulation: dot1q`.

### Paso 5 — Kali: Verificar acceso a tráfico de otras VLANs
```bash
sudo tcpdump -i eth0 -n vlan -c 10
```
Esperado: frames con `vlan 10`, `vlan 20`, `vlan 99` visibles — VLAN Hopping exitoso.

### Paso 6 — SW1: Aplicar contramedida
```bash
conf t
interface e0/3
 switchport mode access
 switchport access vlan 10
 switchport nonegotiate
exit
interface e0/2
 switchport mode access
 switchport nonegotiate
exit
interface e0/1
 switchport mode access
 switchport nonegotiate
exit
end
write memory
```

### Paso 7 — Kali: Limpiar subinterfaces creadas
```bash
sudo ip link delete eth0.10 2>/dev/null
sudo ip link delete eth0.20 2>/dev/null
```

### Paso 8 — Kali: Ejecutar el ataque de nuevo
```bash
sudo python3 HenryVicenteQuezada_2025-1332_dtp_hopping.py -i eth0 --solo-dtp -n 10
```

### Paso 9 — SW1: Verificar que el ataque fue bloqueado
```bash
show interfaces e0/3 switchport
show interfaces e0/3 trunk
show dtp interface e0/3
```
Esperado: `Negotiation of Trunking: Off`, `Operational Mode: static access` — sin trunk, sin hopping posible.

---

## 5. Documentación de la Red

### Topología

<img width="896" height="720" alt="topologia" src="URL_DE_TU_IMAGEN_AQUI" />

### Tabla de Direccionamiento

| Dispositivo | Interfaz | VLAN | IP          | Máscara | Rol                       |
| ----------- | -------- | ---- | ----------- | ------- | ------------------------- |
| R1          | e0/0.10  | 10   | 10.13.32.1  | /24     | Gateway VLAN10 TI         |
| R1          | e0/0.20  | 20   | 10.13.33.1  | /24     | Gateway VLAN20 Gerencia   |
| R1          | e0/0.99  | 99   | 10.13.99.1  | /24     | Gateway Management        |
| SW1         | vlan 99  | 99   | 10.13.99.2  | /24     | VTP Server                |
| SW2         | vlan 99  | 99   | 10.13.99.3  | /24     | VTP Client                |
| VPC10       | eth0     | 10   | 10.13.32.21 | /24     | Cliente VLAN10            |
| VPC20       | eth0     | 20   | 10.13.33.21 | /24     | Cliente VLAN20            |
| Kali        | eth0     | 10   | 10.13.32.5  | /24     | **Atacante**               |

### VLANs

| VLAN | Nombre     | Descripción                     |
| ---- | ---------- | -------------------------------- |
| 10   | TI         | Red de usuarios TI               |
| 20   | Gerencia   | Red de Gerencia                  |
| 99   | Management | Red de gestión de dispositivos   |

### Interfaces SW1

| Puerto | Modo               | VLAN     | Conectado a    |
| ------ | ------------------ | -------- | -------------- |
| e0/0   | Trunk 802.1q       | 10,20,99 | R1 e0/0        |
| e0/1   | Access             | 10       | VPC10          |
| e0/2   | Access             | 20       | VPC20          |
| e0/3   | dynamic auto       | 10       | **Kali Linux** |

---

## 6. Capturas de Pantalla

| Etapa | Captura |
| ----- | ------- |
| Antes del ataque — `show interfaces e0/3 switchport` (static access) | ![antes](URL_IMAGEN) |
| Script en ejecución — frames DTP enviados | ![script](URL_IMAGEN) |
| Durante el ataque — `show interfaces e0/3 trunk` (Operational Mode: trunk) | ![durante](URL_IMAGEN) |
| Captura tcpdump con tráfico VLAN 10/20/99 | ![tcpdump](URL_IMAGEN) |
| Contramedida aplicada — `Negotiation of Trunking: Off` | ![contramedida](URL_IMAGEN) |

---

## 7. Contramedida

```bash
SW1(config)# interface e0/1
SW1(config-if)# switchport mode access
SW1(config-if)# switchport nonegotiate
exit

SW1(config)# interface e0/2
SW1(config-if)# switchport mode access
SW1(config-if)# switchport nonegotiate
exit

SW1(config)# interface e0/3
SW1(config-if)# switchport mode access
SW1(config-if)# switchport access vlan 10
SW1(config-if)# switchport nonegotiate
exit

SW1(config)# end
SW1# write memory

! Verificación
SW1# show interfaces e0/3 switchport
SW1# show interfaces e0/3 trunk
SW1# show dtp interface e0/3
```

**Explicación:** `switchport nonegotiate` deshabilita el envío y respuesta de tramas DTP en el puerto. Aunque el modo administrativo siga siendo `access`, el switch ya no participa en negociaciones DTP, por lo que ningún dispositivo externo puede forzar la conversión del puerto a trunk, eliminando el vector de VLAN Hopping vía DTP.

---

## 8. Estructura del Repositorio

```
.
├── README.md
├── HenryVicenteQuezada_2025-1332_dtp_hopping.py
└── capturas/
    ├── antes.png
    ├── ejecucion_script.png
    ├── durante_trunk.png
    ├── tcpdump_vlans.png
    └── contramedida.png
```
