# Ataque DTP VLAN Hopping — Negociación de Trunk

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 12 de Junio 2026

---

## 🎬 Video Demostrativo

https://youtu.be/TU_LINK_AQUI

---

## 1. Objetivo del Laboratorio

Demostrar cómo el protocolo DTP (Dynamic Trunking Protocol) puede ser explotado para negociar un enlace trunk con un switch Cisco desde un dispositivo no autorizado, obteniendo acceso a todas las VLANs de la red mediante VLAN Hopping, y aplicar la contramedida correspondiente.

---

## 2. Objetivo del Script

Enviar frames DTP al switch víctima para forzar la negociación de trunk, luego crear una subinterfaz en la VLAN objetivo (VLAN 20) para acceder a tráfico de una VLAN diferente a la asignada al atacante.

### 2.1 Parámetros Usados

| Parámetro  | Descripción                          | Valor por defecto      |
| ---------- | ------------------------------------ | ---------------------- |
| `interfaz` | Interfaz de red del atacante         | Requerido (ej: `eth0`) |
| `count`    | Número de frames DTP a enviar        | 15                     |
| `interval` | Intervalo entre frames (segundos)    | 1                      |

### 2.2 Requisitos

- Sistema operativo: **Kali Linux**
- Python 3.x
- Librería Scapy: `pip install scapy`
- Permisos de root: `sudo`
- Puerto `e0/3` de SW2 en modo `dynamic desirable`

---

## 3. Funcionamiento del Script

1. Obtiene la MAC de la interfaz atacante
2. Construye frames DTP (SNAP `0x2004`) con destino multicast `01:00:0c:cc:cc:cc`
3. Envía los frames DTP para iniciar negociación de trunk con SW2
4. El switch negocia y cambia el puerto a modo trunk
5. Crea una subinterfaz `eth0.20` con IP `10.13.33.99/24` (VLAN 20)
6. Verifica acceso a VLAN 20 mediante ping a `10.13.33.11`

```
Crear y guardar el script:
bash
nano /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py

Dar permisos de ejecución:
bash
chmod +x /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py

Pasos de ejecución:

Paso 1 — SW2: Ver estado del puerto antes del ataque
bash
show interfaces e0/3 switchport

Paso 2 — Kali: Verificar que NO hay acceso a VLAN 20
bash
ping 10.13.33.11 -c 4

Paso 3 — Kali: Ejecutar el ataque DTP
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py eth0

Paso 4 — SW2: Verificar que el puerto negoció trunk
bash
show interfaces e0/3 switchport
show interfaces e0/3 trunk

Paso 5 — Kali: Verificar acceso a VLAN 20
bash
ping 10.13.33.11 -c 4

Paso 6 — SW2: Aplicar contramedida
conf t
interface e0/3
switchport mode access
switchport access vlan 10
switchport nonegotiate
exit
end
write memory

Paso 7 — Kali: Limpiar subinterfaz creada
bash
sudo ip link delete eth0.20

Paso 8 — Kali: Ejecutar el ataque de nuevo
bash
sudo python3 /home/kali-linux/HenryVicenteQuezada_2025-1332_dtp_hopping.py eth0

Paso 9 — SW2: Verificar que el ataque fue bloqueado
bash
show interfaces e0/3 switchport
show interfaces e0/3 trunk

🐍 Script — HenryVicenteQuezada_2025-1332_dtp_hopping.py
python
#!/usr/bin/env python3
# =============================================================
# Nombre:     Henry Vicente Quezada
# Matricula:  2025-1332
# Ataque:     DTP VLAN Hopping - Negociacion de Trunk
# Fecha:      2026
# =============================================================
[PEGA AQUÍ EL SCRIPT COMPLETO]

🛡️ Contramedida aplicada
SW2(config)# interface e0/1
SW2(config-if)# switchport mode access
SW2(config-if)# switchport nonegotiate
exit
SW2(config)# interface e0/2
SW2(config-if)# switchport mode access
SW2(config-if)# switchport nonegotiate
exit
SW2(config)# interface e0/3
SW2(config-if)# switchport mode access
SW2(config-if)# switchport nonegotiate
exit
SW2(config)# end
SW2# write memory
! Verificación
SW2# show interfaces e0/3 switchport
SW2# show interfaces e0/3 trunk
SW2# show dtp interface e0/3
```

---

## 4. Documentación de la Red

### Topología

<img width="896" height="720" alt="image" src="https://github.com/user-attachments/assets/bc7c7d6c-6e68-4c77-9cb0-6050226058c2" />

### Tabla de Direccionamiento

| Dispositivo | Interfaz | VLAN | IP          | Máscara | Rol                      |
| ----------- | -------- | ---- | ----------- | ------- | ------------------------ |
| R1          | e0/0.10  | 10   | 10.13.32.1  | /24     | Gateway VLAN10 TI        |
| R1          | e0/0.20  | 20   | 10.13.33.1  | /24     | Gateway VLAN20 Gerencia  |
| R1          | e0/0.99  | 99   | 10.13.99.1  | /24     | Gateway Management       |
| SW1         | vlan 99  | 99   | 10.13.99.2  | /24     | Gestión Switch VTP Server|
| SW2         | vlan 99  | 99   | 10.13.99.3  | /24     | Gestión Switch VTP Client|
| VPC10       | eth0     | 10   | 10.13.32.11 | /24     | Cliente VLAN10           |
| VPC20       | eth0     | 20   | 10.13.33.11 | /24     | Cliente VLAN20           |
| Kali        | eth0     | 10   | 10.13.32.5  | /24     | **Atacante**             |

### VLANs

| VLAN | Nombre     | Descripción                    |
| ---- | ---------- | ------------------------------ |
| 10   | TI         | Red de usuarios TI             |
| 20   | Gerencia   | Red de Gerencia                |
| 99   | Management | Red de gestión de dispositivos |

### Interfaces SW2 (VTP Client)

| Puerto | Modo              | VLAN     | Conectado a    |
| ------ | ----------------- | -------- | -------------- |
| e0/0   | Trunk 802.1q      | 10,20,99 | SW1 e0/1       |
| e0/1   | Access            | 10       | VPC10          |
| e0/2   | Access            | 20       | VPC20          |
| e0/3   | dynamic desirable | 10       | **Kali Linux** |

---

## 5. Capturas de Pantalla

### Antes del ataque

![antes](PEGA_IMAGEN_AQUI)

📷 SW2# show interfaces e0/3 switchport — Mode: static access

### Script en ejecución

![script](PEGA_IMAGEN_AQUI)

📷 Kali ejecutando dtp_hopping.py — Frames DTP enviados

### Durante el ataque

![durante](PEGA_IMAGEN_AQUI)

📷 SW2# show interfaces e0/3 trunk — Operational Mode: trunk ✅

### Contramedida aplicada

![contramedida](PEGA_IMAGEN_AQUI)

📷 SW2# show interfaces e0/3 switchport — Negotiation of Trunking: Off ✅

---

Con `switchport nonegotiate` el switch deja de enviar y responder frames DTP. Ningún dispositivo externo puede forzar la negociación de trunk, eliminando el vector de VLAN Hopping.
