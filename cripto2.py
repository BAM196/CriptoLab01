#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import struct
import time
import os
import random

def calcular_checksum_icmp(data):
    """
    Calcula el checksum ICMP para los datos proporcionados
    """
    if len(data) % 2:
        data += b'\x00'
    
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i+1]
        checksum += word
        checksum = (checksum & 0xffff) + (checksum >> 16)
    
    return ~checksum & 0xffff

def generar_payload_icmp(caracter, seq_num):
    """
    Genera un payload de 48 bytes que parece un ping normal pero contiene el carácter
    """
    # Convertir el carácter a byte
    caracter_byte = bytes([ord(caracter)])
    
    # Timestamp actual (parte del disfraz)
    timestamp = int(time.time() * 1000)
    
    # Crear un payload que se vea como un ping normal pero con nuestro carácter
    # Estructura: [CARACTER][TIMESTAMP][SECUENCIA][DATOS_ALEATORIOS]
    timestamp_bytes = struct.pack('!Q', timestamp)  # 8 bytes
    secuencia_bytes = struct.pack('!I', seq_num)    # 4 bytes
    
    # Datos aleatorios para completar los 48 bytes (pero consistentes)
    datos_aleatorios = b''
    random.seed(42)  # Semilla fija para consistencia pero aparente aleatoriedad
    for i in range(35):  # 48 - 1 - 8 - 4 = 35 bytes
        datos_aleatorios += bytes([random.randint(32, 126)])
    
    # Ensamblar el payload completo
    payload = caracter_byte + timestamp_bytes + secuencia_bytes + datos_aleatorios
    
    return payload

def enviar_ping_disfrazado(destino, caracter, id_paquete, seq_num):
    """
    Envía un paquete ICMP Echo Request disfrazado como ping normal
    """
    try:
        # Crear socket raw para enviar paquetes ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        
        # Generar payload que parece un ping normal
        payload = generar_payload_icmp(caracter, seq_num)
        
        # Verificar tamaño del payload
        if len(payload) != 48:
            raise ValueError(f"Tamaño de payload incorrecto: {len(payload)} bytes")
        
        # Construir el encabezado ICMP
        tipo = 8  # ICMP Echo Request
        codigo = 0
        checksum = 0
        identificador = id_paquete & 0xFFFF
        secuencia = seq_num & 0xFFFF
        
        # Empaquetar encabezado sin checksum
        header_sin_checksum = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, secuencia)
        
        # Calcular checksum
        checksum = calcular_checksum_icmp(header_sin_checksum + payload)
        
        # Reconstruir encabezado con checksum correcto
        header = struct.pack('!BBHHH', tipo, codigo, checksum, identificador, secuencia)
        
        # Enviar paquete
        sock.sendto(header + payload, (destino, 0))
        sock.close()
        
        # Mostrar información del envío
        hex_payload = ' '.join(f'{b:02x}' for b in payload[:16]) + '...'
        char_hex = f'{ord(caracter):02x}'
        print(f"📤 Seq {seq_num:3d}: '{caracter}' (0x{char_hex}) -> {destino}")
        print(f"   Payload: {hex_payload}")
        print(f"   ID: {identificador}, Checksum: {checksum:04x}")
        
        return True
        
    except socket.error as e:
        print(f"❌ Error de socket: {e}")
        return False
    except Exception as e:
        print(f"❌ Error enviando '{caracter}': {e}")
        return False

def main():
    # Verificar que se ejecute con sudo
    if os.geteuid() != 0:
        print("❌ Este programa debe ejecutarse con privilegios de superusuario")
        print("💡 Use: sudo python3 pingv4.py \"texto_cifrado\"")
        sys.exit(1)
    
    # Verificar argumentos
    if len(sys.argv) != 2:
        print("📋 Uso: sudo python3 pingv4.py \"texto_cifrado\"")
        print("📝 Ejemplo: sudo python3 pingv4.py \"larycxpajorj h bnpdarmjm nw anmnb\"")
        sys.exit(1)
    
    texto_cifrado = sys.argv[1]
    
    # Configuración
    destino = "8.8.8.8"  # Google DNS
    id_paquete = os.getpid() & 0xFFFF  # ID coherente basado en PID
    
    print("🚀 Iniciando envío de texto cifrado via ICMP (disfrazado como ping)")
    print("=" * 70)
    print(f"📨 Destino: {destino}")
    print(f"🔢 ID de paquete base: {id_paquete}")
    print(f"📄 Texto a enviar: \"{texto_cifrado}\"")
    print(f"📦 Total de paquetes: {len(texto_cifrado)}")
    print(f"📏 Tamaño payload: 48 bytes (disfrazado como ping normal)")
    print("=" * 70)
    
    # Enviar cada carácter en un paquete ICMP separado
    paquetes_enviados = 0
    paquetes_fallidos = 0
    
    for i, caracter in enumerate(texto_cifrado):
        seq_num = i + 1
        
        # ID coherente que va en aumento (simula diferentes hosts)
        current_id = id_paquete + (i % 100)  # Variación coherente del ID
        
        success = enviar_ping_disfrazado(destino, caracter, current_id, seq_num)
        
        if success:
            paquetes_enviados += 1
        else:
            paquetes_fallidos += 1
        
        # Pausa variable para parecer tráfico real
        time.sleep(random.uniform(0.1, 0.5))
    
    print("=" * 70)
    print("📊 Resumen del envío:")
    print(f"   ✅ Paquetes enviados exitosamente: {paquetes_enviados}")
    print(f"   ❌ Paquetes fallidos: {paquetes_fallidos}")
    print(f"   📨 Total intentados: {len(texto_cifrado)}")
    print()
    print("🔍 Para visualizar en Wireshark:")
    print("   Filtro: icmp.type == 8")
    print("   Los caracteres están en el primer byte del campo Data")
    print("   Estructura payload: [CARACTER][TIMESTAMP][SECUENCIA][DATOS_ALEATORIOS]")
    print()
    print("💡 Los paquetes parecen pings normales pero contienen el mensaje cifrado")

if __name__ == "__main__":
    main()