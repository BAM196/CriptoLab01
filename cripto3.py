#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
from scapy.all import rdpcap, ICMP, Raw
import os

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

def descifrar_cesar(texto_cifrado, corrimiento):
    """
    Descifra un texto usando el algoritmo de César con un corrimiento dado
    """
    texto_descifrado = ""
    corrimiento = corrimiento % 26
    
    for caracter in texto_cifrado:
        if caracter.isalpha():
            # Determinar si es mayúscula o minúscula
            if caracter.isupper():
                base = ord('A')
            else:
                base = ord('a')
            
            # Aplicar descifrado César
            codigo = ord(caracter) - base
            codigo_descifrado = (codigo - corrimiento) % 26
            if codigo_descifrado < 0:
                codigo_descifrado += 26
            caracter_descifrado = chr(codigo_descifrado + base)
            texto_descifrado += caracter_descifrado
        else:
            # Mantener caracteres no alfabéticos sin cambios
            texto_descifrado += caracter
    
    return texto_descifrado

def extraer_caracteres_icmp(archivo_pcap):
    """
    Extrae los caracteres del mensaje cifrado de los paquetes ICMP Echo Request
    """
    try:
        print(f"{Colors.CYAN}📖 Leyendo archivo: {archivo_pcap}{Colors.END}")
        
        # Leer todos los paquetes del archivo pcap
        packets = rdpcap(archivo_pcap)
        
        caracteres = []
        paquetes_icmp = 0
        secuencias = {}
        
        for i, pkt in enumerate(packets):
            # Verificar si es un paquete ICMP Echo Request (tipo 8)
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                paquetes_icmp += 1
                
                # Verificar si tiene datos (capa Raw)
                if pkt.haslayer(Raw):
                    raw_data = bytes(pkt[Raw])
                    
                    # Verificar que tenga al menos 48 bytes de datos
                    if len(raw_data) >= 48:
                        # Extraer el primer byte que contiene el carácter
                        primer_byte = raw_data[0]
                        caracter = chr(primer_byte)
                        
                        # Obtener número de secuencia para ordenar
                        seq_num = pkt[ICMP].seq
                        secuencias[seq_num] = caracter
                        
                        print(f"{Colors.BLUE}📦 Paquete {i+1:3d} - Seq {seq_num:3d}: '{caracter}' (0x{primer_byte:02x}){Colors.END}")
        
        if not secuencias:
            print(f"{Colors.RED}❌ No se encontraron paquetes ICMP Echo Request con datos de 48+ bytes{Colors.END}")
            return None
        
        # Ordenar los caracteres por número de secuencia
        secuencias_ordenadas = sorted(secuencias.items())
        caracteres = [char for seq, char in secuencias_ordenadas]
        
        texto_cifrado = ''.join(caracteres)
        
        print(f"\n{Colors.GREEN}✅ Texto cifrado extraído: {Colors.BOLD}\"{texto_cifrado}\"{Colors.END}")
        print(f"{Colors.CYAN}📊 Total de paquetes ICMP: {paquetes_icmp}{Colors.END}")
        print(f"{Colors.CYAN}📊 Caracteres extraídos: {len(caracteres)}{Colors.END}")
        
        return texto_cifrado
        
    except Exception as e:
        print(f"{Colors.RED}❌ Error al leer el archivo pcap: {e}{Colors.END}")
        return None

def calcular_probabilidad_espanol(texto):
    """
    Calcula la probabilidad de que el texto esté en español
    """
    # Palabras comunes en español (ordenadas por frecuencia)
    palabras_comunes_es = [
        'de', 'la', 'que', 'el', 'en', 'y', 'a', 'los', 'del', 'se', 
        'las', 'por', 'un', 'para', 'con', 'no', 'una', 'su', 'al', 'lo',
        'como', 'más', 'pero', 'sus', 'le', 'ya', 'o', 'este', 'sí', 
        'porque', 'esta', 'entre', 'cuando', 'muy', 'sin', 'sobre', 'también',
        'me', 'hasta', 'hay', 'donde', 'quien', 'desde', 'todo', 'nos',
        'durante', 'todos', 'uno', 'les', 'ni', 'contra', 'otros', 'ese',
        'eso', 'ante', 'ellos', 'e', 'esto', 'mí', 'antes', 'algunos',
        'qué', 'unos', 'yo', 'otro', 'otras', 'otra', 'él', 'tanto',
        'esa', 'estos', 'mucho', 'quienes', 'nada', 'muchos', 'cual', 'poco',
        'ella', 'estar', 'estas', 'algunas', 'algo', 'nosotros', 'mi', 'mis',
        'tú', 'te', 'ti', 'tu', 'tus', 'ellas', 'nosotras', 'vosostros', 'vosostras',
        'os', 'mío', 'mía', 'míos', 'mías', 'tuyo', 'tuya', 'tuyos', 'tuyas',
        'suyo', 'suya', 'suyos', 'suyas', 'nuestro', 'nuestra', 'nuestros', 'nuestras',
        'vuestro', 'vuestra', 'vuestros', 'vuestras', 'esos', 'esas', 'estoy', 'estás',
        'está', 'estamos', 'estáis', 'están', 'esté', 'estés', 'estemos', 'estéis',
        'estén', 'estaré', 'estarás', 'estará', 'estaremos', 'estaréis', 'estarán',
        'estaría', 'estarías', 'estaríamos', 'estaríais', 'estarían', 'estaba',
        'estabas', 'estábamos', 'estabais', 'estaban', 'estuve', 'estuviste',
        'estuvo', 'estuvimos', 'estuvisteis', 'estuvieron', 'estuviera', 'estuvieras',
        'estuviéramos', 'estuvierais', 'estuvieran', 'estuviese', 'estuvieses',
        'estuviésemos', 'estuvieseis', 'estuviesen', 'estando', 'estado', 'estada',
        'estados', 'estadas', 'estad', 'he', 'has', 'ha', 'hemos', 'habéis',
        'han', 'haya', 'hayas', 'hayamos', 'hayáis', 'hayan', 'habré', 'habrás',
        'habrá', 'habremos', 'habréis', 'habrán', 'habría', 'habrías', 'habríamos',
        'habríais', 'habrían', 'había', 'habías', 'habíamos', 'habíais', 'habían',
        'hube', 'hubiste', 'hubo', 'hubimos', 'hubisteis', 'hubieron', 'hubiera',
        'hubieras', 'hubiéramos', 'hubierais', 'hubieran', 'hubiese', 'hubieses',
        'hubiésemos', 'hubieseis', 'hubiesen', 'habiendo', 'habido', 'habida',
        'habidos', 'habidas', 'soy', 'eres', 'es', 'somos', 'sois', 'son',
        'sea', 'seas', 'seamos', 'seáis', 'sean', 'seré', 'serás', 'será',
        'seremos', 'seréis', 'serán', 'sería', 'serías', 'seríamos', 'seríais',
        'serían', 'era', 'eras', 'éramos', 'erais', 'eran', 'fui', 'fuiste',
        'fue', 'fuimos', 'fuisteis', 'fueron', 'fuera', 'fueras', 'fuéramos',
        'fuerais', 'fueran', 'fuese', 'fueses', 'fuésemos', 'fueseis', 'fuesen',
        'siendo', 'sido', 'sed', 'tengo', 'tienes', 'tiene', 'tenemos', 'tenéis',
        'tienen', 'tenga', 'tengas', 'tengamos', 'tengáis', 'tengan', 'tendré',
        'tendrás', 'tendrá', 'tendremos', 'tendréis', 'tendrán', 'tendría',
        'tendrías', 'tendríamos', 'tendríais', 'tendrían', 'tenía', 'tenías',
        'teníamos', 'teníais', 'tenían', 'tuve', 'tuviste', 'tuvo', 'tuvimos',
        'tuvisteis', 'tuvieron', 'tuviera', 'tuvieras', 'tuviéramos', 'tuvierais',
        'tuvieran', 'tuviese', 'tuvieses', 'tuviésemos', 'tuvieseis', 'tuviesen',
        'teniendo', 'tenido', 'tenida', 'tenidos', 'tenidas', 'tened'
    ]
    
    if not texto or len(texto.strip()) == 0:
        return 0.0
    
    # Convertir a minúsculas y dividir en palabras
    texto_lower = texto.lower()
    palabras = texto_lower.split()
    
    if not palabras:
        return 0.0
    
    # Contar palabras comunes
    palabras_comunes_count = sum(1 for palabra in palabras if palabra in palabras_comunes_es)
    
    # Contar caracteres válidos (letras, espacios, puntuación básica)
    caracteres_validos = sum(1 for c in texto if c.isalpha() or c.isspace() or c in ',.;!?-')
    ratio_caracteres_validos = caracteres_validos / len(texto)
    
    # Calcular ratio de palabras comunes
    ratio_palabras_comunes = palabras_comunes_count / len(palabras)
    
    # Ponderar los factores
    probabilidad = (ratio_palabras_comunes * 0.7) + (ratio_caracteres_validos * 0.3)
    
    return probabilidad

def main():
    # Verificar argumentos
    if len(sys.argv) != 2:
        print(f"{Colors.RED}📋 Uso: sudo python3 readv2.py archivo.pcapng{Colors.END}")
        print(f"{Colors.YELLOW}📝 Ejemplo: sudo python3 readv2.py cesar.pcapng{Colors.END}")
        sys.exit(1)
    
    archivo_pcap = sys.argv[1]
    
    # Verificar que el archivo existe
    if not os.path.exists(archivo_pcap):
        print(f"{Colors.RED}❌ El archivo '{archivo_pcap}' no existe{Colors.END}")
        sys.exit(1)
    
    print(f"{Colors.CYAN}{Colors.BOLD}🔍 Iniciando análisis de captura de red...{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")
    
    # Extraer caracteres de los paquetes ICMP
    texto_cifrado = extraer_caracteres_icmp(archivo_pcap)
    
    if texto_cifrado is None:
        sys.exit(1)
    
    print(f"\n{Colors.CYAN}{'=' * 70}{Colors.END}")
    print(f"{Colors.MAGENTA}{Colors.BOLD}🔓 Iniciando descifrado César (fuerza bruta - 25 corrimientos)...{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")
    
    # Probar todos los corrimientos posibles (1-25)
    resultados = []
    
    for corrimiento in range(1, 26):
        texto_descifrado = descifrar_cesar(texto_cifrado, corrimiento)
        probabilidad = calcular_probabilidad_espanol(texto_descifrado)
        
        resultados.append({
            'corrimiento': corrimiento,
            'texto': texto_descifrado,
            'probabilidad': probabilidad
        })
    
    # Ordenar resultados por probabilidad (mayor a menor)
    resultados_ordenados = sorted(resultados, key=lambda x: x['probabilidad'], reverse=True)
    
    # Mostrar todos los resultados
    for i, resultado in enumerate(resultados_ordenados):
        prob = resultado['probabilidad']
        if prob > 0.6:  # Muy probable
            color = Colors.GREEN + Colors.BOLD
            emoji = "✅"
        elif prob > 0.3:  # Posible
            color = Colors.YELLOW
            emoji = "⚠️ "
        else:  # Improbable
            color = Colors.RED
            emoji = "❌"
        
        print(f"{color}{emoji} Corrimiento {resultado['corrimiento']:2d} (prob: {prob:.2f}): \"{resultado['texto']}\"{Colors.END}")
    
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")
    print(f"{Colors.GREEN}{Colors.BOLD}🎯 RESULTADO MÁS PROBABLE:{Colors.END}")
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")
    
    if resultados_ordenados and resultados_ordenados[0]['probabilidad'] > 0.1:
        mejor = resultados_ordenados[0]
        print(f"{Colors.GREEN}{Colors.BOLD}🔓 MENSAJE DESCIFRADO (corrimiento {mejor['corrimiento']}):{Colors.END}")
        print(f"{Colors.GREEN}{Colors.BOLD}   \"{mejor['texto']}\"{Colors.END}")
        print(f"{Colors.CYAN}   Probabilidad: {mejor['probabilidad']:.2f}{Colors.END}")
    else:
        print(f"{Colors.RED}❌ No se encontró un mensaje claramente legible{Colors.END}")
        print(f"{Colors.YELLOW}💡 Revise manualmente los resultados anteriores{Colors.END}")
    
    print(f"{Colors.CYAN}{'=' * 70}{Colors.END}")

if __name__ == "__main__":
    # Verificar que scapy esté instalado
    try:
        from scapy.all import rdpcap, ICMP, Raw
    except ImportError:
        print(f"{Colors.RED}❌ Scapy no está instalado. Instálalo con:{Colors.END}")
        print(f"{Colors.YELLOW}sudo apt install python3-scapy{Colors.END}")
        sys.exit(1)
    
    # Verificar permisos de superusuario
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        print(f"{Colors.YELLOW}⚠️  Advertencia: Sin permisos de superusuario, algunas funciones pueden fallar{Colors.END}")
    
    main()