#!/usr/bin/env python3
"""
Escáner de Puertos con Banner Grabbing + Reporte PDF
"""

import socket
import threading
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

puertos_abiertos = []

def obtener_banner(host, port, timeout=3):
    """Obtiene el banner del servicio en un puerto abierto"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        banner = banner.replace('\n', ' ').replace('\r', '')
        return banner[:150] if banner else "No se pudo obtener banner"
    except:
        return "Banner no disponible"

def escanear_puerto(host, port):
    """Escanea un puerto y guarda el banner si está abierto"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        resultado = s.connect_ex((host, port))
        if resultado == 0:
            banner = obtener_banner(host, port)
            puertos_abiertos.append((port, banner))
            print(f"[+] Puerto {port}: ABIERTO - {banner[:80]}...")
        s.close()
    except:
        pass

def generar_pdf(host, cliente, puertos, archivo_salida):
    """Genera un reporte PDF profesional"""
    doc = SimpleDocTemplate(archivo_salida, pagesize=A4)
    elementos = []
    estilos = getSampleStyleSheet()
    
    # Título
    titulo_style = ParagraphStyle('Titulo', parent=estilos['Title'], alignment=TA_CENTER)
    elementos.append(Paragraph("REPORTE DE ESCANEO DE PUERTOS", titulo_style))
    elementos.append(Spacer(1, 20))
    
    # Datos del escaneo
    datos = f"""
    <b>Cliente:</b> {cliente}<br/>
    <b>Objetivo:</b> {host}<br/>
    <b>Fecha:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    <b>Puertos escaneados:</b> {len(puertos_abiertos)} abiertos
    """
    elementos.append(Paragraph(datos, estilos['Normal']))
    elementos.append(Spacer(1, 30))
    
    # Tabla de resultados
    elementos.append(Paragraph("RESULTADOS DEL ESCANEO", estilos['Heading2']))
    
    tabla_datos = [["Puerto", "Servicio / Banner"]]
    for port, banner in puertos:
        tabla_datos.append([str(port), banner[:100]])
    
    tabla = Table(tabla_datos)
    tabla.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
    ]))
    elementos.append(tabla)
    elementos.append(Spacer(1, 30))
    
    # Resumen
    elementos.append(Paragraph("RESUMEN", estilos['Heading2']))
    elementos.append(Paragraph(f"Se encontraron <b>{len(puertos_abiertos)}</b> puertos abiertos.", estilos['Normal']))
    
    # Firmas
    elementos.append(Spacer(1, 40))
    elementos.append(Paragraph(f"<i>Reporte generado por: {cliente}</i>", estilos['Normal']))
    elementos.append(Paragraph("<i>Herramienta: Escáner de Puertos con Banner Grabbing</i>", estilos['Normal']))
    
    doc.build(elementos)
    print(f"[✓] PDF generado: {archivo_salida}")

def main():
    print("=" * 60)
    print("     ESCÁNER DE PUERTOS + REPORTE PDF")
    print("=" * 60)
    
    host = input("\n[?] IP a escanear: ")
    cliente = input("[?] Nombre del cliente: ")
    
    print("\n[?] Rango de puertos:")
    print("   1. Puertos comunes (1-1024)")
    print("   2. Todos los puertos (1-65535)")
    opcion = input("\nElige 1 o 2: ")
    
    inicio, fin = (1, 1024) if opcion == "1" else (1, 65535)
    
    print(f"\n[+] Escaneando {host} puertos {inicio}-{fin}...")
    print("-" * 60)
    
    hilos = []
    for port in range(inicio, fin + 1):
        hilo = threading.Thread(target=escanear_puerto, args=(host, port))
        hilos.append(hilo)
        hilo.start()
        
        if port % 100 == 0:
            print(f"Progreso: {port}/{fin} puertos...", end="\r")
    
    for hilo in hilos:
        hilo.join()
    
    print("\n" + "-" * 60)
    print(f"[✓] Escaneo completado. Puertos abiertos: {len(puertos_abiertos)}")
    
    if puertos_abiertos:
        nombre_archivo = f"reporte_escaneo_{cliente.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generar_pdf(host, cliente, puertos_abiertos, nombre_archivo)
    else:
        print("[!] No se encontraron puertos abiertos. No se genera PDF.")
    
    input("\nPresiona Enter para salir...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Escaneo interrumpido")