import requests
import urllib3
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

# Desactivar advertencias de SSL para entornos de prueba
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------
# 1. ESCANEADOR DE CABECERAS DE SEGURIDAD
# ------------------------------------------------------------
def escanear_cabeceras(url_objetivo):
    """
    Escanea las cabeceras de seguridad HTTP de una URL.
    Retorna una lista de hallazgos (diccionarios).
    """
    # Asegurar que la URL tenga http:// o https://
    if not url_objetivo.startswith(('http://', 'https://')):
        url_objetivo = 'http://' + url_objetivo

    print(f"\n[+] Escaneando {url_objetivo} ...")
    
    hallazgos = []
    
    try:
        respuesta = requests.get(url_objetivo, timeout=10, verify=False)
        cabeceras = respuesta.headers
        
        # Lista de cabeceras de seguridad a verificar
        chequeos = {
            'X-Frame-Options': {
                'recomendacion': 'Configurar con DENY o SAMEORIGIN para evitar ataques de Clickjacking.',
                'severidad': 'Media'
            },
            'X-Content-Type-Options': {
                'recomendacion': 'Configurar con "nosniff" para evitar ataques de MIME sniffing.',
                'severidad': 'Media'
            },
            'Content-Security-Policy': {
                'recomendacion': 'Definir una política CSP para restringir fuentes de contenido y prevenir XSS.',
                'severidad': 'Alta'
            },
            'Strict-Transport-Security': {
                'recomendacion': 'Habilitar HSTS para forzar conexiones HTTPS en el navegador.',
                'severidad': 'Alta'
            },
            'X-XSS-Protection': {
                'recomendacion': 'Configurar con "1; mode=block" como capa adicional de proteccion XSS.',
                'severidad': 'Baja'
            },
            'Referrer-Policy': {
                'recomendacion': 'Configurar para controlar la informacion de referencia enviada a otros sitios.',
                'severidad': 'Baja'
            },
            'Permissions-Policy': {
                'recomendacion': 'Restringir el uso de APIs del navegador (camara, microfono, ubicacion, etc.).',
                'severidad': 'Baja'
            }
        }
        
        for cabecera, info in chequeos.items():
            if cabecera not in cabeceras:
                hallazgos.append({
                    'titulo': f'Ausencia de cabecera {cabecera}',
                    'descripcion': f'La cabecera de seguridad "{cabecera}" no esta presente en la respuesta del servidor web.',
                    'riesgo': info['recomendacion'],
                    'severidad': info['severidad'],
                    'prioridad': info['severidad'],
                    'recomendacion': f'Agregar la cabecera {cabecera} con la configuracion adecuada en el servidor web (Apache, Nginx, etc.).'
                })
        
        if not hallazgos:
            print("[OK] No se encontraron ausencias de cabeceras de seguridad.")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Error al conectar con el objetivo: {e}")
        hallazgos.append({
            'titulo': 'Error de conexion',
            'descripcion': f'No se pudo establecer conexion con el objetivo: {e}',
            'riesgo': 'No se pudo realizar la auditoria.',
            'severidad': 'N/A',
            'prioridad': 'N/A',
            'recomendacion': 'Verificar que la URL es correcta y que el servidor esta accesible.'
        })
    
    return hallazgos

# ------------------------------------------------------------
# 2. GENERADOR DE PDF PROFESIONAL
# ------------------------------------------------------------
def generar_pdf_reporte(datos_reporte, nombre_archivo="informe_auditoria.pdf"):
    """
    Genera un PDF profesional con el informe de auditoria.
    datos_reporte debe contener:
    {
        'cliente': str,
        'objetivo': str,
        'fecha': str,
        'auditor': str,
        'hallazgos': list
    }
    """
    doc = SimpleDocTemplate(nombre_archivo, pagesize=A4)
    elementos = []
    estilos = getSampleStyleSheet()
    
    # PORTADA
    titulo = Paragraph("INFORME DE AUDITORIA DE SEGURIDAD", estilos['Title'])
    elementos.append(titulo)
    elementos.append(Spacer(1, 20))
    
    # Datos del informe
    datos_cliente = f"""
    <b>Cliente:</b> {datos_reporte.get('cliente', 'No especificado')}<br/>
    <b>Objetivo:</b> {datos_reporte['objetivo']}<br/>
    <b>Fecha:</b> {datos_reporte.get('fecha', datetime.now().strftime('%d/%m/%Y'))}<br/>
    <b>Auditor:</b> {datos_reporte.get('auditor', 'Antonio Romero')}
    """
    elementos.append(Paragraph(datos_cliente, estilos['Normal']))
    elementos.append(Spacer(1, 30))
    
    # RESUMEN EJECUTIVO
    elementos.append(Paragraph("1. RESUMEN EJECUTIVO", estilos['Heading2']))
    elementos.append(Spacer(1, 10))
    
    hallazgos = datos_reporte['hallazgos']
    altas = sum(1 for h in hallazgos if h.get('severidad') == 'Alta')
    medias = sum(1 for h in hallazgos if h.get('severidad') == 'Media')
    bajas = sum(1 for h in hallazgos if h.get('severidad') == 'Baja')
    
    tabla_resumen = Table([
        ['SEVERIDAD', 'CANTIDAD'],
        ['ALTA', str(altas)],
        ['MEDIA', str(medias)],
        ['BAJA', str(bajas)],
        ['TOTAL', str(len(hallazgos))]
    ])
    
    # Estilos de la tabla de resumen
    tabla_resumen.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#ffcccc")),
        ('BACKGROUND', (0,2), (-1,2), colors.HexColor("#fff3cc")),
        ('BACKGROUND', (0,3), (-1,3), colors.HexColor("#e6ffe6")),
    ]))
    
    elementos.append(tabla_resumen)
    elementos.append(Spacer(1, 30))
    
    # HALLAZGOS DETALLADOS
    elementos.append(Paragraph("2. HALLAZGOS DETALLADOS", estilos['Heading2']))
    elementos.append(Spacer(1, 10))
    
    if not hallazgos:
        elementos.append(Paragraph("No se encontraron vulnerabilidades en el analisis realizado.", estilos['Normal']))
    else:
        for i, hallazgo in enumerate(hallazgos, 1):
            severidad = hallazgo.get('severidad', 'N/A')
            color_severidad = {
                'Alta': '#cc0000',
                'Media': '#cc6600',
                'Baja': '#009900'
            }.get(severidad, '#000000')
            
            contenido_hallazgo = f"""
            <b>{i}. {hallazgo.get('titulo', 'Sin titulo')}</b><br/><br/>
            <font color="{color_severidad}"><b>Severidad: {severidad}</b></font><br/><br/>
            <b>Descripcion:</b><br/>
            {hallazgo.get('descripcion', 'No disponible.')}<br/><br/>
            <b>Riesgo:</b><br/>
            {hallazgo.get('riesgo', 'No especificado.')}<br/><br/>
            <b>Recomendacion:</b><br/>
            {hallazgo.get('recomendacion', 'No especificada.')}
            """
            elementos.append(Paragraph(contenido_hallazgo, estilos['Normal']))
            elementos.append(Spacer(1, 20))
    
    # FIRMA
    elementos.append(Spacer(1, 40))
    firma = f"""
    <i>Reporte generado automaticamente por Auditor de Seguridad Web.<br/>
    Contacto: antonio.romero@email.com</i>
    """
    elementos.append(Paragraph(firma, estilos['Normal']))
    
    doc.build(elementos)
    print(f"\n[OK] PDF generado exitosamente: {nombre_archivo}")
    return nombre_archivo

# ------------------------------------------------------------
# 3. PROGRAMA PRINCIPAL
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  AUDITOR DE SEGURIDAD WEB - v1.0")
    print("=" * 50)
    
    # Solicitar datos al usuario
    url = input("\nURL a auditar (ej. misitio.com): ").strip()
    cliente = input("Nombre del cliente: ").strip()
    
    # Realizar escaneo
    resultados = escanear_cabeceras(url)
    
    # Preparar datos para el PDF
    datos = {
        'cliente': cliente,
        'objetivo': url,
        'fecha': datetime.now().strftime('%d/%m/%Y'),
        'auditor': 'Antonio Romero',
        'hallazgos': resultados
    }
    
    # Generar PDF
    nombre_archivo = f"auditoria_{cliente.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
    generar_pdf_reporte(datos, nombre_archivo)
    
    print("\n[OK] Proceso completado.")
    print(f"[OK] Archivo generado: {nombre_archivo}")