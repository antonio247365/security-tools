#!/usr/bin/env python3
"""
Enterprise Port Scanner - Port Scanner with Banner Grabbing + PDF Report
Professional Edition - By Antonio Romero
"""

import socket
import concurrent.futures
import re
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

open_ports = []

# --- Mapeo de riesgos para puertos críticos ---
PORT_RISKS = {
    21: "FTP - Cleartext auth risk. Consider SFTP.",
    22: "SSH - Ensure key-based auth & disable root login.",
    23: "Telnet - INSECURE. Cleartext transmission.",
    25: "SMTP - Potential email relay. Restrict access.",
    53: "DNS - Ensure no zone transfers allowed.",
    80: "HTTP - Unencrypted traffic. Consider HTTPS.",
    110: "POP3 - Cleartext. Use POP3S.",
    111: "RPCBind - Information disclosure risk.",
    135: "RPC - Windows RPC. Check for exposed services.",
    137: "NetBIOS - Information disclosure.",
    139: "NetBIOS-SSN - Legacy sharing.",
    443: "HTTPS - Verify certificate validity & TLS version.",
    445: "SMB - High risk. Check for EternalBlue patches.",
    1433: "MSSQL - Database exposed. Restrict access.",
    1434: "MSSQL Monitor - Information disclosure.",
    1723: "PPTP - Insecure VPN protocol. Consider OpenVPN.",
    3306: "MySQL - Database exposed. Should not be public.",
    3389: "RDP - High brute-force risk. Use VPN or RD Gateway.",
    5432: "PostgreSQL - Database exposed. Restrict access.",
    5900: "VNC - High risk. Use SSH tunneling or VPN.",
    6379: "Redis - No auth by default. Add authentication.",
    8080: "HTTP-Alt - Unencrypted web. Consider HTTPS.",
    27017: "MongoDB - Database exposed. Add authentication.",
}

# Lista de banners extraños para filtrar
WEIRD_BANNERS = [
    "where are you", "hello?", "?", "hi", "welcome",
    "enter command", "unknown", "invalid", "error"
]

def is_valid_banner(banner):
    """Verifica si el banner parece real o es basura"""
    if not banner:
        return False
    banner_lower = banner.lower()
    for weird in WEIRD_BANNERS:
        if weird in banner_lower:
            return False
    if len(banner) < 3:
        return False
    return True

def sanitize_filename(text):
    """Limpia caracteres inválidos para nombres de archivo"""
    return re.sub(r'[<>:"/\\|?*]', '_', text)

def get_banner(sock):
    """Obtiene banner desde un socket ya conectado (con filtro anti-basura)"""
    try:
        sock.settimeout(2)
        # Fase 1: Escuchar silenciosamente
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner and is_valid_banner(banner):
            return banner.replace('\n', ' ').replace('\r', '')[:100]
    except socket.timeout:
        pass
    except:
        pass
    
    # Fase 2: Petición HTTP
    try:
        sock.send(b"HEAD / HTTP/1.1\r\nHost: \r\nUser-Agent: SecurityScanner\r\n\r\n")
        banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
        if banner and is_valid_banner(banner):
            return banner.replace('\n', ' ').replace('\r', '')[:100]
    except:
        pass
    
    return "Banner not available"

def scan_port(host, port, timeout=1.0):
    """Escanea un puerto, obtiene banner y mapea riesgo"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        
        if result == 0:
            banner = get_banner(s)
            risk_note = PORT_RISKS.get(port, "Informational - Standard service")
            open_ports.append((port, banner, risk_note))
            short_risk = risk_note.split('-')[0].strip()
            print(f"[+] Port {port}: OPEN - {short_risk}")
        s.close()
    except:
        pass

def generate_pdf(host, client, ports, output_file):
    """Genera reporte PDF profesional con análisis de riesgos"""
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('Title', parent=styles['Title'], alignment=TA_CENTER)
    elements.append(Paragraph("SECURITY ASSESSMENT REPORT - PORT SCAN", title_style))
    elements.append(Spacer(1, 20))
    
    details = f"""
    <b>Client:</b> {client}<br/>
    <b>Target:</b> {host}<br/>
    <b>Date:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    <b>Open ports found:</b> {len(ports)}
    """
    elements.append(Paragraph(details, styles['Normal']))
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("SCAN RESULTS & RISK MAPPING", styles['Heading2']))
    
    table_data = [["Port", "Service / Banner", "Risk / Note"]]
    
    for port, banner, risk in ports:
        table_data.append([
            str(port), 
            Paragraph(banner[:80], styles['Normal']), 
            Paragraph(risk, styles['Normal'])
        ])
    
    table = Table(table_data, colWidths=[50, 200, 180])
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2c3e50')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 30))
    
    elements.append(Paragraph("EXECUTIVE SUMMARY", styles['Heading2']))
    
    high_risk = sum(1 for _, _, r in ports if "INSECURE" in r or "High risk" in r)
    medium_risk = sum(1 for _, _, r in ports if "auth risk" in r or "exposed" in r or "disclosure" in r)
    low_risk = len(ports) - high_risk - medium_risk
    
    summary = f"""
    Found <b>{len(ports)}</b> open ports on target <b>{host}</b>.<br/>
    <b>Risk breakdown:</b> 🔴 High: {high_risk} | 🟡 Medium: {medium_risk} | 🟢 Low: {low_risk}<br/><br/>
    <b>Recommendation:</b> Prioritize investigating high-risk services (RDP, SMB, Telnet, exposed databases). 
    Implement firewall rules to restrict access to critical ports.
    """
    elements.append(Paragraph(summary, styles['Normal']))
    
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"<i>Report generated for: {client}</i>", styles['Normal']))
    elements.append(Paragraph("<i>Generated by: Enterprise Port Scanner</i>", styles['Normal']))
    
    doc.build(elements)
    print(f"\n[✓] PDF Report: {output_file}")

def main():
    print("=" * 65)
    print("  ENTERPRISE PORT SCANNER - VULNERABILITY ASSESSMENT")
    print("  Created by: Antonio Romero - Cybersecurity Specialist")
    print("=" * 65)
    
    host = input("\n[?] Target IP: ").strip()
    client = input("[?] Client name: ").strip()
    
    if not client:
        client = "Client"
    
    print("\n[?] Port range:")
    print("   1. Common ports (1-1024) - Recommended")
    print("   2. All ports (1-65535) - Takes longer")
    option = input("\nChoose 1 or 2: ")
    
    start, end = (1, 1024) if option == "1" else (1, 65535)
    
    print(f"\n[+] Scanning {host} ports {start}-{end} with Thread Pool...")
    print("[+] This may take a moment. Please wait...")
    print("-" * 65)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(scan_port, host, port) for port in range(start, end + 1)]
        concurrent.futures.wait(futures)
    
    print("-" * 65)
    print(f"[✓] Scan completed. Total open ports: {len(open_ports)}")
    
    if open_ports:
        open_ports.sort(key=lambda x: x[0])
        safe_client = sanitize_filename(client)
        filename = f"Security_Report_{safe_client}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf(host, client, open_ports, filename)
    else:
        print("[!] No open ports found. PDF not generated.")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")