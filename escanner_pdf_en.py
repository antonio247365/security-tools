#!/usr/bin/env python3
"""
Port Scanner with Banner Grabbing + PDF Report (ENGLISH VERSION)
"""

import socket
import threading
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER

open_ports = []

def get_banner(host, port, timeout=3):
    """Get banner from open port"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
        banner = s.recv(256).decode('utf-8', errors='ignore').strip()
        s.close()
        banner = banner.replace('\n', ' ').replace('\r', '')
        return banner[:150] if banner else "Banner not available"
    except:
        return "Banner not available"

def scan_port(host, port):
    """Scan a port and save banner if open"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        if result == 0:
            banner = get_banner(host, port)
            open_ports.append((port, banner))
            print(f"[+] Port {port}: OPEN - {banner[:80]}...")
        s.close()
    except:
        pass

def generate_pdf(host, client, ports, output_file):
    """Generate professional PDF report in English"""
    doc = SimpleDocTemplate(output_file, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # Title
    title_style = ParagraphStyle('Title', parent=styles['Title'], alignment=TA_CENTER)
    elements.append(Paragraph("PORT SCAN REPORT", title_style))
    elements.append(Spacer(1, 20))
    
    # Scan details
    details = f"""
    <b>Client:</b> {client}<br/>
    <b>Target:</b> {host}<br/>
    <b>Date:</b> {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}<br/>
    <b>Open ports found:</b> {len(ports)}
    """
    elements.append(Paragraph(details, styles['Normal']))
    elements.append(Spacer(1, 30))
    
    # Results table
    elements.append(Paragraph("SCAN RESULTS", styles['Heading2']))
    
    table_data = [["Port", "Service / Banner"]]
    for port, banner in ports:
        table_data.append([str(port), banner[:100]])
    
    table = Table(table_data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.grey),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 30))
    
    # Summary
    elements.append(Paragraph("SUMMARY", styles['Heading2']))
    elements.append(Paragraph(f"Found <b>{len(ports)}</b> open ports on target <b>{host}</b>.", styles['Normal']))
    
    # Footer
    elements.append(Spacer(1, 40))
    elements.append(Paragraph(f"<i>Report generated for: {client}</i>", styles['Normal']))
    elements.append(Paragraph("<i>Tool: Port Scanner with Banner Grabbing</i>", styles['Normal']))
    
    doc.build(elements)
    print(f"[✓] PDF generated: {output_file}")

def main():
    print("=" * 60)
    print("     PORT SCANNER + PDF REPORT (ENGLISH)")
    print("=" * 60)
    
    host = input("\n[?] Target IP: ")
    client = input("[?] Client name: ")
    
    print("\n[?] Port range:")
    print("   1. Common ports (1-1024)")
    print("   2. All ports (1-65535)")
    option = input("\nChoose 1 or 2: ")
    
    start, end = (1, 1024) if option == "1" else (1, 65535)
    
    print(f"\n[+] Scanning {host} ports {start}-{end}...")
    print("-" * 60)
    
    threads = []
    for port in range(start, end + 1):
        thread = threading.Thread(target=scan_port, args=(host, port))
        threads.append(thread)
        thread.start()
        
        if port % 100 == 0:
            print(f"Progress: {port}/{end} ports...", end="\r")
    
    for thread in threads:
        thread.join()
    
    print("\n" + "-" * 60)
    print(f"[✓] Scan completed. Open ports: {len(open_ports)}")
    
    if open_ports:
        filename = f"port_scan_{client.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        generate_pdf(host, client, open_ports, filename)
    else:
        print("[!] No open ports found. PDF not generated.")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Scan interrupted by user")