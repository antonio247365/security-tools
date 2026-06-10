import requests
import urllib3
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet

# Disable SSL warnings for testing environments
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------
# 1. SECURITY HEADER SCANNER
# ------------------------------------------------------------
def scan_headers(target_url):
    """
    Scans HTTP security headers of a given URL.
    Returns a list of findings (dictionaries).
    """
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url

    print(f"\n[+] Scanning {target_url} ...")
    
    findings = []
    
    try:
        response = requests.get(target_url, timeout=10, verify=False)
        headers = response.headers
        
        checks = {
            'X-Frame-Options': {
                'recommendation': 'Set to DENY or SAMEORIGIN to prevent Clickjacking attacks.',
                'severity': 'Medium'
            },
            'X-Content-Type-Options': {
                'recommendation': 'Set to "nosniff" to prevent MIME sniffing attacks.',
                'severity': 'Medium'
            },
            'Content-Security-Policy': {
                'recommendation': 'Define a CSP policy to restrict content sources and prevent XSS.',
                'severity': 'High'
            },
            'Strict-Transport-Security': {
                'recommendation': 'Enable HSTS to force HTTPS connections in the browser.',
                'severity': 'High'
            },
            'X-XSS-Protection': {
                'recommendation': 'Set to "1; mode=block" as an additional XSS protection layer.',
                'severity': 'Low'
            },
            'Referrer-Policy': {
                'recommendation': 'Configure to control referrer information sent to other sites.',
                'severity': 'Low'
            },
            'Permissions-Policy': {
                'recommendation': 'Restrict browser API usage (camera, microphone, location, etc.).',
                'severity': 'Low'
            }
        }
        
        for header, info in checks.items():
            if header not in headers:
                findings.append({
                    'title': f'Missing {header} Header',
                    'description': f'The security header "{header}" is not present in the server response.',
                    'risk': info['recommendation'],
                    'severity': info['severity'],
                    'priority': info['severity'],
                    'recommendation': f'Add the {header} header with the appropriate configuration on the web server (Apache, Nginx, etc.).'
                })
        
        if not findings:
            print("[OK] No missing security headers found.")
        
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to target: {e}")
        findings.append({
            'title': 'Connection Error',
            'description': f'Could not establish connection to target: {e}',
            'risk': 'Audit could not be completed.',
            'severity': 'N/A',
            'priority': 'N/A',
            'recommendation': 'Verify that the URL is correct and the server is accessible.'
        })
    
    return findings

# ------------------------------------------------------------
# 2. PROFESSIONAL PDF REPORT GENERATOR
# ------------------------------------------------------------
def generate_pdf_report(report_data, filename="security_audit_report.pdf"):
    """
    Generates a professional PDF security audit report.
    report_data must contain:
    {
        'client': str,
        'target': str,
        'date': str,
        'auditor': str,
        'findings': list
    }
    """
    doc = SimpleDocTemplate(filename, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # COVER PAGE
    title = Paragraph("SECURITY AUDIT REPORT", styles['Title'])
    elements.append(title)
    elements.append(Spacer(1, 20))
    
    # Report details
    client_data = f"""
    <b>Client:</b> {report_data.get('client', 'Not specified')}<br/>
    <b>Target:</b> {report_data['target']}<br/>
    <b>Date:</b> {report_data.get('date', datetime.now().strftime('%m/%d/%Y'))}<br/>
    <b>Auditor:</b> {report_data.get('auditor', 'Antonio Romero')}
    """
    elements.append(Paragraph(client_data, styles['Normal']))
    elements.append(Spacer(1, 30))
    
    # EXECUTIVE SUMMARY
    elements.append(Paragraph("1. EXECUTIVE SUMMARY", styles['Heading2']))
    elements.append(Spacer(1, 10))
    
    findings = report_data['findings']
    high = sum(1 for f in findings if f.get('severity') == 'High')
    medium = sum(1 for f in findings if f.get('severity') == 'Medium')
    low = sum(1 for f in findings if f.get('severity') == 'Low')
    
    summary_table = Table([
        ['SEVERITY', 'COUNT'],
        ['HIGH', str(high)],
        ['MEDIUM', str(medium)],
        ['LOW', str(low)],
        ['TOTAL', str(len(findings))]
    ])
    
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('GRID', (0,0), (-1,-1), 0.5, colors.grey),
        ('BACKGROUND', (0,1), (-1,1), colors.HexColor("#ffcccc")),
        ('BACKGROUND', (0,2), (-1,2), colors.HexColor("#fff3cc")),
        ('BACKGROUND', (0,3), (-1,3), colors.HexColor("#e6ffe6")),
    ]))
    
    elements.append(summary_table)
    elements.append(Spacer(1, 30))
    
    # DETAILED FINDINGS
    elements.append(Paragraph("2. DETAILED FINDINGS", styles['Heading2']))
    elements.append(Spacer(1, 10))
    
    if not findings:
        elements.append(Paragraph("No vulnerabilities were found during the analysis.", styles['Normal']))
    else:
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'N/A')
            severity_color = {
                'High': '#cc0000',
                'Medium': '#cc6600',
                'Low': '#009900'
            }.get(severity, '#000000')
            
            finding_content = f"""
            <b>{i}. {finding.get('title', 'Untitled')}</b><br/><br/>
            <font color="{severity_color}"><b>Severity: {severity}</b></font><br/><br/>
            <b>Description:</b><br/>
            {finding.get('description', 'Not available.')}<br/><br/>
            <b>Risk:</b><br/>
            {finding.get('risk', 'Not specified.')}<br/><br/>
            <b>Recommendation:</b><br/>
            {finding.get('recommendation', 'Not specified.')}
            """
            elements.append(Paragraph(finding_content, styles['Normal']))
            elements.append(Spacer(1, 20))
    
    # FOOTER
    elements.append(Spacer(1, 40))
    footer = """
    <i>Report automatically generated by Web Security Auditor.<br/>
    Contact: antonio.romero@email.com</i>
    """
    elements.append(Paragraph(footer, styles['Normal']))
    
    doc.build(elements)
    print(f"\n[OK] PDF successfully generated: {filename}")
    return filename

# ------------------------------------------------------------
# 3. MAIN PROGRAM
# ------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 50)
    print("  WEB SECURITY AUDITOR - v1.0")
    print("=" * 50)
    
    url = input("\nURL to audit (e.g. mysite.com): ").strip()
    client = input("Client name: ").strip()
    
    results = scan_headers(url)
    
    data = {
        'client': client,
        'target': url,
        'date': datetime.now().strftime('%m/%d/%Y'),
        'auditor': 'Antonio Romero',
        'findings': results
    }
    
    filename = f"audit_{client.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}.pdf"
    generate_pdf_report(data, filename)
    
    print("\n[OK] Process completed.")
    print(f"[OK] File generated: {filename}")