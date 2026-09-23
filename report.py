import os
from reportlab.lib.pagesizes import landscape, letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

def build_pdf_report(audit_data, filename="Audit_Report.pdf"):
    doc = SimpleDocTemplate(filename, pagesize=landscape(letter))
    styles = getSampleStyleSheet()
    story = []
    
    story.append(Paragraph("<b>NetBaseline Security Assessment</b>", styles['Title']))
    story.append(Spacer(1, 12))

    # General Liability Protection
    story.append(Paragraph("<b>Assessment Limitations & Scope</b>", styles['Heading3']))
    limitations = "<i>This assessment utilizes an extended protocol sweep to identify administrative, infrastructure, and IoT services. It performs non-destructive identification, active protocol enumeration, and banner grabbing to identify software versions and potential configuration flaws. It does not perform destructive exploitation, endpoint malware analysis, or password brute-forcing.</i>"
    story.append(Paragraph(limitations, styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph("<b>Perimeter & Gateway Assessment</b>", styles['Heading2']))
    if audit_data['gateway_compromised']:
        details = audit_data['gateway_details'].replace("[POTENTIAL EXPOSURE] ", "")
        gw_text = f"<font color='red'><b>Potential Exposure Identified:</b></font> {details}"
    else:
        gw_text = "<font color='green'><b>No Findings:</b></font> Gateway did not accept common default credentials."
    story.append(Paragraph(gw_text, styles['Normal']))
    story.append(Spacer(1, 20))

    story.append(Paragraph(f"<b>Asset Exposure Inventory (Total Devices: {audit_data['total_devices']})</b>", styles['Heading2']))
    story.append(Spacer(1, 10))

    table_data = [["Asset IP", "Identification", "Network Exposure", "Assessment Finding"]]
    sorted_inventory = sorted(audit_data['inventory'], key=lambda x: [int(part) for part in x['ip'].split('.')])
    
    for dev in sorted_inventory:
        table_data.append([dev['ip'], dev['classification'], dev['exposure'], dev['finding']])

    t = Table(table_data, colWidths=[100, 250, 200, 180])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#273f7a")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f4f4f4")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
    ]))
    
    story.append(t)
    doc.build(story)
    return filename