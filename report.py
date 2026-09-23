import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def build_pdf_report(audit_data, filename="Audit_Report.pdf"):
    """Takes a dictionary of audit findings and generates a 1-page PDF at the specified filepath."""
    
    doc = SimpleDocTemplate(filename, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    # Title
    story.append(Paragraph("<b>SMB Network Security Assessment</b>", styles['Title']))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("<b>Executive Summary</b>", styles['Heading2']))
    summary_text = f"The audit successfully swept the local subnet and identified <b>{audit_data['total_devices']}</b> active devices."
    story.append(Paragraph(summary_text, styles['Normal']))
    story.append(Spacer(1, 12))

   # 1. Gateway Status
    story.append(Paragraph("<b>1. Perimeter & Gateway Security</b>", styles['Heading2']))
    if audit_data['gateway_compromised']:
        details = audit_data['gateway_details'].replace("[CRITICAL] ", "")
        gw_text = f"<font color='red'><b>[FAILED]</b></font> The main router is vulnerable to default administrator credentials.<br/><b>Exposure:</b> {details}<br/><i>This allows attackers to reroute traffic or completely disable the firewall.</i>"
    else:
        gw_text = "<font color='green'><b>[PASSED]</b></font> The main router gateway resisted basic default credential attacks."
    story.append(Paragraph(gw_text, styles['Normal']))
    story.append(Spacer(1, 12))

    # 2. Internal Device Findings
    story.append(Paragraph("<b>2. Internal Device Vulnerabilities</b>", styles['Heading2']))
    if not audit_data['vulnerable_devices']:
        story.append(Paragraph("<font color='green'><b>[PASSED]</b></font> No critical exposed services (RDP, SMB, FTP, Telnet) were detected on internal devices.", styles['Normal']))
    else:
        for dev in audit_data['vulnerable_devices']:
            dev_text = f"<b>Target IP:</b> {dev['ip']} ({dev['vendor']})"
            story.append(Paragraph(dev_text, styles['Normal']))
            
            for finding in dev['findings']:
                story.append(Paragraph(f"<font color='red'><b>- {finding}</b></font>", styles['Normal']))
            story.append(Spacer(1, 6))

    # 3. Recommended Actions (Now Dynamic)
    story.append(Spacer(1, 12))
    story.append(Paragraph("<b>Recommended Action Plan</b>", styles['Heading2']))
    
    step_num = 1
    
    if audit_data['gateway_compromised']:
        story.append(Paragraph(f"{step_num}. Update router administrator passwords immediately to prevent unauthorized access.", styles['Normal']))
        step_num += 1
        
    if audit_data['vulnerable_devices']:
        story.append(Paragraph(f"{step_num}. Disable File Sharing (SMB) or open ports on internal devices that do not explicitly require it for business operations.", styles['Normal']))
        step_num += 1
        
    # Always include segmentation as a baseline best practice
    story.append(Paragraph(f"{step_num}. Ensure Guest Wi-Fi is physically or logically segmented from the main business network.", styles['Normal']))

    # Generate the file
    doc.build(story)
    return filename