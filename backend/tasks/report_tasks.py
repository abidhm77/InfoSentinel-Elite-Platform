#!/usr/bin/env python3
"""
Celery tasks for report generation and delivery.
"""
from celery import current_app
from services.celery_service import celery_app
from database.db import get_db
from datetime import datetime
from flask_mail import Message
import logging
import os
import tempfile
from jinja2 import Template
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT

logger = logging.getLogger(__name__)

@celery_app.task
def generate_pdf_report(scan_id, report_type='standard'):
    """
    Generate PDF report for a completed scan.
    
    Args:
        scan_id: Scan identifier
        report_type: Type of report (standard, executive, compliance)
        
    Returns:
        dict: Report generation results
    """
    try:
        logger.info(f"Generating {report_type} PDF report for scan {scan_id}")
        
        db = get_db()
        
        # Get scan data
        scan = db.scans.find_one({"_id": scan_id})
        if not scan:
            raise ValueError(f"Scan {scan_id} not found")
        
        # Get vulnerabilities
        vulnerabilities = list(db.vulnerabilities.find({"scan_id": scan_id}))
        
        # Create temporary file for PDF
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
            pdf_path = tmp_file.name
        
        # Generate PDF based on report type
        if report_type == 'executive':
            _generate_executive_report(pdf_path, scan, vulnerabilities)
        elif report_type == 'compliance':
            _generate_compliance_report(pdf_path, scan, vulnerabilities)
        else:
            _generate_standard_report(pdf_path, scan, vulnerabilities)
        
        # Read PDF content
        with open(pdf_path, 'rb') as pdf_file:
            pdf_content = pdf_file.read()
        
        # Store report in database
        report_doc = {
            "scan_id": scan_id,
            "report_type": report_type,
            "generated_at": datetime.utcnow(),
            "file_size": len(pdf_content),
            "status": "completed"
        }
        
        report_id = db.reports.insert_one(report_doc).inserted_id
        
        # Store PDF file (in production, use cloud storage)
        report_storage_path = f"reports/{scan_id}_{report_type}_{report_id}.pdf"
        
        # Clean up temporary file
        os.unlink(pdf_path)
        
        logger.info(f"PDF report generated successfully for scan {scan_id}")
        
        return {
            "report_id": str(report_id),
            "scan_id": scan_id,
            "report_type": report_type,
            "file_size": len(pdf_content),
            "storage_path": report_storage_path
        }
        
    except Exception as e:
        logger.error(f"Error generating PDF report for scan {scan_id}: {str(e)}")
        raise

def _generate_standard_report(pdf_path, scan, vulnerabilities):
    """Generate standard technical report."""
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=24,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkblue
    )
    
    story.append(Paragraph("InfoSentinel Security Assessment Report", title_style))
    story.append(Spacer(1, 20))
    
    # Executive Summary
    story.append(Paragraph("Executive Summary", styles['Heading2']))
    
    summary_data = [
        ['Target', scan.get('target', 'N/A')],
        ['Scan Type', scan.get('scan_type', 'N/A')],
        ['Start Time', scan.get('start_time', 'N/A')],
        ['End Time', scan.get('end_time', 'N/A')],
        ['Status', scan.get('status', 'N/A')],
        ['Total Vulnerabilities', str(len(vulnerabilities))]
    ]
    
    summary_table = Table(summary_data, colWidths=[2*inch, 3*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(summary_table)
    story.append(Spacer(1, 20))
    
    # Vulnerability Breakdown
    if vulnerabilities:
        story.append(Paragraph("Vulnerability Details", styles['Heading2']))
        
        # Group vulnerabilities by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Severity breakdown table
        severity_data = [
            ['Severity', 'Count', 'Percentage'],
            ['High', str(severity_counts['high']), f"{(severity_counts['high']/len(vulnerabilities)*100):.1f}%" if vulnerabilities else '0%'],
            ['Medium', str(severity_counts['medium']), f"{(severity_counts['medium']/len(vulnerabilities)*100):.1f}%" if vulnerabilities else '0%'],
            ['Low', str(severity_counts['low']), f"{(severity_counts['low']/len(vulnerabilities)*100):.1f}%" if vulnerabilities else '0%']
        ]
        
        severity_table = Table(severity_data, colWidths=[2*inch, 1*inch, 1.5*inch])
        severity_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (0, 1), colors.red),
            ('BACKGROUND', (0, 2), (0, 2), colors.orange),
            ('BACKGROUND', (0, 3), (0, 3), colors.yellow),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(severity_table)
        story.append(PageBreak())
        
        # Detailed vulnerability list
        story.append(Paragraph("Detailed Vulnerability List", styles['Heading2']))
        
        for i, vuln in enumerate(vulnerabilities, 1):
            story.append(Paragraph(f"{i}. {vuln.get('title', 'Unknown Vulnerability')}", styles['Heading3']))
            story.append(Paragraph(f"<b>Severity:</b> {vuln.get('severity', 'Unknown').title()}", styles['Normal']))
            story.append(Paragraph(f"<b>Description:</b> {vuln.get('description', 'No description available')}", styles['Normal']))
            
            if vuln.get('host'):
                story.append(Paragraph(f"<b>Affected Host:</b> {vuln.get('host')}", styles['Normal']))
            
            if vuln.get('port'):
                story.append(Paragraph(f"<b>Port:</b> {vuln.get('port')}", styles['Normal']))
            
            story.append(Spacer(1, 12))
    
    else:
        story.append(Paragraph("No vulnerabilities found during this scan.", styles['Normal']))
    
    # Build PDF
    doc.build(story)

def _generate_executive_report(pdf_path, scan, vulnerabilities):
    """Generate executive summary report."""
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    title_style = ParagraphStyle(
        'ExecutiveTitle',
        parent=styles['Heading1'],
        fontSize=28,
        spaceAfter=30,
        alignment=TA_CENTER,
        textColor=colors.darkred
    )
    
    story.append(Paragraph("Executive Security Assessment Summary", title_style))
    story.append(Spacer(1, 30))
    
    # Risk Assessment
    high_vulns = len([v for v in vulnerabilities if v.get('severity') == 'high'])
    medium_vulns = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
    low_vulns = len([v for v in vulnerabilities if v.get('severity') == 'low'])
    
    # Determine overall risk level
    if high_vulns > 0:
        risk_level = "HIGH"
        risk_color = colors.red
    elif medium_vulns > 3:
        risk_level = "MEDIUM"
        risk_color = colors.orange
    else:
        risk_level = "LOW"
        risk_color = colors.green
    
    story.append(Paragraph("Overall Security Risk Assessment", styles['Heading2']))
    
    risk_style = ParagraphStyle(
        'RiskLevel',
        parent=styles['Normal'],
        fontSize=20,
        alignment=TA_CENTER,
        textColor=risk_color,
        fontName='Helvetica-Bold'
    )
    
    story.append(Paragraph(f"RISK LEVEL: {risk_level}", risk_style))
    story.append(Spacer(1, 20))
    
    # Key findings
    story.append(Paragraph("Key Findings", styles['Heading2']))
    
    findings = [
        f"• Total vulnerabilities identified: {len(vulnerabilities)}",
        f"• High-risk vulnerabilities: {high_vulns}",
        f"• Medium-risk vulnerabilities: {medium_vulns}",
        f"• Low-risk vulnerabilities: {low_vulns}",
        f"• Scan completed on: {scan.get('end_time', 'N/A')}"
    ]
    
    for finding in findings:
        story.append(Paragraph(finding, styles['Normal']))
        story.append(Spacer(1, 6))
    
    story.append(Spacer(1, 20))
    
    # Recommendations
    story.append(Paragraph("Immediate Actions Required", styles['Heading2']))
    
    if high_vulns > 0:
        story.append(Paragraph("• Address all high-risk vulnerabilities immediately", styles['Normal']))
        story.append(Paragraph("• Implement additional security monitoring", styles['Normal']))
        story.append(Paragraph("• Consider engaging security experts for remediation", styles['Normal']))
    elif medium_vulns > 0:
        story.append(Paragraph("• Plan remediation for medium-risk vulnerabilities", styles['Normal']))
        story.append(Paragraph("• Review and update security policies", styles['Normal']))
    else:
        story.append(Paragraph("• Maintain current security posture", styles['Normal']))
        story.append(Paragraph("• Continue regular security assessments", styles['Normal']))
    
    # Build PDF
    doc.build(story)

def _generate_compliance_report(pdf_path, scan, vulnerabilities):
    """Generate compliance-focused report."""
    doc = SimpleDocTemplate(pdf_path, pagesize=A4)
    styles = getSampleStyleSheet()
    story = []
    
    # Title
    story.append(Paragraph("Security Compliance Assessment Report", styles['Title']))
    story.append(Spacer(1, 30))
    
    # Compliance frameworks
    story.append(Paragraph("Compliance Framework Assessment", styles['Heading2']))
    
    # OWASP Top 10 compliance
    owasp_findings = [v for v in vulnerabilities if 'owasp' in v.get('title', '').lower()]
    
    compliance_data = [
        ['Framework', 'Status', 'Issues Found'],
        ['OWASP Top 10', 'Non-Compliant' if owasp_findings else 'Compliant', str(len(owasp_findings))],
        ['PCI DSS', 'Requires Review', 'Manual assessment needed'],
        ['ISO 27001', 'Partial Compliance', 'Documentation review required']
    ]
    
    compliance_table = Table(compliance_data, colWidths=[2*inch, 2*inch, 2*inch])
    compliance_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 12),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    
    story.append(compliance_table)
    
    # Build PDF
    doc.build(story)

@celery_app.task
def send_report_email(report_id, recipient_email, scan_id):
    """
    Send generated report via email.
    
    Args:
        report_id: Report identifier
        recipient_email: Email address to send to
        scan_id: Associated scan ID
        
    Returns:
        dict: Email sending results
    """
    try:
        logger.info(f"Sending report {report_id} to {recipient_email}")
        
        from app import mail
        
        db = get_db()
        
        # Get report data
        report = db.reports.find_one({"_id": report_id})
        if not report:
            raise ValueError(f"Report {report_id} not found")
        
        # Get scan data
        scan = db.scans.find_one({"_id": scan_id})
        
        # Create email message
        subject = f"InfoSentinel Security Report - {scan.get('target', 'Unknown Target')}"
        
        body = f"""
        Dear Security Team,
        
        Please find attached the security assessment report for the scan completed on {scan.get('end_time', 'Unknown')}.
        
        Scan Details:
        - Target: {scan.get('target', 'N/A')}
        - Scan Type: {scan.get('scan_type', 'N/A')}
        - Status: {scan.get('status', 'N/A')}
        - Vulnerabilities Found: {scan.get('vulnerability_count', 0)}
        
        Please review the attached report and take appropriate action for any identified vulnerabilities.
        
        Best regards,
        InfoSentinel Security Platform
        """
        
        msg = Message(
            subject=subject,
            recipients=[recipient_email],
            body=body
        )
        
        # Attach PDF report (in production, retrieve from storage)
        # msg.attach(filename=f"security_report_{scan_id}.pdf", content_type="application/pdf", data=pdf_data)
        
        # Send email
        mail.send(msg)
        
        # Update report status
        db.reports.update_one(
            {"_id": report_id},
            {
                "$set": {
                    "email_sent": True,
                    "email_sent_at": datetime.utcnow(),
                    "recipient": recipient_email
                }
            }
        )
        
        logger.info(f"Report {report_id} sent successfully to {recipient_email}")
        
        return {
            "report_id": str(report_id),
            "recipient": recipient_email,
            "sent_at": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error sending report {report_id} to {recipient_email}: {str(e)}")
        raise

@celery_app.task
def generate_scheduled_reports():
    """
    Generate reports for scheduled scans.
    
    Returns:
        dict: Generation results
    """
    try:
        logger.info("Generating scheduled reports")
        
        db = get_db()
        
        # Find completed scans without reports
        scans_without_reports = db.scans.find({
            "status": "completed",
            "report_generated": {"$ne": True}
        })
        
        reports_generated = 0
        
        for scan in scans_without_reports:
            try:
                # Generate standard report
                result = generate_pdf_report.delay(scan["_id"], "standard")
                
                # Mark scan as having report generated
                db.scans.update_one(
                    {"_id": scan["_id"]},
                    {"$set": {"report_generated": True}}
                )
                
                reports_generated += 1
                
            except Exception as e:
                logger.error(f"Error generating report for scan {scan['_id']}: {str(e)}")
        
        logger.info(f"Generated {reports_generated} scheduled reports")
        
        return {
            "reports_generated": reports_generated
        }
        
    except Exception as e:
        logger.error(f"Error generating scheduled reports: {str(e)}")
        raise