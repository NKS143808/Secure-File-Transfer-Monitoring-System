from io import BytesIO
from datetime import datetime,timezone
from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate,Paragraph,Spacer,Table,TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
def pdf_report(ev,al):
    b=BytesIO();s=getSampleStyleSheet();bad=[x for x in ev if x.get("status")=="Suspicious"]
    story=[Paragraph("Secure File Transfer Monitoring System",s["Title"]),Paragraph("Security Audit Report",s["Heading2"]),Paragraph("Generated: "+datetime.now(timezone.utc).isoformat(),s["Normal"]),Spacer(1,14)]
    t=Table([["Metric","Count"],["Total events",str(len(ev))],["Suspicious events",str(len(bad))],["Alerts",str(len(al))]],colWidths=[250,80])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#172554")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),.5,colors.grey),("PADDING",(0,0),(-1,-1),7)]))
    story += [t,Spacer(1,14),Paragraph("Recent suspicious events",s["Heading2"])]
    for x in bad[-15:]:story.append(Paragraph((str(x.get("timestamp",""))+" | "+str(x.get("event_type",""))+" | "+str(x.get("source_path",""))).replace("&","&amp;"),s["BodyText"]))
    story += [Spacer(1,10),Paragraph("Recommendations",s["Heading2"]),Paragraph("Review high-risk events, keep sensitive files in approved locations, maintain backups and verify important file hashes.",s["BodyText"]),Spacer(1,8),Paragraph("Scope: this report summarizes observed events only. It does not prove that all USB, network, browser or cloud transfers were detected.",s["Italic"])]
    SimpleDocTemplate(b,pagesize=A4).build(story);return b.getvalue()
