import streamlit as st, pandas as pd, plotly.express as px
from pathlib import Path
from src.database import init_db, events, alerts, add_event, add_alert, baselines, save_baseline
from src.monitor import start_monitoring, stop_monitoring, running
from src.integrity import sha256_file
from src.reports import pdf_report
from src.policy import sensitive
st.set_page_config(page_title="Secure File Transfer Monitor",page_icon="🛡️",layout="wide")
st.title("🛡️ Secure File Transfer Monitoring System")
st.caption("Local-first defensive file monitoring and SHA-256 integrity auditing")
init_db()
with st.sidebar:
    page=st.radio("Navigation",["Dashboard","File Monitoring","Sensitive File Policy","Integrity Checker","Security Alerts","Audit Logs","Reports","Settings"])
    st.write("Watcher:", "🟢 Running" if running() else "⚪ Stopped")
def df_events():
    rows=events()
    return pd.DataFrame(rows) if rows else pd.DataFrame(columns=["id","timestamp","event_type","source_path","destination_path","sha256","risk_level","status","details"])
if page=="Dashboard":
    d=df_events(); n=len(d); bad=int((d.status=="Suspicious").sum()) if n else 0
    a,b,c,e=st.columns(4); a.metric("Total events",n); b.metric("Normal",n-bad); c.metric("Suspicious",bad); e.metric("Integrity failures",int((d.event_type=="INTEGRITY_FAILURE").sum()) if n else 0)
    if n:
        x,y=st.columns(2)
        x.plotly_chart(px.histogram(d,x="event_type",color="risk_level"),use_container_width=True)
        y.plotly_chart(px.pie(d,names="risk_level",hole=.4),use_container_width=True)
        st.dataframe(d.tail(25).iloc[::-1],use_container_width=True,hide_index=True)
    else: st.info("No events. Start monitoring a folder.")
    st.subheader("Recent alerts"); st.dataframe(pd.DataFrame(alerts()[-10:][::-1]),use_container_width=True,hide_index=True)
elif page=="File Monitoring":
    folder=st.text_input("Folder to monitor",str(Path.home()/"Documents"))
    recursive=st.checkbox("Include subfolders",True)
    if st.button("Start monitoring",type="primary"):
        p=Path(folder).expanduser()
        if p.is_dir():
            try: start_monitoring(str(p.resolve()),recursive,st.session_state.get("policy",{})); st.success("Monitoring started.")
            except Exception as ex: st.error(str(ex))
        else: st.error("Enter an existing folder.")
    if st.button("Stop monitoring"): stop_monitoring(); st.success("Stopped.")
    st.warning("Run locally to monitor this computer. Streamlit Cloud cannot access your laptop folders.")
elif page=="Sensitive File Policy":
    ex=st.text_input("Sensitive extensions", ".pem,.key,.env,.sql,.db,.xlsx")
    kw=st.text_input("Sensitive filename keywords","password,secret,confidential,customer")
    al=st.text_area("Allowed destination folders (one path per line)",str(Path.home()/"Documents"))
    st.session_state["policy"]={"extensions":[x.strip().lower() for x in ex.split(",") if x.strip()],"keywords":[x.strip().lower() for x in kw.split(",") if x.strip()],"allowed":[x.strip() for x in al.splitlines() if x.strip()]}
    st.success("Policy saved for this app session; restart resets it.")
elif page=="Integrity Checker":
    path=st.text_input("File path")
    if st.button("Check / create baseline"):
        p=Path(path).expanduser()
        if p.is_file():
            key=str(p.resolve()); digest=sha256_file(p); old=baselines().get(key)
            if old is None: save_baseline(key,digest); st.success("Baseline saved.")
            elif old==digest: st.success("Integrity verified.")
            else: add_event("INTEGRITY_FAILURE",key,"",digest,"HIGH","Suspicious","SHA-256 mismatch"); add_alert("HIGH","Integrity mismatch",key,"Hash differs from baseline"); st.error("Integrity failure.")
            st.code(digest)
        else: st.error("File not found.")
elif page=="Security Alerts":
    st.dataframe(pd.DataFrame(alerts()).iloc[::-1],use_container_width=True,hide_index=True)
elif page=="Audit Logs":
    d=df_events(); q=st.text_input("Search logs")
    if q and not d.empty: d=d[d.astype(str).apply(lambda c:c.str.contains(q,case=False,na=False)).any(axis=1)]
    st.dataframe(d.iloc[::-1],use_container_width=True,hide_index=True)
    if not d.empty:
        st.download_button("Export CSV",d.to_csv(index=False).encode(),"audit.csv","text/csv")
        st.download_button("Export JSON",d.to_json(orient="records",indent=2).encode(),"audit.json","application/json")
elif page=="Reports":
    if st.button("Generate PDF report",type="primary"): st.download_button("Download PDF",pdf_report(events(),alerts()),"security_audit_report.pdf","application/pdf")
elif page=="Settings":
    st.markdown("Only explicitly selected folders are monitored. Files are never executed or uploaded. Hashes and metadata are stored locally. Filesystem watchers may miss/coalesce events. USB, network, browser and cloud exfiltration are not comprehensively detected. Alerts require human review.")
