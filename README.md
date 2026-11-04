# Secure File Transfer Monitoring System
## Run on Windows
1. Install Python 3.11+.
2. Extract ZIP and open Command Prompt in the folder.
3. Run: `python -m venv .venv`
4. Run: `.venv\\Scripts\\activate`
5. Run: `pip install -r requirements.txt`
6. Run: `streamlit run app.py`
7. Select an authorized folder in File Monitoring and click Start.
## Tests
`python -m unittest discover -s tests -v`
## Important limitations
The watcher runs in the same local Python process. Streamlit Community Cloud cannot monitor your personal laptop folders. Filesystem events may be missed/coalesced. This educational prototype does not comprehensively detect USB, network share, browser or cloud-sync transfers, nor reliably identify the user/process. UI policy settings are session-scoped. Alerts are indicators, not proof of malicious activity. Only monitor systems and folders you are authorized to monitor. File contents are not uploaded or stored.
