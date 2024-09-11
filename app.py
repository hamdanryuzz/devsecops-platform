import streamlit as st
import requests
import json
import pandas as pd
import math
import time

# CSS untuk memperbesar tombol
button_style = """
    <style>
    .stButton > button {
        font-size: 20px;  /* Ukuran font tombol */
    }
    </style>
"""

# Pengaturan halaman
st.set_page_config(page_title="Development Security Operations Platform", layout="centered")

def main_page():
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Development Security Operations Platform")
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        if st.button("SCA"):
            st.session_state.page = "sca_page"
    with col2:
        if st.button("SAST"):
            st.session_state.page = "sast_page"
    with col3:
        if st.button("DAST"):
            st.session_state.page = "dast_page"
    with col4:
        if st.button("RAPS"):
            st.session_state.page = "raps_page"

def sca_page():
    if st.button("Back"):
        st.session_state.page = "main_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Software Composition Analysis")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sonarqube"):
            st.write("You clicked Sonarqube.")
    with col2:
        if st.button("Checkmarx"):
            st.session_state.page = "sca_checkmarx_dashboard"

def sast_page():
    if st.button("Back"):
        st.session_state.page = "main_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Static Application Security Testing")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sonarqube"):
            st.write("You clicked Sonarqube.")
    with col2:
        if st.button("Checkmarx"):
            st.session_state.page = "checkmarx_dashboard"

def dast_page():
    if st.button("Back"):
        st.session_state.page = "main_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Dynamic Application Security Testing")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sonarqube"):
            st.write("You clicked Sonarqube.")
    with col2:
        if st.button("Checkmarx"):
            st.write("You clicked Checkmarx.")

def raps_page():
    if st.button("Back"):
        st.session_state.page = "main_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("RAPS")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Sonarqube"):
            st.write("You clicked Sonarqube.")
    with col2:
        if st.button("Checkmarx"):
            st.write("You clicked Checkmarx.")

def checkmarx_dashboard():
    if st.button("Back"):
        st.session_state.page = "sast_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Checkmarx Dashboard")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("List Project SAST"):
            st.session_state.page = "sast_page_checkmarx_list"
    with col2:
        if st.button("New Scan Project SAST"):
            st.session_state.page = "sast_page_checkmarx_scan"

def sca_checkmarx_dashboard():
    if st.button("Back"):
        st.session_state.page = "sca_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("SCA Checkmarx Dashboard")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("List Project SCA"):
            st.session_state.page = "sca_page_checkmarx_list"
    with col2:
        if st.button("New Scan Project SCA"):
            # st.session_state.page = "sast_page_checkmarx_scan"
            st.write("SCA Scan")

def sast_page_checkmarx():
    if st.button("Back"):
        st.session_state.page = "sast_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Checkmarx SAST")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Scan"):
            st.session_state.page = "sast_page_checkmarx_scan"
    with col2:
        if st.button('Result'):
            st.session_state.page = "sast_page_checkmarx_result"

def get_access_token():
    tenant_name = "ptsthree-nfr"
    client_id = "Testing"
    client_secret = "53sFLsmmtmbVDITsv79wHXrA0OuCbagF"

    url = f"https://sng.iam.checkmarx.net/auth/realms/{tenant_name}/protocol/openid-connect/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    data = {
        "client_id": client_id,
        "grant_type": "client_credentials",
        "client_secret": client_secret
    }

    response = requests.post(url, headers=headers, data=data)

    if response.status_code == 200:
        token_data = response.json()
        access_token = token_data.get("access_token")
        if access_token:
            return access_token
        else:
            st.error("Access token tidak ditemukan dalam respons.")
    else:
        st.error(f"Terjadi kesalahan. Status code: {response.status_code}")
        st.json(response.json())
    return None

def fetch_sast_results(access_token, scan_id, show_query, show_language,show_severity):
    url = "https://sng.ast.checkmarx.net/api/sast-results/"
    querystring = {"scan-id": scan_id, "limit": str(10000)}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json",
        "request-data": json.dumps({
            "visible-columns": ["severity", "query-name", "language", "status", "source-node", "sink-file", "source-file", "sink-node"],
            "include-nodes": ["true"],
            "apply-predicates": ["true"]
        })
    }

    try:
        response = requests.get(url, headers=headers, params=querystring)

        if response.status_code == 200:
            data = response.json()
            df = pd.DataFrame(data["results"])

            df = df.reindex(columns=[
                'queryName',
                'severity',
                'status',
                'sourceNode',
                'sourceFileName',
                'sinkNode',
                'sinkFileName',
                'languageName',
            ])
            df = df.rename(columns={
                'queryName': 'Vulnerabilty',
                'status': 'Status',
                'sourceNode': 'Source Node',
                'sourceFileName': 'Source File',
                'sinkNode': 'Sink Node',
                'sinkFileName': 'Sink File',
                'languageName': 'Language',
                'severity': 'Severity'
            })

            total_data = len(df)
            st.write(f"**Total Vulnerabilty: {total_data}**")

            if show_query and not show_severity and not show_language:
                grouped = df.groupby('Vulnerabilty').size()
                for query_name, count in grouped.items():
                    with st.expander(f"{query_name} ({count}) >"):
                        st.write(df[df['Vulnerabilty'] == query_name])

            elif show_language and not show_query and not show_severity:
                grouped = df.groupby('Language').size()
                for lang, count in grouped.items():
                    with st.expander(f"{lang} ({count}) >"):
                        st.write(df[df['Language'] == lang])
            
            elif show_severity and not show_language and not show_query:
                grouped = df.groupby('Severity').size()
                for severity, count in grouped.items():
                    with st.expander(f"{severity} ({count}) >"):
                        st.write(df[df['Severity'] == severity])
                        

            elif show_query and show_language and not show_severity:
                grouped_query = df.groupby('Vulnerabilty')

                for query_name, group in grouped_query:
                    grouped_lang = group.groupby('Language').size()

                    for lang, lang_count in grouped_lang.items():
                        with st.expander(f"{query_name} > {lang} > {lang_count} item >"):
                            st.write(group[group['Language'] == lang])

            elif show_language and show_severity and not show_query:
                # Mengelompokkan data berdasarkan Language terlebih dahulu
                grouped_lang = df.groupby('Language')

                for lang, group in grouped_lang:
                    # Di dalam setiap Language, kelompokkan lagi berdasarkan Severity
                    grouped_severity = group.groupby('Severity')

                    for severity, severity_group in grouped_severity:
                        # Tampilkan expander dengan format lang_name > severity
                        with st.expander(f"{lang} > {severity}"):
                            st.write(severity_group)

            elif show_query and show_severity and not show_language:
                # Mengelompokkan data berdasarkan Language terlebih dahulu
                grouped_query = df.groupby('Vulnerabilty')

                for query, group in grouped_query:
                    # Di dalam setiap queryuage, kelompokkan lagi berdasarkan Severity
                    grouped_severity = group.groupby('Severity')

                    for severity, severity_group in grouped_severity:
                        # Tampilkan expander dengan format query_name > severity
                        with st.expander(f"{query} > {severity}"):
                            st.write(severity_group)

            elif show_query and show_severity and show_language:
                # Mengelompokkan data berdasarkan query_name terlebih dahulu
                grouped_query = df.groupby('Vulnerabilty')

                for query_name, query_group in grouped_query:
                    # Di dalam setiap query_name, kelompokkan lagi berdasarkan Language
                    grouped_language = query_group.groupby('Language')

                    for language, language_group in grouped_language:
                        # Di dalam setiap Language, kelompokkan lagi berdasarkan Severity
                        grouped_severity = language_group.groupby('Severity')

                        for severity, severity_group in grouped_severity:
                            # Tampilkan expander dengan format query_name > language > severity
                            with st.expander(f"{query_name} > {language} > {severity}"):
                                st.write(severity_group)

            else:
                # Dropdown untuk memilih jumlah item per halaman
                items_per_page = st.selectbox('Items per page', [5, 10, 20, 50, 100], index=1)

                # Hitung total halaman berdasarkan jumlah item per halaman yang dipilih
                total_pages = math.ceil(total_data / items_per_page)
                
                # Pagination controls
                page = st.number_input('Page', min_value=1, max_value=total_pages, step=1)

                # Indexing untuk pagination
                start_idx = (page - 1) * items_per_page
                end_idx = min(start_idx + items_per_page, total_data)

                # Display tabel dengan pagination
                st.dataframe(df.iloc[start_idx:end_idx])

            st.success("Data fetched successfully.")
        else:
            st.error(f"Error fetching data: {response.status_code}")
    except Exception as e:
        st.error(f"An error occurred: {str(e)}")

def check_scan_status(scan_id, access_token):
    # URL untuk mendapatkan status scan
    url = f"https://sng.ast.checkmarx.net/api/scans/{scan_id}"

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""  # Bisa ditambahkan jika diperlukan
    }

    # Mengirim GET request untuk mendapatkan status scan
    response = requests.get(url, headers=headers)
    return response.json()

def sast_page_checkmarx_scan():
    if st.button("Back"):
        st.session_state.page = "checkmarx_dashboard"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Scan Checkmarx SAST")

    # Refresh Token Button
    if st.button("Refresh Token"):
        access_token = get_access_token()
        if access_token:
            st.session_state['access_token'] = access_token
            st.success("Token refreshed successfully.")

    # Form input untuk data project
    with st.form(key='scan_form'):
        project_id = st.text_input("Project ID")
        repo_url = st.text_input("Repo URL")
        username = st.text_input("Username")
        api_key = st.text_input("API Key", type="password")  # Hide API Key input

        submit_button = st.form_submit_button("Submit Scan Request")

        if submit_button:
            if 'access_token' not in st.session_state:
                st.error("Access token is not available. Please refresh the token.")
            else:
                headers = {
                    "Authorization": f"Bearer {st.session_state['access_token']}",
                    "Accept": "application/json; version=1.0",
                    "Content-Type": "application/json"
                }

                payload = {
                    "project": {
                        "id": project_id,
                    },
                    "type": "git",
                    "handler": {
                        "repoUrl": repo_url,
                        "branch": "master",
                        "credentials": {
                            "username": username,
                            "type": "apiKey",
                            "value": api_key
                        }
                    },
                    "tags": {
                        "ScanTag01": "",
                        "ScanSeverity": "high"
                    },
                    "config": [
                        {
                            "type": "sast",
                            "value": {
                                "incremental": "false",
                                "presetName": "Checkmarx Default",
                                "engineVerbose": "false"
                            }
                        },
                    ]
                }

                # URL endpoint API
                url = "https://sng.ast.checkmarx.net/api/scans/"

                # Mengirim POST request untuk memulai scan
                response = requests.post(url, data=json.dumps(payload), headers=headers)

                if response.status_code == 201:
                    # Ambil ID scan dari respons
                    response_data = response.json()
                    scan_id = response_data.get('id')

                    if scan_id:
                        st.success("Scan request submitted successfully. Waiting for scan to complete...")

                        # Animasi loading selama proses scan
                        with st.spinner("Scan is in progress..."):
                            scan_status = ""
                            while scan_status != "Completed":
                                # Memeriksa status scan setiap 5 detik
                                status_response = check_scan_status(scan_id, st.session_state['access_token'])
                                scan_status = status_response.get('status', '')

                                # Jika scan belum selesai, tunggu 5 detik
                                if scan_status != "Completed":
                                    time.sleep(5)

                        # Setelah status "Completed", tampilkan ID
                        st.success(f"Scan completed! Scan ID: {scan_id}")
                    else:
                        st.error("Failed to retrieve scan ID.")
                else:
                    st.error(f"Failed to submit scan request: {response.status_code}")
                    st.json(response.json())

def get_projects():
    access_token = get_access_token()
    if not access_token:
        return []

    url = "https://sng.ast.checkmarx.net/api/projects/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""
    }
    response = requests.get(url, headers=headers)

    # Cek apakah respons JSON valid
    try:
        data = response.json()
        projects = data.get('projects', [])
        return projects
    except ValueError:
        st.error("Gagal mengurai respons JSON.")
        return []

def get_scans_by_project_id(project_id):
    access_token = get_access_token()
    if not access_token:
        return []

    url = "https://sng.ast.checkmarx.net/api/scans/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""
    }
    response = requests.get(url, headers=headers)

    # Cek apakah respons JSON valid
    try:
        data = response.json()
        scans = data.get('scans', [])
        # Filter hanya untuk scan dengan 'type': 'sast' dan project_id yang sesuai
        filtered_scans = [scan for scan in scans if scan['metadata']['configs'][0]['type'] == 'sast' and scan['projectId'] == project_id]
        return filtered_scans
    except ValueError:
        st.error("Gagal mengurai respons JSON.")
        return []

def sca_get_scans_by_project_id(project_id):
    access_token = get_access_token()
    if not access_token:
        return []

    url = "https://sng.ast.checkmarx.net/api/scans/"
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""
    }
    response = requests.get(url, headers=headers)

    # Cek apakah respons JSON valid
    try:
        data = response.json()
        scans = data.get('scans', [])
        # Filter hanya untuk scan dengan 'type': 'sast' dan project_id yang sesuai
        filtered_scans = [scan for scan in scans if scan['metadata']['configs'][0]['type'] == 'sca' and scan['projectId'] == project_id]
        return filtered_scans
    except ValueError:
        st.error("Gagal mengurai respons JSON.")
        return []
                         
def get_scan_results(scan_id):
    access_token = get_access_token()
    if not access_token:
        return []  # Pastikan selalu mengembalikan list kosong jika tidak ada token

    url = f"https://sng.ast.checkmarx.net/api/sast-results/"
    querystring = {"scan-id": scan_id, "limit": "10000"}

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""
    }

    response = requests.get(url, headers=headers, params=querystring)
    
    if response.status_code == 200:
        data = response.json()
        return data.get("results", [])  # Pastikan mengembalikan list, bukan None
    else:
        st.error(f"Failed to fetch scan results. Status code: {response.status_code}")
        return []  # Jika gagal, kembalikan list kosong
    
def count_severity(scan_results):
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    # Tambahkan pemeriksaan jika scan_results adalah list kosong
    if not scan_results:
        return severity_counts
    
    for result in scan_results:
        severity = result.get("severity", "").upper()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    return severity_counts

def get_sca_scan_result(scan_id):
    access_token = get_access_token()
    if not access_token:
        return []  # Pastikan selalu mengembalikan list kosong jika tidak ada token

    # URL untuk API scan summary
    url = "https://sng.ast.checkmarx.net/api/scan-summary"
    
    # Parameter query untuk API
    querystring = {
        "scan-ids": scan_id,
        "include-queries": "false",
        "include-status-counters": "false",
        "include-files": "false"
    }
    
    # Headers, termasuk JWT access token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "application/json; version=1.0",
        "CorrelationId": ""
    }
    
    # Mengirim permintaan GET ke API
    response = requests.get(url, headers=headers, params=querystring)
    
    if response.status_code == 200:
        data = response.json()
        return data.get("scansSummaries",[]) # Kembalikan list dari severityCounters
    else:
        # Jika gagal, tampilkan pesan error dan kembalikan list kosong
        print(f"Failed to fetch SCA scan results. Status code: {response.status_code}")
        return []

def sca_count_severity(scan_results):
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    # Tambahkan pemeriksaan jika scan_results adalah list kosong
    if not scan_results:
        return severity_counts
    
    for result in scan_results:
        sca_counters = result.get('scaCounters', {})
        severity_counters = sca_counters.get('severityCounters', [])
        
        for severity_data in severity_counters:
            severity = severity_data.get("severity", "").upper()
            if severity in severity_counts:
                severity_counts[severity] += severity_data.get("counter", 0)
    
    return severity_counts


def sast_page_checkmarx_list():
    if st.button("Back"):
        st.session_state.page = "checkmarx_dashboard"
    
    st.title("List Project Checkmarx SAST")

    # Ambil daftar project
    projects = get_projects()

    if projects:
        st.subheader("Daftar Project:")
        for project in projects:
            if 'id' in project and 'name' in project:
                with st.expander(f"Project: {project['name']} (ID: {project['id']})"):
                    scans = get_scans_by_project_id(project['id'])

                    if scans:
                        scan_data = []
                        for scan in scans:
                            # Ambil hasil scan berdasarkan scan ID
                            scan_results = get_scan_results(scan['id'])
                            # st.write(scan_results)
                            # Hitung severity
                            severity_counts = count_severity(scan_results)
                            # st.write(severity_counts)

                            # Format data scan ke bentuk dictionary
                            scan_data.append({
                                "Scan ID": scan['id'], 
                                "Type": scan['metadata']['configs'][0]['type'], 
                                "Status": scan['status'],
                                "Created At": scan['createdAt'],
                                "High Severity": severity_counts['HIGH'],
                                "Medium Severity": severity_counts['MEDIUM'],
                                "Low Severity": severity_counts['LOW']
                            })
                        
                        # Urutkan berdasarkan tanggal (Created At) secara descending
                        scan_data = sorted(scan_data, key=lambda x: x['Created At'], reverse=True)
                        
                        # Header Tabel
                        col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns([2, 2, 2, 2, 2, 2, 2, 3,3])
                        with col1:
                            st.write("Scan ID")
                        with col2:
                            st.write("Type")
                        with col3:
                            st.write("Status")
                        with col4:
                            st.write("Created At")
                        with col5:
                            st.write("High Severity")
                        with col6:
                            st.write("Medium Severity")
                        with col7:
                            st.write("Low Severity")
                        with col8:
                            st.write("Action")
                        with col9:
                            st.write("Action")

                        # Isi Tabel
                        for scan in scan_data:
                            scan_id = scan['Scan ID']
                            project_id = project['id']
                            col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns([2, 2, 2, 2, 2, 2, 2, 3,3])
                            with col1:
                                st.write(scan['Scan ID'])
                            with col2:
                                st.write(scan['Type'])
                            with col3:
                                st.write(scan['Status'])
                            with col4:
                                st.write(scan['Created At'])
                            with col5:
                                st.write(scan['High Severity'])
                            with col6:
                                st.write(scan['Medium Severity'])
                            with col7:
                                st.write(scan['Low Severity'])
                            with col8:
                                if st.button(f"Result", key=f"result_{scan_id}"):
                                    # Ambil access token baru saat tombol diklik
                                    access_token = get_access_token()
                                    if access_token:
                                        # Simpan scan_id dan access_token ke session_state
                                        st.session_state.scan_id = scan_id
                                        st.session_state.access_token = access_token
                                        # Arahkan ke halaman hasil
                                        st.session_state.page = "sast_page_checkmarx_result"
                                    # Tidak perlu st.experimental_rerun()
                            with col9:
                                if st.button(f"Report", key=f"report_{scan_id}"):
                                    access_token = get_access_token()
                                    # Simpan scan_id, project_id, dan access_token ke session_state
                                    st.session_state.scan_id = scan_id
                                    st.session_state.project_id = project_id
                                    st.session_state.access_token = access_token                                    # Arahkan ke halaman report
                                    st.session_state.page = "sast_page_checkmarx_report"

                    else:
                        st.write("No SAST scans found for this project.")

def sca_page_checkmarx_list():
    if st.button("Back"):
        st.session_state.page = "sca_checkmarx_dashboard"
    
    st.title("List Project Checkmarx SCA")

    # Ambil daftar project
    projects = get_projects()

    if projects:
        st.subheader("Daftar Project:")
        for project in projects:
            if 'id' in project and 'name' in project:
                with st.expander(f"Project: {project['name']} (ID: {project['id']})"):
                    scans = sca_get_scans_by_project_id(project['id'])
                    # st.write(scans)
                    if scans:
                        scan_data = []
                        for scan in scans:
                            # Ambil hasil scan berdasarkan scan ID
                            scan_results = get_sca_scan_result(scan['id'])
                            # st.write(scan_results)
                            # Hitung severity
                            severity_counts = sca_count_severity(scan_results)
                            # st.write(severity_counts)
                            # Format data scan ke bentuk dictionary
                            scan_data.append({
                                "Scan ID": scan['id'], 
                                "Type": scan['metadata']['configs'][0]['type'], 
                                "Status": scan['status'],
                                "Created At": scan['createdAt'],
                                "High Severity": severity_counts['HIGH'],
                                "Medium Severity": severity_counts['MEDIUM'],
                                "Low Severity": severity_counts['LOW']
                            })
                        
                        # Urutkan berdasarkan tanggal (Created At) secara descending
                        scan_data = sorted(scan_data, key=lambda x: x['Created At'], reverse=True)
                        
                        # Header Tabel
                        col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns([2, 2, 2, 2, 2, 2, 2, 3,3])
                        with col1:
                            st.write("Scan ID")
                        with col2:
                            st.write("Type")
                        with col3:
                            st.write("Status")
                        with col4:
                            st.write("Created At")
                        with col5:
                            st.write("High Severity")
                        with col6:
                            st.write("Medium Severity")
                        with col7:
                            st.write("Low Severity")
                        with col8:
                            st.write("Action")
                        with col9:
                            st.write("Action")

                        # Isi Tabel
                        for scan in scan_data:
                            scan_id = scan['Scan ID']
                            project_id = project['id']
                            col1, col2, col3, col4, col5, col6, col7, col8, col9 = st.columns([2, 2, 2, 2, 2, 2, 2, 3,3])
                            with col1:
                                st.write(scan['Scan ID'])
                            with col2:
                                st.write(scan['Type'])
                            with col3:
                                st.write(scan['Status'])
                            with col4:
                                st.write(scan['Created At'])
                            with col5:
                                st.write(scan['High Severity'])
                            with col6:
                                st.write(scan['Medium Severity'])
                            with col7:
                                st.write(scan['Low Severity'])
                            with col8:
                                if st.button(f"Result", key=f"result_{scan_id}"):
                                    # Ambil access token baru saat tombol diklik
                                    access_token = get_access_token()
                                    if access_token:
                                        access_token = get_access_token()
                                        # Simpan scan_id, project_id, dan access_token ke session_state
                                        st.session_state.scan_id = scan_id
                                        st.session_state.project_id = project_id
                                        st.session_state.access_token = access_token 
                                        # Arahkan ke halaman hasil
                                        st.session_state.page = "sca_page_checkmarx_result"
                                    # Tidak perlu st.experimental_rerun()
                            with col9:
                                if st.button(f"Report", key=f"report_{scan_id}"):
                                    access_token = get_access_token()
                                    # Simpan scan_id, project_id, dan access_token ke session_state
                                    st.session_state.scan_id = scan_id
                                    st.session_state.project_id = project_id
                                    st.session_state.access_token = access_token 
                                    # Arahkan ke halaman report
                                    st.session_state.page = "sca_page_checkmarx_report"

                    else:
                        st.write("No SCA scans found for this project.")

def sast_page_checkmarx_report():
    if st.button("Back"):
        st.session_state.page = "checkmarx_dashboard"

    st.title("Generate Report Checkmarx SAST")

    # Ambil access token, scan_id, dan project_id dari session state
    access_token = st.session_state.get('access_token', '')
    scan_id = st.session_state.get('scan_id', '')
    project_id = st.session_state.get('project_id', '')
    st.write(access_token)


    # Tampilkan Scan ID dan Project ID yang terpilih
    if scan_id and project_id:
        st.write(f"Generating report for Scan ID: {scan_id} and Project ID: {project_id}")

        email = st.text_input("Email recipient", value="recipient@example.com")
        file_format = st.selectbox("File format", options=["pdf", "json", "csv"])
        
        if st.button("Generate Report"):
            # Panggil API untuk membuat report
            sca_create_report(scan_id, project_id, email, file_format, access_token)
    else:
        st.write("Missing scan ID or project ID.")

def sca_page_checkmarx_report():
    if st.button("Back"):
        st.session_state.page = "sca_checkmarx_dashboard"

    st.title("Generate Report Checkmarx SCA")

    # Ambil access token, scan_id, dan project_id dari session state
    access_token = st.session_state.get('access_token', '')
    scan_id = st.session_state.get('scan_id', '')
    project_id = st.session_state.get('project_id', '')


    # Tampilkan Scan ID dan Project ID yang terpilih
    if scan_id and project_id:
        st.write(f"Generating report for Scan ID: {scan_id} and Project ID: {project_id}")

        email = st.text_input("Email recipient", value="recipient@example.com")
        file_format = st.selectbox("File format", options=["pdf", "json", "csv"])
        
        if st.button("Generate Report"):
            # Panggil API untuk membuat report
            sca_create_report(scan_id, project_id, email, file_format, access_token)
    else:
        st.write("Missing scan ID or project ID.")

def create_report(scan_id, project_id, email, file_format, access_token):
    url = "https://sng.ast.checkmarx.net/api/reports"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "*/*; version=1.0",
    }

    data = {
        "reportName": "improved-scan-report",
        "fileFormat": file_format,  # Bisa "pdf", "json", atau "csv"
        "reportType": "email",  # Bisa "cli", "ui", atau "email"
        "data": {
            "scanId": scan_id,  # Scan ID yang sesuai
            "projectId": project_id,  # Project ID yang sesuai
            "branchName": "main",  # Nama branch jika diperlukan
            "sections": ["scan-information", "results-overview", "scan-results"],  # Bagian yang ingin disertakan
            "scanners": ["SAST"],  # Scanner yang ingin disertakan
            "email": [email]  # Email penerima laporan
        }
    }

    # Melakukan POST request ke API
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 202:
        # Ambil reportId dari respon
        report_id = response.json().get("reportId")
        st.success(f"Report successfully generated! Report ID: {report_id}")
    else:
        st.error(f"Failed to generate report. Status code: {response.status_code}")
        st.write("Response:", response.text)

def sca_create_report(scan_id, project_id, email, file_format, access_token):
    url = "https://sng.ast.checkmarx.net/api/reports"
    
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Accept": "*/*; version=1.0",
    }

    data = {
        "reportName": "improved-scan-report",
        "fileFormat": file_format,  # Bisa "pdf", "json", atau "csv"
        "reportType": "email",  # Bisa "cli", "ui", atau "email"
        "data": {
            "scanId": scan_id,  # Scan ID yang sesuai
            "projectId": project_id,  # Project ID yang sesuai
            "branchName": "main",  # Nama branch jika diperlukan
            "sections": ["scan-information", "results-overview", "scan-results"],  # Bagian yang ingin disertakan
            "scanners": ["SCA"],  # Scanner yang ingin disertakan
            "email": [email]  # Email penerima laporan
        }
    }

    # Melakukan POST request ke API
    response = requests.post(url, headers=headers, json=data)

    if response.status_code == 202:
        # Ambil reportId dari respon
        report_id = response.json().get("reportId")
        st.success(f"Report successfully generated! Report ID: {report_id}")
    else:
        st.error(f"Failed to generate report. Status code: {response.status_code}")
        st.write("Response:", response.text)

def sast_page_checkmarx_result():
    if st.button("Back"):
        st.session_state.page = "checkmarx_dashboard"
    
    st.title("Result Checkmarx SAST")

    # Ambil access token dan scan_id dari session state
    access_token = st.session_state.get('access_token', '')
    scan_id = st.session_state.get('scan_id', '')

    # Tampilkan Scan ID yang terpilih
    if scan_id:
        st.write(f"Showing results for Scan ID: {scan_id}")
        
        # Checkbox untuk menampilkan filter
        show_query = st.checkbox("Vulnerability")
        show_language = st.checkbox("Language")
        show_severity = st.checkbox("Severity")

        # Fetch data secara otomatis tanpa harus refresh token
        if access_token and scan_id:
            fetch_sast_results(access_token, scan_id, show_query, show_language, show_severity)
        else:
            st.error("Missing access token or scan ID.")
    else:
        st.write("No scan ID selected.")

def sca_page_checkmarx_result():
    if st.button("Back"):
        st.session_state.page = "sca_checkmarx_dashboard"
    st.title("Result Checkmarx SCA")

    access_token = st.session_state.get('access_token', '')
    scan_id = st.session_state.get('scan_id', '')

    st.write(f"Scan ID: {scan_id}")

    # URL untuk membuat laporan
    create_report_url = "https://sng.ast.checkmarx.net/api/sca/export/requests"

    # Headers
    headers = {
        "Authorization": f"Bearer {access_token}",  # Ganti dengan token akses Anda
        "Content-Type": "application/json",
        "Accept": "application/json"
    }

    # Body parameters
    data = {
        "ScanId": scan_id,  # Menggunakan Scan ID dari session state
        "FileFormat": "ScanReportJson",  # Format laporan yang diinginkan
        "ExportParameters": {
            "hideDevAndTestDependencies": False,
            "showOnlyEffectiveLicenses": False,
            "excludePackages": False,
            "excludeLicenses": True,
            "excludeVulnerabilities": False,
            "excludePolicies": True
        }
    }

    # Mengirimkan request POST untuk membuat laporan
    response = requests.post(create_report_url, headers=headers, json=data)

    # Memeriksa status response untuk mendapatkan export_id
    if response.status_code == 202:
        export_id = response.json().get("exportId")
        st.write(f"Laporan berhasil dibuat. Export ID: {export_id}")
        
        # Memeriksa status export sampai "Completed"
        check_status_url = f"https://sng.ast.checkmarx.net/api/sca/export/requests?exportId={export_id}"

        # Menggunakan spinner sebagai animasi loading
        with st.spinner('Menunggu hingga laporan selesai...'):
            while True:
                status_response = requests.get(check_status_url, headers=headers)
                status_data = status_response.json()
                export_status = status_data.get('exportStatus')
                
                if export_status == "Completed":
                    st.success("Export Completed!")
                    file_url = status_data.get('fileUrl')
                    break
                elif export_status == "Failed":
                    st.error("Export gagal.")
                    return
                else:
                    time.sleep(5)  # Tunggu 5 detik sebelum pengecekan ulang

        # Mengunduh hasil laporan setelah status Completed
        download_url = file_url
        download_response = requests.get(download_url, headers=headers)

        if download_response.status_code == 200:
            report_data = download_response.json()  # Parsing JSON dari response

            # Membuat tabel untuk menampilkan hasil
            if "Packages" in report_data:
                packages = report_data["Packages"]
                results = [{
                    "Id": pkg["Id"],
                    "Name": pkg["Name"],
                    "Version": pkg["Version"],
                    "Licenses": ', '.join(pkg.get("Licenses", [])),
                    "MatchType": pkg.get("MatchType", ""),
                    "CriticalVulnerabilityCount": pkg.get("CriticalVulnerabilityCount", 0),
                    "HighVulnerabilityCount": pkg.get("HighVulnerabilityCount", 0),
                    "MediumVulnerabilityCount": pkg.get("MediumVulnerabilityCount", 0),
                    "LowVulnerabilityCount": pkg.get("LowVulnerabilityCount", 0)
                } for pkg in packages]

                # Menampilkan data dalam tabel menggunakan Streamlit
                st.table(results)
            else:
                st.write("Tidak ada data Packages yang ditemukan dalam laporan.")
        else:
            st.write(f"Terjadi kesalahan saat mengunduh laporan: {download_response.status_code} - {download_response.text}")

    else:
        st.write(f"Gagal membuat laporan. Status code: {response.status_code}")
        st.write("Response:", response.text)


def sast_page_checkmarx_result_group():
    if st.button("Back"):
        st.session_state.page = "sast_page_checkmarx"
    st.title("Result Checkmarx SAST")

    if st.button("Refresh Token"):
        access_token = get_access_token()
        if access_token:
            st.session_state['access_token'] = access_token
            st.success("Token refreshed successfully.")

    access_token = st.session_state.get('access_token', '')

    scan_id = st.text_input("Scan ID", "ee86f413-e659-4d59-8b09-67891142a9a5")

# Navigasi halaman berdasarkan session state
if 'page' not in st.session_state:
    st.session_state.page = 'main_page'

page_functions = {
    'main_page': main_page,
    'sca_page': sca_page,
    'sast_page': sast_page,
    'dast_page': dast_page,
    'raps_page': raps_page,
    'sast_page_checkmarx': sast_page_checkmarx,
    'sast_page_checkmarx_result': sast_page_checkmarx_result,
    'sast_page_checkmarx_result_group': sast_page_checkmarx_result_group,
    'sast_page_checkmarx_scan': sast_page_checkmarx_scan,
    'checkmarx_dashboard': checkmarx_dashboard,
    'sast_page_checkmarx_list': sast_page_checkmarx_list,
    'sast_page_checkmarx_report': sast_page_checkmarx_report,
    'sca_checkmarx_dashboard': sca_checkmarx_dashboard,
    'sca_page_checkmarx_list': sca_page_checkmarx_list,
    'sca_page_checkmarx_result': sca_page_checkmarx_result,
    'sca_page_checkmarx_report': sca_page_checkmarx_report
}

# Panggil fungsi yang sesuai berdasarkan halaman di session_state
page_function = page_functions.get(st.session_state.page, main_page)
page_function()
