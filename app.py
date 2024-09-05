import streamlit as st
import requests
import json
import pandas as pd
import math

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
            st.write("You clicked Checkmarx.")

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
            st.session_state.page = "sast_page_checkmarx"

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

def sast_page_checkmarx():
    if st.button("Back"):
        st.session_state.page = "sast_page"
    st.markdown(button_style, unsafe_allow_html=True)  
    st.title("Checkmarx SAST")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Scan"):
            st.write('Scan')
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

import streamlit as st
import pandas as pd
import requests
import json
import math  # Tambahkan ini

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

def sast_page_checkmarx_result():
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

    # Checkbox untuk menampilkan filter
    show_query = st.checkbox("Vulnerabilty")
    show_language = st.checkbox("Language")
    show_severity = st.checkbox("Severity")

    # Fetch data secara otomatis saat checkbox diubah
    if access_token and scan_id:
        fetch_sast_results(access_token, scan_id, show_query, show_language,show_severity)

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

if st.session_state.page == 'main_page':
    main_page()
elif st.session_state.page == 'sca_page':
    sca_page()
elif st.session_state.page == 'sast_page':
    sast_page()
elif st.session_state.page == 'dast_page':
    dast_page()
elif st.session_state.page == 'raps_page':
    raps_page()
elif st.session_state.page == 'sast_page_checkmarx':
    sast_page_checkmarx()
elif st.session_state.page == 'sast_page_checkmarx_result':
    sast_page_checkmarx_result()
elif st.session_state.page == 'sast_page_checkmarx_result_group':
    sast_page_checkmarx_result_group()
