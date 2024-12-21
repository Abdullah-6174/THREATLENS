import streamlit as st
import pandas as pd
from groq import Groq
from langchain.prompts import PromptTemplate
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
import vt
import asyncio
import nest_asyncio
import os
import time
import re

# Enable nested event loops
nest_asyncio.apply()

# Load Nigerian Fraud CSV file
df_nigerian_fraud = pd.read_csv('Nigerian_Fraud.csv')
df_nigerian_fraud['text'] = df_nigerian_fraud['subject'].fillna('') + ' ' + df_nigerian_fraud['body']
texts = df_nigerian_fraud['text'].tolist()

embedding_model_name = "sentence-transformers/all-MiniLM-L6-v2"
embeddings_model = HuggingFaceEmbeddings(model_name=embedding_model_name)

vector_store = FAISS.from_texts(
    texts=texts,
    embedding=embeddings_model
)

prompt = """
Given the email body and subject below, determine if the email is a phishing email. Give reasons for your assessment and provide recommendations to what to do if the email is found to be phishing.
Email Subject and Body: {email_text}
Below are phishing emails subject+email for your context, you only have to learn from this context and there is no need to mention it in your response:
{retrieved_data}
"""

client = Groq(api_key="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")

virustotal_api_key = "41f1d1b04eff54f6432b2f35578847353bb196694ecf51c098485c4ffb3e984f"

# VirusTotal API helpers using the `vt-py` library
async def analyze_url(url):
    async with vt.Client(virustotal_api_key) as client:
        try:
            url_id = vt.url_id(url)
            url_obj = await client.get_object_async(f"/urls/{url_id}")
            stats = url_obj.last_analysis_stats
            scan_results = url_obj.last_analysis_results

            total = sum(stats.values())
            suspicious_percentage = (stats.get("suspicious", 0) / total) * 100
            malicious_percentage = (stats.get("malicious", 0) / total) * 100

            detailed_results = "\n".join([f"{engine}: {result['category']}" for engine, result in scan_results.items()])
            return stats, detailed_results, suspicious_percentage, malicious_percentage
        except Exception as e:
            return f"Error: {e}", "", 0, 0

async def analyze_file(file_obj):
    async with vt.Client(virustotal_api_key) as client:
        try:
            with open(file_obj.name, "rb") as f:
                analysis = await client.scan_file_async(f)

            while True:
                analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                if analysis.status == "completed":
                    break
                await asyncio.sleep(10)

            stats = analysis.stats
            scan_results = analysis.results

            total = sum(stats.values())
            suspicious_percentage = (stats.get("suspicious", 0) / total) * 100
            malicious_percentage = (stats.get("malicious", 0) / total) * 100

            detailed_results = "\n".join([f"{engine}: {result['category']}" for engine, result in scan_results.items()])
            return stats, detailed_results, suspicious_percentage, malicious_percentage
        except Exception as e:
            return f"Error occurred during file analysis: {str(e)}", "", 0, 0

def process_content(content_text):
    retrieved_docs = vector_store.similarity_search(content_text, k=3)
    retrieved_data = "\n".join([doc.page_content for doc in retrieved_docs])
    formatted_prompt = prompt.format(email_text=content_text, retrieved_data=retrieved_data)

    completion = client.chat.completions.create(
        model="llama3-groq-70b-8192-tool-use-preview",
        messages=[{"role": "user", "content": formatted_prompt}],
        temperature=0.5,
        max_tokens=8170,
        top_p=0.65,
        stream=False,
        stop=None,
    )
    response = completion.choices[0].message.content
    return response

def create_dynamic_circular_display(percentage, label):
    stroke_dasharray = 2 * 3.14159 * 40
    stroke_dashoffset = stroke_dasharray * (1 - percentage / 100)
    color = 'red' if percentage > 50 else 'orange' if percentage > 20 else 'green'

    return f"""
    <div style='display: flex; flex-direction: column; align-items: center;'>
        <svg width='100' height='100'>
            <circle cx='50' cy='50' r='40' stroke='gray' stroke-width='10' fill='none'></circle>
            <circle cx='50' cy='50' r='40' stroke='{color}' stroke-width='10' fill='none'
                stroke-dasharray='{stroke_dasharray}' stroke-dashoffset='{stroke_dashoffset}'
                transform='rotate(-90deg)' transform-origin='50% 50%'></circle>
        </svg>
        <div style='color: {color}; font-size: 16px; font-weight: bold;'>{label}: {percentage:.2f}%</div>
    </div>
    """

def analyze_email_header(header):
    results = []

    header_lines = header.splitlines()

    delivered_to = None
    to = None

    suspicious_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.scr', '.pif', '.com']

    for line in header_lines:
        lower_line = line.lower()

        if line.startswith("Delivered-To:"):
            delivered_to = line.split("Delivered-To:")[1].strip()
        elif line.startswith("To:"):
            to = line.split("To:")[1].strip()

        if "dkim=fail" in lower_line:
            results.append(f"DKIM check failed: {line.strip()}. This indicates potential spoofing.")
        if "spf=fail" in lower_line:
            results.append(f"SPF check failed: {line.strip()}. This could be a spoofed email.")
        if "dmarc=fail" in lower_line:
            results.append(f"DMARC check failed: {line.strip()}. This might be phishing.")

        attachment_matches = re.findall(r'filename="([^"]+)"', line)
        for match in attachment_matches:
            for ext in suspicious_extensions:
                if match.lower().endswith(ext):
                    results.append(f"Suspicious attachment detected: {match} ({ext} file extension).")

    if delivered_to and to and delivered_to != to:
        results.append("Mismatch between 'Delivered-To' and 'To' fields.")

    received_fields = [line for line in header_lines if line.startswith("Received:")]
    if len(received_fields) > 10:
        results.append("Too many hops in 'Received' fields, indicating potential spoofing.")

    if not any("dkim-signature" in line.lower() for line in header_lines):
        results.append("Missing DKIM-Signature: The email is not authenticated via DKIM.")

    return "\n".join(results) if results else "Header appears legitimate."

# Streamlit app layout
st.title("THREATLENS")
st.markdown("""
Use this app to analyze emails, URLs, and files for phishing or malicious content.
""")

# Phishing content detection
st.subheader("Phishing Content Detection")
content_input = st.text_area(
    label="Paste Content",
    placeholder="Enter the content here..."
)
if st.button("Analyze Content"):
    result = process_content(content_input)
    st.text_area("Assessment and Recommendations", value=result, height=300, disabled=True)

# URL analysis
st.subheader("URL Analysis")
url_input = st.text_input("Enter URL", "")
if st.button("Analyze URL"):
    stats, detailed_results, suspicious, malicious = asyncio.run(analyze_url(url_input))
    st.text_area("Summary of Analysis", value=str(stats), height=150, disabled=True)
    st.text_area("Detailed Engine Results", value=detailed_results, height=150, disabled=True)
    st.markdown(suspicious)
    st.markdown(malicious)

# File analysis
st.subheader("File Analysis")
file_input = st.file_uploader("Upload File", type=['exe', 'bat', 'cmd', 'vbs', 'js', 'scr', 'pif', 'com', 'txt', 'pdf'])
if st.button("Analyze File"):
    if file_input:
        stats, detailed_results, suspicious, malicious = asyncio.run(analyze_file(file_input))
        st.text_area("Summary of Analysis", value=str(stats), height=150, disabled=True)
        st.text_area("Detailed Engine Results", value=detailed_results, height=150, disabled=True)
        st.markdown(suspicious)
        st.markdown(malicious)
    else:
        st.text("No file uploaded")

# Email Header Analysis
st.subheader("Email Header Analysis")
header_input = st.text_area("Paste Email Header", "", height=200)
if st.button("Analyze Header"):
    header_result = analyze_email_header(header_input)
    st.text_area("Header Analysis Results", value=header_result, height=300, disabled=True)
