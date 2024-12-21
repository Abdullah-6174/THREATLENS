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
import re

# Enable nested event loops
nest_asyncio.apply()

# Streamlit caching for embeddings model and FAISS vector store
@st.cache_resource
def load_embedding_model():
    embedding_model_name = "sentence-transformers/all-MiniLM-L6-v2"
    return HuggingFaceEmbeddings(model_name=embedding_model_name)

@st.cache_resource
def load_vector_store():
    df_nigerian_fraud = pd.read_csv('Nigerian_Fraud.csv')
    df_nigerian_fraud['text'] = df_nigerian_fraud['subject'].fillna('') + ' ' + df_nigerian_fraud['body']
    texts = df_nigerian_fraud['text'].tolist()
    embeddings_model = load_embedding_model()
    return FAISS.from_texts(texts=texts, embedding=embeddings_model)

@st.cache_resource
def load_groq_client():
    return Groq(api_key="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")

@st.cache_resource
def load_virustotal_client():
    return vt.Client("41f1d1b04eff54f6432b2f35578847353bb196694ecf51c098485c4ffb3e984f")

# Initialize cached resources
vector_store = load_vector_store()
client = load_groq_client()

# Prompt template for content analysis
prompt = """
Given the email body and subject below, determine if the email is a phishing email. 
Give reasons for your assessment and provide recommendations to what to do if the email is found to be phishing.
Email Subject and Body: {email_text}
Below are phishing emails subject+email for your context, you only have to learn from this context and there is no need to mention it in your response:
{retrieved_data}
"""

# VirusTotal API helpers using the `vt-py` library
@st.cache_data
async def analyze_url(url):
    async with load_virustotal_client() as client:
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

@st.cache_data
async def analyze_file(file_obj):
    async with load_virustotal_client() as client:
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

def analyze_email_header(header):
    results = []

    # Split the header into lines
    header_lines = header.splitlines()

    # Variables to track Delivered-To and To fields
    delivered_to = None
    to = None

    # Define suspicious file extensions for attachment checks
    suspicious_extensions = ['.exe', '.bat', '.cmd', '.vbs', '.js', '.scr', '.pif', '.com']

    # Process each line in the header
    for line in header_lines:
        lower_line = line.lower()

        # Check Delivered-To and To fields
        if line.startswith("Delivered-To:"):
            delivered_to = line.split("Delivered-To:")[1].strip()
        elif line.startswith("To:"):
            to = line.split("To:")[1].strip()

        # DKIM, SPF, and DMARC checks with detailed reasoning
        if "dkim=fail" in lower_line:
            results.append(
                f"DKIM check failed: {line.strip()}. "
                "This indicates the email's DKIM signature does not match the expected value. "
                "It could mean the email was altered in transit, suggesting potential spoofing or tampering."
            )
        if "spf=fail" in lower_line:
            results.append(
                f"SPF check failed: {line.strip()}. "
                "This means the sender's IP address is not authorized to send emails for the domain specified in the From field. "
                "It could indicate that the email is being sent from a spoofed or malicious source."
            )
        if "dmarc=fail" in lower_line:
            results.append(
                f"DMARC check failed: {line.strip()}. "
                "This indicates the domain failed alignment with the email's SPF and DKIM records, "
                "or the domain's policy requires rejection for unauthorized emails. "
                "It suggests the email might not be legitimate and could be phishing."
            )

        # Check DKIM-Signature
        if "dkim-signature" in lower_line:
            pass  # Acknowledge the presence of a DKIM-Signature

        # Attachment checks for suspicious file extensions
        attachment_matches = re.findall(r'filename="([^"]+)"', line)
        for match in attachment_matches:
            for ext in suspicious_extensions:
                if match.lower().endswith(ext):
                    results.append(f"Suspicious attachment detected: {match} ({ext} file extension).")

    # Final checks after scanning all lines
    if delivered_to and to and delivered_to != to:
        results.append("Mismatch between 'Delivered-To' and 'To' fields. This might indicate email spoofing.")

    # Received field hops check (example threshold: 10 hops)
    received_fields = [line for line in header_lines if line.startswith("Received:")]
    if len(received_fields) > 10:  # Arbitrary threshold
        results.append("Too many hops in 'Received' fields, indicating potential spoofing or forwarding.")

    # Check for missing DKIM-Signature
    if not any("dkim-signature" in line.lower() for line in header_lines):
        results.append("Missing DKIM-Signature: The email is not authenticated via DKIM.")

    # Return the final results
    return "\n".join(results) if results else "Header appears legitimate."


# Streamlit app layout
st.title("THREATLENS")
st.markdown("Use this app to analyze emails, URLs, and files for phishing or malicious content.")

st.subheader("Phishing Content Detection")
content_input = st.text_area("Paste Content", "Enter the content here...")
if st.button("Analyze Content"):
    result = process_content(content_input)
    st.text_area("Assessment and Recommendations", value=result, height=300, disabled=True)

st.subheader("URL Analysis")
url_input = st.text_input("Enter URL", "")
if st.button("Analyze URL"):
    stats, detailed_results, suspicious, malicious = asyncio.run(analyze_url(url_input))
    st.text_area("Summary of Analysis", value=str(stats), height=150, disabled=True)
    st.text_area("Detailed Engine Results", value=detailed_results, height=150, disabled=True)

st.subheader("File Analysis")
file_input = st.file_uploader("Upload File", type=['exe', 'bat', 'cmd', 'vbs', 'js', 'scr', 'pif', 'com', 'txt', 'pdf'])
if st.button("Analyze File"):
    if file_input:
        stats, detailed_results, suspicious, malicious = asyncio.run(analyze_file(file_input))
        st.text_area("Summary of Analysis", value=str(stats), height=150, disabled=True)
        st.text_area("Detailed Engine Results", value=detailed_results, height=150, disabled=True)
    else:
        st.text("No file uploaded")

st.subheader("Email Header Analysis")
header_input = st.text_area("Paste Email Header", "", height=200)
if st.button("Analyze Header"):
    header_result = analyze_email_header(header_input)
    st.text_area("Header Analysis Results", value=header_result, height=300, disabled=True)
