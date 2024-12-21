import gradio as gr
import pandas as pd
from groq import Groq
from langchain.prompts import PromptTemplate
from langchain_community.vectorstores import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
import vt
import asyncio
import nest_asyncio
import os
import time
import re

# Enable nested event loops
nest_asyncio.apply()

# Load Nigerian Fraud CSV file (update to relative path for deployment)
df_nigerian_fraud = pd.read_csv('Nigerian_Fraud.csv')

df_nigerian_fraud['text'] = df_nigerian_fraud['subject'].fillna('') + ' ' + df_nigerian_fraud['body']
texts = df_nigerian_fraud['text'].tolist()

embedding_model_name = "sentence-transformers/all-MiniLM-L6-v2"
embeddings_model = HuggingFaceEmbeddings(model_name=embedding_model_name)

# Use Chroma DB for storing and retrieving embeddings
vector_store = Chroma.from_texts(
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
            # Read the file as a binary stream
            with open(file_obj.name, "rb") as f:
                analysis = await client.scan_file_async(f)

            # Poll the status of the analysis
            while True:
                analysis = await client.get_object_async(f"/analyses/{analysis.id}")
                if analysis.status == "completed":
                    break
                await asyncio.sleep(10)

            # Fetch final analysis results
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

# Helper function to create dynamic circular percentage display
def create_dynamic_circular_display(percentage, label):
    # Calculate the stroke-dasharray and stroke-dashoffset for animation
    stroke_dasharray = 2 * 3.14159 * 40  # Circumference of the circle
    stroke_dashoffset = stroke_dasharray * (1 - percentage / 100)
    # Color logic based on percentage values
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

# Email header analysis with DKIM, DMARC, SPF checks, and dangerous file extensions detection

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

# Gradio app
with gr.Blocks() as app:
    gr.Markdown("""<h1>THREATLENS</h1>
    Use this app to analyze emails, URLs, and files for phishing or malicious content.
    """)

    # Phishing content detection
    with gr.Tab("Phishing Content Detection"):
        content_input = gr.Textbox(
            label="Paste Content",
            placeholder="Enter the content here...",
            lines=10
        )
        result_output = gr.Textbox(
            label="Assessment and Recommendations",
            placeholder="Results will be displayed here...",
            lines=15,
            interactive=False
        )
        analyze_content_button = gr.Button("Analyze Content")
        analyze_content_button.click(
            fn=process_content,
            inputs=content_input,
            outputs=result_output
        )

    # URL analysis
    with gr.Tab("URL Analysis"):
        url_input = gr.Textbox(
            label="Enter URL",
            placeholder="Enter a URL to analyze..."
        )
        url_stats_output = gr.Textbox(
            label="Summary of Analysis",
            interactive=False
        )
        url_details_output = gr.Textbox(
            label="Detailed Results",
            interactive=False
        )
        url_suspicious_percentage_output = gr.Textbox(
            label="Suspicious URL Percentage",
            interactive=False
        )
        url_malicious_percentage_output = gr.Textbox(
            label="Malicious URL Percentage",
            interactive=False
        )
        analyze_url_button = gr.Button("Analyze URL")
        analyze_url_button.click(
            fn=analyze_url,
            inputs=url_input,
            outputs=[url_stats_output, url_details_output, url_suspicious_percentage_output, url_malicious_percentage_output]
        )

    # File analysis
    with gr.Tab("File Analysis"):
        file_input = gr.File(label="Upload File to Analyze")
        file_stats_output = gr.Textbox(
            label="Summary of File Analysis",
            interactive=False
        )
        file_details_output = gr.Textbox(
            label="File Scan Results",
            interactive=False
        )
        file_suspicious_percentage_output = gr.Textbox(
            label="Suspicious File Percentage",
            interactive=False
        )
        file_malicious_percentage_output = gr.Textbox(
            label="Malicious File Percentage",
            interactive=False
        )
        analyze_file_button = gr.Button("Analyze File")
        analyze_file_button.click(
            fn=analyze_file,
            inputs=file_input,
            outputs=[file_stats_output, file_details_output, file_suspicious_percentage_output, file_malicious_percentage_output]
        )

    # Email Header Analysis
    with gr.Tab("Email Header Analysis"):
        header_input = gr.Textbox(
            label="Paste Email Header",
            placeholder="Paste the raw email header here...",
            lines=10
        )
        header_analysis_output = gr.Textbox(
            label="Email Header Analysis Results",
            interactive=False
        )
        analyze_header_button = gr.Button("Analyze Header")
        analyze_header_button.click(
            fn=analyze_email_header,
            inputs=header_input,
            outputs=header_analysis_output
        )

app.launch()
