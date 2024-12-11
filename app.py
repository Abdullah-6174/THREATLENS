import streamlit as st
import pandas as pd
from groq import Groq
from langchain.prompts import PromptTemplate
from langchain_community.vectorstores import FAISS  # Updated import as per deprecation notice
from langchain_huggingface import HuggingFaceEmbeddings
import os

# Load Nigerian Fraud CSV file (update to relative path for deployment)
df_nigerian_fraud = pd.read_csv('Nigerian_Fraud.csv')

# Combine the 'subject' and 'body' columns to create a 'text' column
df_nigerian_fraud['text'] = df_nigerian_fraud['subject'].fillna('') + ' ' + df_nigerian_fraud['body']

# Use only the 'text' column
texts = df_nigerian_fraud['text'].tolist()

# Initialize Hugging Face Embeddings
embedding_model_name = "sentence-transformers/all-MiniLM-L6-v2"
embeddings_model = HuggingFaceEmbeddings(model_name=embedding_model_name)

# Use FAISS to create a vector store from text only
vector_store = FAISS.from_texts(
    texts=texts,  # Pass only the textual data
    embedding=embeddings_model
)

# Define an updated prompt template with clearer instructions
prompt = """
Given the email body and subject below, determine if the email is a phishing email. Give reasons for your assessment and provide recommendations to what to do if the email is found to be phishing.

Email Subject and Body: {email_text}

Below are phishing emails subject+email for your context, you only have to learn from this context and there is no need to mention it in your response:
{retrieved_data}
"""

# Initialize Groq API client
# Set your Groq API key securely using environment variables
groq_api_key = os.getenv('GROQ_API_KEY')  # Use environment variable for API key
client = Groq(api_key="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")

# Define the function to process the content
def process_content(content_text):
    # Retrieve relevant documents from the FAISS vector store based on the content
    retrieved_docs = vector_store.similarity_search(content_text, k=3)  # Retrieve top 3 most similar documents

    # Combine the content with the retrieved data to form the prompt
    retrieved_data = "\n".join([doc.page_content for doc in retrieved_docs])  # Extract the text content of the retrieved documents

    # Format the final prompt
    formatted_prompt = prompt.format(email_text=content_text, retrieved_data=retrieved_data)

    # Use the Groq API to get the completion after passing the prompt with context
    completion = client.chat.completions.create(
        model="llama3-groq-70b-8192-tool-use-preview",  # Replace with your desired model
        messages=[
            {"role": "user", "content": formatted_prompt}
        ],
        temperature=0.5,
        max_tokens=2048,  # Reduced max_tokens for faster response
        top_p=0.65,
        stream=False,
        stop=None,
    )

    # Extract and format the response
    response = completion.choices[0].message.content
    return response

# Streamlit App UI
st.set_page_config(page_title="Phishing Content Detector", layout="centered")

# App Title
st.title("Phishing Content Detector")
st.markdown(
    "Paste the content below, and this app will assess whether it's a phishing attempt.\n\n"
    "It will also provide reasons for the assessment and recommendations."
)

# Input Textbox for content
content_text = st.text_area(
    "Paste Content",
    placeholder="Enter the content here...",
    height=200
)

# Analyze Button
if st.button("Analyze Content"):
    if content_text.strip():
        with st.spinner("Analyzing content..."):
            # Get the analysis result
            result = process_content(content_text)
        st.success("Analysis Complete!")
        # Display the result
        st.text_area("Assessment and Recommendations", result, height=300)
    else:
        st.error("Please enter some content to analyze.")

# Disclaimer
st.markdown(
    """<h3>Disclaimer</h3>
    Always exercise caution when interacting with suspicious content.
    """,
    unsafe_allow_html=True
)
