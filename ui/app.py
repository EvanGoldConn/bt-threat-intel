import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), "..", ".env"))

import streamlit as st
from src.chat.pipeline import ChatPipeline

st.set_page_config(page_title="BT Threat Intel", page_icon="shield", layout="wide")
st.title("BT Threat Intel - Analyst Chat")
st.caption("Ask questions about current CVEs, vulnerabilities, and your exposure status.")

# Initialize chat pipeline and session message history
if "pipeline" not in st.session_state:
    st.session_state.pipeline = ChatPipeline()

if "messages" not in st.session_state:
    st.session_state.messages = []

# Render previous messages
for message in st.session_state.messages:
    with st.chat_message(message["role"]):
        st.markdown(message["content"])

# Handle new input
if prompt := st.chat_input("Ask about a CVE, your exposure, or recent threats..."):
    st.session_state.messages.append({"role": "user", "content": prompt})
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        with st.spinner("Searching intel store..."):
            response = st.session_state.pipeline.query(prompt)
        st.markdown(response)

    st.session_state.messages.append({"role": "assistant", "content": response})
