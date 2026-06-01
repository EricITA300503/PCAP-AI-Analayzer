# 📡 AI-Powered PCAP Analyzer (Blue Team Triage)

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-UI-FF4B4B)
![Groq](https://img.shields.io/badge/AI-Groq%20Llama%203.3-orange)
![PyShark](https://img.shields.io/badge/Network-PyShark-lightgrey)

An automated, web-based network traffic analysis tool designed to bridge the gap between raw packet captures (`.pcap`) and rapid threat triage. 

This project was built to programmatically implement advanced **Prompt Engineering Architectures** (based on formal training from Vanderbilt University) to force Large Language Models into strict, hallucination-free forensic workflows.

## 🧠 Advanced Prompt Engineering Patterns Implemented

Rather than using basic zero-shot queries, this software orchestrates an LLM pipeline utilizing four distinct structural patterns:

1. **The Root Prompt Pattern:** Enforces strict global constraints across the entire application. It explicitly forbids the LLM from inventing or hypothesizing IP addresses, ports, or packet numbers that do not exist in the source JSON.
2. **The Persona Pattern:** Dynamically alters the LLM's analytical lens based on user selection:
   * **Tier 1 SOC Analyst:** Focuses on rapid triage, severity categorization, and immediate containment.
   * **DFIR Specialist:** Conducts deep-dive hexadecimal payload analysis, C2 beacon mapping, and MITRE ATT&CK correlation.
   * **Network Engineer:** Ignores malicious intent to focus strictly on protocol health, TCP retransmissions, and latency bottlenecks.
3. **The Fact-Check List Pattern (Self-Correction):** To completely eliminate AI hallucinations, the backend runs a secondary, silent audit pipeline. After the primary report is generated, the AI switches to an "Auditor" role, cross-referencing every metric in the report against the raw PyShark dictionary stream to verify its authenticity.
4. **The Flipped Interaction Pattern:** Moves beyond static generation. Upon report completion, the AI takes control of a conversational terminal, asking the analyst targeted, step-by-step questions to build a tailored incident mitigation roadmap.

## 🏗️ Technical Architecture
* **Frontend:** Streamlit for rapid, interactive state management.
* **Backend Parser:** PyShark (TShark wrapper). *Note: Implements specialized isolated `ProcessPoolExecutor` pipelines to prevent asyncio loop collisions between PyShark and Starlette/Uvicorn ASGI servers on Windows.*
* **AI Inference:** Groq Cloud (`llama-3.3-70b-versatile`) for ultra-low latency, high-context structured text generation.

---

## 🚀 Quick Start Guide

### 1. Prerequisites
* Python 3.10+
* [Wireshark/TShark](https://www.wireshark.org/) installed on your host machine (required for PyShark to decode packets).
* A free [Groq API Key](https://console.groq.com/keys).

### 2. Installation
Clone the repository and install the dependencies:
```bash
git clone [https://github.com/YourUsername/PCAP-AI-Analyzer.git](https://github.com/YourUsername/PCAP-AI-Analyzer.git)
cd PCAP-AI-Analyzer
python -m venv venv
# Windows: venv\Scripts\activate
# Mac/Linux: source venv/bin/activate
pip install -r requirements.txt
```
### 3. Environment Setup
Rename the provided .env.example file to .env and paste your Groq API key inside:

Plaintext
```
GROQ_API_KEY=gsk_your_api_key_here
```
### 4. Run the Application
```Bash
streamlit run main.py
```
