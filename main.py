import os
import tempfile
import json
import streamlit as st
import pandas as pd
import pyshark
from groq import Groq
import concurrent.futures

from dotenv import load_dotenv
load_dotenv()

# ==============================================================================
# 1. AI Pattern & Persona Definitions (Vanderbilt Course Implementation)
# ==============================================================================

ROOT_PROMPT = """
[GLOBAL SYSTEM CONSTRAINTS - ROOT PROMPT PATTERN]
- You must maintain your assigned professional security persona under all circumstances.
- Your analysis must be entirely context-grounded. Never invent, extrapolate, or hypothesize network indicators (IPs, ports, packet numbers) that do not explicitly exist within the provided source JSON dataset.
- Always communicate using professional, precise technical language.
- Format all outputs cleanly using structured Markdown with precise headings.
"""

PERSONAS = {
    "SOC Analyst Tier 1": """You are a Tier 1 Security Operations Center (SOC) Analyst.
Your primary objective is rapid triage and incident escalation. Focus on identifying obvious malicious anomalies (e.g., cleartext credentials, unauthorized port usage, brute force attempts).

[TEMPLATE PATTERN REQUIREMENT]
You MUST format your output exactly as follows:
### 🚨 SOC Triage Report
**Severity Level:** [Low / Medium / High / CRITICAL]
**Executive Summary:** [2-3 sentences explaining the immediate threat]
**Key Indicators of Compromise (IOCs):**
- [List suspicious IPs, Ports, or cleartext payloads extracted from the JSON]
**Immediate Action Required:** [Specific containment recommendations]
""",

    "DFIR Specialist": """You are an elite Digital Forensics and Incident Response (DFIR) Specialist.
Your primary objective is deep-dive forensic analysis, payload inspection, and timeline reconstruction. Focus on advanced threats like DNS tunneling, C2 beaconing, and data exfiltration vectors.

[TEMPLATE PATTERN REQUIREMENT]
You MUST format your output exactly as follows:
### 🕵️‍♂️ DFIR Deep-Dive Analysis
**Incident Narrative:** [Detailed technical explanation of the attack sequence]
**Observed Payload Mechanics:** [Analysis of specific hex/text payloads, protocols, or encoded strings]
**Forensic Timeline:**
- [Chronological bullet points linking specific packet numbers (e.g., "Packet 12: Initial beacon...")]
**Root Cause Hypothesis:** [What vulnerability or vector allowed this?]
""",

    "Network Engineer": """You are a Senior Network Automation and Reliability Engineer.S
Your primary objective is network health, performance troubleshooting, and protocol compliance. Ignore malicious hacking threats; focus entirely on infrastructure issues like routing loops, TCP retransmission storms, broken handshakes, or excessive DNS latency.

[TEMPLATE PATTERN REQUIREMENT]
You MUST format your output exactly as follows:
### 🖧 Network Health Diagnostics
**Diagnostic Summary:** [Overview of the infrastructure bottleneck or protocol failure]
**Protocol Anomalies:** [Specific breakdown of TCP flags, DNS delays, etc.]
**Affected Endpoints:** [List the client/server IPs experiencing the degradation]
**Infrastructure Remediation Steps:** [Technical steps to optimize the routing or fix the misconfiguration]
"""
}

BEHAVIOR_INTENT_ADDENDUM = """
[CRITICAL INSTRUCTION - ATTACKER INTENT ANALYSIS]
The user has requested a macro-level behavioral analysis. You MUST:
1. Map any suspicious findings to the MITRE ATT&CK framework (Tactics and Techniques).
2. Infer the psychological or strategic intent of the adversary based on the traffic flow (e.g., Are they scanning? Attempting lateral movement? Setting up persistence?).
3. Evaluate the sophistication of the observed activity.
Append a dedicated section titled "### Adversary Intent & Behavioral Profiling" at the end of your report to cover these points.
"""

FACT_CHECK_PROMPT = """
You are an independent Senior Security Auditor. Your sole task is to cross-examine a newly generated network report against the raw source packet data to eliminate hallucinations.

Review the generated report carefully. Output an audit verification section containing a Markdown checklist:
1. For every technical metric referenced (IP addresses, Port numbers, Protocol types, Packet Numbers), verify if it exists identically in the raw source stream data.
2. Mark each verification check with a '[x] Verified' or '[ ] Hallucination Warning'.
3. If an indicator is flagged as a warning, explicitly state what was fabricated.

Format your entire output inside a neat layout titled: '### 🛡️ Post-Generation Hallucination Self-Audit (Fact-Check Pattern)'
"""

FLIPPED_INTERACTION_PROMPT = """
You are the selected expert persona. The user has finished reviewing the primary report and wants to perform an interactive deep-dive into mitigation or remediation protocols.

[CRITICAL - FLIPPED INTERACTION PATTERN CONFIGURATION]
1. You are leading the conversation. Do not dump a list of steps all at once.
2. Your task is to ask the user questions, one at a time, to guide them to create a customized response roadmap.
3. Based on your assigned persona, ask your FIRST question now regarding how the user plans to address the most critical finding in the data table.
4. Wait for the user's response before asking the next follow-up question.
"""

# ==========================================
# 2. Backend Parsing Logic (True Process Isolation)
# ==========================================

def _run_pyshark(file_path, packet_limit):
    """
    Runs PyShark in a completely isolated OS process to prevent asyncio corruption.
    Must be defined at the top level so Windows multiprocessing can pickle it.
    """
    import asyncio
    import pyshark
    
    # Force a fresh loop in this new process to be safe
    asyncio.set_event_loop(asyncio.new_event_loop())
    
    packets_data = []
    capture = None
    try:
        capture = pyshark.FileCapture(file_path, keep_packets=False)
        count = 0
        for packet in capture:
            if count >= packet_limit:
                break
            try:
                pkt_data = {
                    "No": packet.number if hasattr(packet, 'number') else "N/A",
                    "Protocol": packet.highest_layer if hasattr(packet, 'highest_layer') else "N/A",
                    "Length": packet.length if hasattr(packet, 'length') else "0",
                    "Source_IP": "N/A",
                    "Dest_IP": "N/A",
                    "Payload_Summary": "N/A",
                    "Deep_Details": str(packet)
                }

                if hasattr(packet, 'ip'):
                    pkt_data["Source_IP"] = packet.ip.src
                    pkt_data["Dest_IP"] = packet.ip.dst
                elif hasattr(packet, 'ipv6'):
                    pkt_data["Source_IP"] = packet.ipv6.src
                    pkt_data["Dest_IP"] = packet.ipv6.dst

                if hasattr(packet, 'http'):
                    host = getattr(packet.http, 'host', '')
                    uri = getattr(packet.http, 'request_uri', '')
                    method = getattr(packet.http, 'request_method', '')
                    if method or host:
                        pkt_data["Payload_Summary"] = f"HTTP {method} {host}{uri}"
                
                elif hasattr(packet, 'dns'):
                    qry = getattr(packet.dns, 'qry_name', '')
                    if qry:
                        pkt_data["Payload_Summary"] = f"DNS Query: {qry}"

                packets_data.append(pkt_data)
                count += 1
            except Exception:
                continue
                
    except Exception as e:
        print(f"Parsing engine alert: {e}")
    finally:
        if capture:
            capture.close()
            
    return packets_data

def parse_pcap_file(file_path, packet_limit=100):
    """
    Spawns a totally separate Python process to run PyShark.
    This guarantees Streamlit's ASGI servers remain untouched.
    """
    with concurrent.futures.ProcessPoolExecutor(max_workers=1) as executor:
        future = executor.submit(_run_pyshark, file_path, packet_limit)
        parsed_data = future.result()

    return parsed_data

# ==========================================
# 3. Groq AI Generation Engine
# ==========================================

def generate_ai_report(pcap_json, persona, analyze_intent):
    if not os.environ.get("GROQ_API_KEY"):
        st.error("Error: GROQ_API_KEY environment variable is not set. Check your .env file.")
        return None, None

    client = Groq()

    system_instruction = f"{ROOT_PROMPT}\n\n{PERSONAS[persona]}"
    if analyze_intent:
        system_instruction += f"\n\n{BEHAVIOR_INTENT_ADDENDUM}"

    prompt_content = f"Please analyze the following parsed network packet capture (PCAP) data in JSON format:\n\n{pcap_json}"

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt_content}
            ],
            temperature=0.1
        )
        primary_report = response.choices[0].message.content

        fact_check_prompt_content = f"RAW PACKET DATA:\n{pcap_json}\n\nGENERATED REPORT:\n{primary_report}"
        
        audit_response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": FACT_CHECK_PROMPT},
                {"role": "user", "content": fact_check_prompt_content}
            ],
            temperature=0.0
        )
        audit_log = audit_response.choices[0].message.content

        return primary_report, audit_log
        
    except Exception as e:
        st.error(f"Error communicating with Groq API: {str(e)}")
        return None, None

def interact_flipped_agent(history, user_input, pcap_json, persona):
    client = Groq()
    system_instruction = f"{ROOT_PROMPT}\n\n{PERSONAS[persona]}\n\n{FLIPPED_INTERACTION_PROMPT}"
    
    messages = [{"role": "system", "content": system_instruction}]
    messages.append({"role": "system", "content": f"CONTEXT DATA REFERENCE:\n{pcap_json}"})
    
    for msg in history:
        messages.append({"role": msg["role"], "content": msg["content"]})
        
    if user_input:
        messages.append({"role": "user", "content": user_input})

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=messages,
            temperature=0.3
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error continuing interaction: {str(e)}"

# ==========================================
# 4. Streamlit Frontend UI Layout
# ==========================================

def main():
    st.set_page_config(page_title="AI PCAP Analyzer", page_icon="📡", layout="wide")
    st.title("📡 AI-Powered PCAP Analyzer")
    st.markdown("Upload a network capture file (`.pcap`) and leverage Groq Llama 3.3 to dissect traffic streams through formalized Prompt Engineering layouts.")

    if "ai_report" not in st.session_state: st.session_state.ai_report = None
    if "audit_log" not in st.session_state: st.session_state.audit_log = None
    if "flipped_chat" not in st.session_state: st.session_state.flipped_chat = []

    with st.sidebar:
        st.header("⚙️ Analysis Settings")
        selected_persona = st.selectbox("Select AI Persona:", options=list(PERSONAS.keys()))
        analyze_intent = st.checkbox("Analyze Attacker Intent & Behavior", value=False)
        st.markdown("---")
        show_audit = st.toggle("Enable Fact-Checking Audit Output View", value=True)

    uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        if "current_file" not in st.session_state or st.session_state.current_file != uploaded_file.name:
            st.session_state.current_file = uploaded_file.name
            st.session_state.ai_report = None
            st.session_state.audit_log = None
            st.session_state.flipped_chat = []

        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_pcap_path = tmp_file.name

        with st.spinner("Extracting packet metadata layers via PyShark..."):
            parsed_data = parse_pcap_file(tmp_pcap_path, packet_limit=100)
        os.remove(tmp_pcap_path)

        if not parsed_data:
            st.warning("No standard packets could be translated from this capture pool source.")
            return

        st.subheader("📊 Network Traffic View")
        df = pd.DataFrame(parsed_data)
        display_df = df.drop(columns=["Deep_Details"])

        selection_event = st.dataframe(display_df, width="stretch", hide_index=True, on_select="rerun", selection_mode="single-row")

        selected_rows = selection_event.selection.rows
        if selected_rows:
            st.code(parsed_data[selected_rows[0]]['Deep_Details'], language="text")

        pcap_json_string = json.dumps(display_df.to_dict(orient="records"), indent=2)
        st.divider()

        col1, col2 = st.columns([2, 1]) if show_audit else (st.container(), None)

        with st.container():
            if st.button("Generate Groq AI Report & Fact-Check Pass", type="primary"):
                with st.spinner("Compiling analysis with verification checks active..."):
                    report, audit = generate_ai_report(pcap_json_string, selected_persona, analyze_intent)
                    st.session_state.ai_report = report
                    st.session_state.audit_log = audit
                    
                    if report:
                        initial_query = interact_flipped_agent([], None, pcap_json_string, selected_persona)
                        st.session_state.flipped_chat = [{"role": "assistant", "content": initial_query}]

        if st.session_state.ai_report:
            if show_audit:
                with col1:
                    st.markdown("### 📋 Primary Persona Report")
                    st.info(f"**Root Prompt Constraints Implemented for: {selected_persona}**")
                    st.markdown(st.session_state.ai_report)
                with col2:
                    st.markdown(st.session_state.audit_log)
            else:
                st.markdown(st.session_state.ai_report)

            st.divider()
            st.subheader("Interactive Mitigation Session (Flipped Interaction Pattern)")
            st.caption("The AI agent below will ask you targeted questions step-by-step to compile a mitigation/remediation roadmap.")
            
            for msg in st.session_state.flipped_chat:
                with st.chat_message(msg["role"]):
                    st.write(msg["content"])

            if user_response := st.chat_input("Enter your response to the AI's inquiry here..."):
                st.session_state.flipped_chat.append({"role": "user", "content": user_response})
                with st.chat_message("user"): st.write(user_response)
                
                with st.spinner("AI is evaluating your input and preparing the next query..."):
                    next_question = interact_flipped_agent(st.session_state.flipped_chat[:-1], user_response, pcap_json_string, selected_persona)
                    st.session_state.flipped_chat.append({"role": "assistant", "content": next_question})
                    st.rerun()

if __name__ == "__main__":
    main()