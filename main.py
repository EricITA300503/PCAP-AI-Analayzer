import os
import tempfile
import json
import asyncio
import streamlit as st
import pandas as pd
import pyshark
from google import genai
from google.genai import types

# Load the .env file variables into the system environment memory automatically
from dotenv import load_dotenv
load_dotenv()

# ==============================================================================
# 1. AI Pattern & Persona Definitions (Vanderbilt Course Implementation)
# ==============================================================================

# THE ROOT PROMPT PATTERN: Defines absolute constraints, boundaries, and behaviors
ROOT_PROMPT = """
[GLOBAL SYSTEM CONSTRAINTS - ROOT PROMPT PATTERN]
- You must maintain your assigned professional security persona under all circumstances.
- Your analysis must be entirely context-grounded. Never invent, extrapolate, or hypothesize network indicators (IPs, ports, packet numbers) that do not explicitly exist within the provided source JSON dataset.
- Always communicate using professional, precise technical language.
- Format all outputs cleanly using structured Markdown with precise headings.
"""

PERSONAS = {
    "SOC Analyst Tier 1": """You are a Tier 1 Security Operations Center (SOC) Analyst.
Your primary objective is rapid triage. When reviewing network traffic, focus on:
- Identifying obvious malicious anomalies (e.g., cleartext credentials, unauthorized port usage).
- Highlighting suspicious source/destination IP pairings.
- Categorizing the severity of the network behavior (Low, Medium, High).
Keep your report concise, action-oriented, and structured with clear headings. Recommend immediate next steps for containment if necessary.""",

    "DFIR Specialist": """You are an elite Digital Forensics and Incident Response (DFIR) Specialist.
Your primary objective is deep-dive forensic analysis and timeline reconstruction. When reviewing network traffic, focus on:
- Identifying Indicators of Compromise (IOCs) and potential data exfiltration vectors.
- Analyzing HTTP/DNS payloads for command-and-control (C2) beaconing patterns.
- Correlating packet sequences to establish an attack narrative.
Provide a highly technical, detailed report. Use precise terminology and format your findings into forensic evidence blocks.""",

    "Network Engineer": """You are a Senior Network Automation and Reliability Engineer.
Your primary objective is network health, performance, and protocol compliance. When reviewing network traffic, focus on:
- Identifying routing loops, broadcast storms, or excessive latency indicators.
- Highlighting misconfigurations in standard protocols (DNS, HTTP, TCP handshakes).
- Suggesting optimizations for network architecture.
Keep your analysis focused strictly on infrastructure, topology, and protocol mechanics rather than malicious threats."""
}

BEHAVIOR_INTENT_ADDENDUM = """
[CRITICAL INSTRUCTION - ATTACKER INTENT ANALYSIS]
The user has requested a macro-level behavioral analysis. You MUST:
1. Map any suspicious findings to the MITRE ATT&CK framework (Tactics and Techniques).
2. Infer the strategic intent of the adversary based on the traffic flow (e.g., Are they scanning? Attempting lateral movement? Setting up persistence?).
3. Evaluate the sophistication of the observed activity.
Append a dedicated section titled "### Adversary Intent & Behavioral Profiling" at the end of your report to cover these points.
"""

# THE FACT-CHECK LIST PATTERN: Forces the model to audit its own output for hallucinations
FACT_CHECK_PROMPT = """
You are an independent Senior Security Auditor. Your sole task is to cross-examine a newly generated network report against the raw source packet data to eliminate hallucinations.

Review the generated report carefully. Output an audit verification section containing a Markdown checklist:
1. For every technical metric referenced (IP addresses, Port numbers, Protocol types, Packet Numbers), verify if it exists identically in the raw source stream data.
2. Mark each verification check with a '[x] Verified' or '[ ] Hallucination Warning'.
3. If an indicator is flagged as a warning, explicitly state what was fabricated.

Format your entire output inside a neat layout titled: '### 🛡️ Post-Generation Hallucination Self-Audit (Fact-Check Pattern)'
"""

# THE FLIPPED INTERACTION PATTERN: Reverses control so the AI queries the user to solve the incident
FLIPPED_INTERACTION_PROMPT = """
You are the selected Network Security expert persona. The analyst has finished reviewing the primary report and wants to perform an interactive deep-dive into mitigation or remediation protocols.

[CRITICAL - FLIPPED INTERACTION PATTERN CONFIGURATION]
1. You are leading the conversation. Do not dump a list of steps all at once.
2. Your task is to ask the user questions, one at a time, to guide them to create a customized incident response or optimization roadmap.
3. Ask your first question now regarding how they plan to contain the active assets or protocols identified in the traffic capture data table.
4. Wait for the user's response before asking the next follow-up question.
"""

# ==========================================
# 2. Backend Parsing Logic (PyShark Process Isolation)
# ==========================================

def parse_pcap_file(file_path, packet_limit=100):
    """
    Parses a PCAP file cleanly by running PyShark inside a completely isolated,
    dedicated standard thread context to prevent event loop contamination.
    """
    import threading
    packets_data = []

    # Standalone worker function
    def worker():
        import asyncio
        import pyshark

        # 1. Create a dedicated event loop specifically for this thread instance
        # Note: nest_asyncio is REMOVED to prevent contaminating Streamlit's ASGI server
        local_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(local_loop)
        
        try:
            # 2. Open the capture inside the isolated loop environment
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
                    
            # 3. Explicitly close the capture to trigger PyShark's async cleanup tasks
            capture.close()
            
            # 4. Force garbage collection of the capture object NOW, while the loop is still alive
            del capture
            
        except Exception as e:
            print(f"Parsing engine alert: {e}")
        finally:
            # 5. Safely clean up the loop now that PyShark has fully terminated
            try:
                local_loop.close()
            except Exception:
                pass

    # Force execution on an isolated, dedicated standard thread
    t = threading.Thread(target=worker)
    t.start()
    t.join() # Wait synchronously for the parsing thread to finish translating data

    return packets_data

# ==========================================
# 3. AI Generation Engine
# ==========================================

def generate_ai_report(pcap_json, persona, analyze_intent):
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("Error: GEMINI_API_KEY environment variable is not set.")
        return None, None

    client = genai.Client(api_key=api_key)

    # Compile final System Prompt incorporating the Root Prompt and Selected Persona
    system_instruction = f"{ROOT_PROMPT}\n\n{PERSONAS[persona]}"
    if analyze_intent:
        system_instruction += f"\n\n{BEHAVIOR_INTENT_ADDENDUM}"

    prompt_content = f"Please analyze the following parsed network packet capture (PCAP) data in JSON format:\n\n{pcap_json}"

    try:
        # Phase 1: Generate Primary Report
        config = types.GenerateContentConfig(system_instruction=system_instruction, temperature=0.1)
        response = client.models.generate_content(model='gemini-2.5-flash', contents=prompt_content, config=config)
        primary_report = response.text

        # Phase 2: Execute Self-Verification Audit Pass (Fact-Check List Pattern)
        fact_check_prompt_content = f"RAW PACKET DATA:\n{pcap_json}\n\nGENERATED REPORT:\n{primary_report}"
        fact_check_config = types.GenerateContentConfig(system_instruction=FACT_CHECK_PROMPT, temperature=0.0)
        fact_check_response = client.models.generate_content(model='gemini-2.5-flash', contents=fact_check_prompt_content, config=fact_check_config)
        audit_log = fact_check_response.text

        return primary_report, audit_log
        
    except Exception as e:
        st.error(f"Error communicating with Gemini API: {str(e)}")
        return None, None

def interact_flipped_agent(history, user_input, pcap_json, persona):
    """
    Handles multi-turn conversation states for the Flipped Interaction Pattern loop.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    client = genai.Client(api_key=api_key)

    system_instruction = f"{ROOT_PROMPT}\n\n{PERSONAS[persona]}\n\n{FLIPPED_INTERACTION_PROMPT}"
    
    # Pack data history into API conversation chunks
    contents = [f"CONTEXT DATA REFERENCE:\n{pcap_json}"]
    for msg in history:
        role = "user" if msg["role"] == "user" else "model"
        contents.append(f"{role.upper()}: {msg['content']}")
        
    if user_input:
        contents.append(f"USER: {user_input}")

    config = types.GenerateContentConfig(system_instruction=system_instruction, temperature=0.3)
    response = client.models.generate_content(model='gemini-2.5-flash', contents=contents, config=config)
    return response.text

# ==========================================
# 4. Streamlit Frontend UI Layout
# ==========================================

def main():
    st.set_page_config(page_title="AI PCAP Analyzer", page_icon="📡", layout="wide")
    st.title("📡 AI-Powered PCAP Analyzer")
    st.markdown("Upload a network capture file (`.pcap`) and leverage Gemini 2.5 Pro to dissect traffic streams through formalized Prompt Engineering layout metrics.")

    # State Persistence Setup
    if "ai_report" not in st.session_state: st.session_state.ai_report = None
    if "audit_log" not in st.session_state: st.session_state.audit_log = None
    if "flipped_chat" not in st.session_state: st.session_state.flipped_chat = []

    with st.sidebar:
        st.header("⚙️ Analysis Settings")
        selected_persona = st.selectbox("Select AI Persona:", options=list(PERSONAS.keys()))
        analyze_intent = st.checkbox("Analyze Attacker Intent & Behavior", value=False)
        st.markdown("---")
        
        # Fact-Check Display Control Feature
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

        selection_event = st.dataframe(
            display_df, 
            width="stretch",             # Replaces use_container_width=True
            hide_index=True,
            on_select="rerun",           
            selection_mode="single-row"  
        )

        selected_rows = selection_event.selection.rows
        if selected_rows:
            st.code(parsed_data[selected_rows[0]]['Deep_Details'], language="text")

        pcap_json_string = json.dumps(display_df.to_dict(orient="records"), indent=2)
        st.divider()

        # --- Report Engine Execution ---
        col1, col2 = st.columns([2, 1]) if show_audit else (st.container(), None)

        with st.container():
            if st.button("Generate AI Report & Fact-Check Pass", type="primary"):
                with st.spinner("Compiling analysis with verification checks active..."):
                    report, audit = generate_ai_report(pcap_json_string, selected_persona, analyze_intent)
                    st.session_state.ai_report = report
                    st.session_state.audit_log = audit
                    
                    # Prime the Flipped Chat engine with its first leading query question
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

            # --- FLIPPED INTERACTION TERMINAL SECTION ---
            st.divider()
            st.subheader("Interactive Mitigation Session (Flipped Interaction Pattern)")
            st.caption("The AI agent below will ask you targeted questions step-by-step to compile a mitigation/remediation roadmap based on the incident profile.")
            
            # Render Conversational Container block
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