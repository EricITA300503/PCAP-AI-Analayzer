import os
import tempfile
import json
import asyncio
import nest_asyncio
import streamlit as st
import pandas as pd
import pyshark
from google import genai
from google.genai import types

# ==========================================
# 1. AI Persona Definitions (Template Pattern)
# ==========================================
nest_asyncio.apply()

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
2. Infer the psychological or strategic intent of the adversary based on the traffic flow (e.g., Are they scanning? Attempting lateral movement? Setting up persistence?).
3. Evaluate the sophistication of the observed activity.
Append a dedicated section titled "### Adversary Intent & Behavioral Profiling" at the end of your report to cover these points.
"""

# ==========================================
# 2. Backend Parsing Logic (PyShark)
# ==========================================

def parse_pcap_file(file_path, packet_limit=100):
    """
    Parses a PCAP file using PyShark and extracts critical attributes into a clean dictionary list.
    """
    # --- THE DEFINITIVE FIX ---
    # Create a fresh event loop specifically for this Streamlit worker thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # Apply the nest_asyncio patch directly to this new loop
    nest_asyncio.apply(loop)
    # --------------------------

    packets_data = []
    
    try:
        # Load PCAP file using PyShark
        capture = pyshark.FileCapture(file_path, keep_packets=False)
        
        count = 0
        for packet in capture:
            if count >= packet_limit:
                break
                
            try:
                # Extract base packet properties securely
                pkt_data = {
                    "No": packet.number if hasattr(packet, 'number') else "N/A",
                    "Protocol": packet.highest_layer if hasattr(packet, 'highest_layer') else "N/A",
                    "Length": packet.length if hasattr(packet, 'length') else "0",
                    "Source_IP": "N/A",
                    "Dest_IP": "N/A",
                    "Payload_Summary": "N/A",
                    "Deep_Details": str(packet) # <--- ADD THIS LINE: Captures the full Wireshark-style layer dump
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
                
            except AttributeError:
                continue
            
        capture.close()
        return packets_data

    except Exception as e:
        st.error(f"Error parsing PCAP: {str(e)}")
        return []

# ==========================================
# 3. AI Generation Engine
# ==========================================

def generate_ai_report(pcap_json, persona, analyze_intent):
    """
    Initializes the Google GenAI SDK, constructs the dynamic prompt, and fetches the report.
    """
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        st.error("Error: GEMINI_API_KEY environment variable is not set.")
        return None

    # Initialize the new Google GenAI Client
    client = genai.Client(api_key=api_key)

    # 1. Base System Instruction setup (Persona Pattern)
    system_instruction = PERSONAS[persona]
    
    # 2. Dynamic Prompt Injection for specific behaviors
    if analyze_intent:
        system_instruction += f"\n\n{BEHAVIOR_INTENT_ADDENDUM}"

    # 3. Contextual Data Setup
    # We avoid using markdown backticks here to prevent markdown parsing errors in the output
    prompt_content = f"""
Please analyze the following parsed network packet capture (PCAP) data. 
The data is provided in JSON format, representing a chronological sequence of up to 100 packets.

--- JSON DATA BEGIN ---
{pcap_json}
--- JSON DATA END ---

Deliver your analysis based strictly on your assigned system instructions and persona.
"""

    try:
        # Define the Generation Configuration
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.2, # Low temperature for more analytical, factual grounding
        )

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt_content,
            config=config
        )
        return response.text
        
    except Exception as e:
        st.error(f"Error communicating with Gemini API: {str(e)}")
        return None

# ==========================================
# 4. Streamlit Frontend UI
# ==========================================

def main():
    st.set_page_config(page_title="AI PCAP Analyzer", page_icon="📡", layout="wide")
    
    st.title("📡 AI-Powered PCAP Analyzer")
    st.markdown("Upload a network capture file (`.pcap`) and leverage Gemini 2.5 Pro to dissect the traffic using advanced Persona-based Prompt Engineering.")

    # --- Sidebar Configuration ---
    with st.sidebar:
        st.header("⚙️ Analysis Settings")
        
        # Persona Selection Dropdown
        selected_persona = st.selectbox(
            "Select AI Persona:",
            options=list(PERSONAS.keys()),
            help="Changes the system instructions to alter how the LLM interprets the network data."
        )
        
        # Intent Checkbox
        analyze_intent = st.checkbox(
            "Analyze Attacker Intent & Behavior", 
            value=False,
            help="Dynamically appends MITRE ATT&CK instructions to the context window."
        )
        
        st.markdown("---")
        st.info("Ensure your `GEMINI_API_KEY` is set in your environment variables before running.")

    # --- Main Application Area ---
    uploaded_file = st.file_uploader("Upload a .pcap file", type=["pcap", "pcapng"])

    if uploaded_file is not None:
        # Save the uploaded file to a temporary location so PyShark can read it
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pcap") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_pcap_path = tmp_file.name

        st.info(f"File uploaded successfully. Parsing up to 100 packets...")

        with st.spinner("Extracting packet attributes via PyShark..."):
            parsed_data = parse_pcap_file(tmp_pcap_path, packet_limit=100)
            
        # Clean up temporary file
        os.remove(tmp_pcap_path)

        if not parsed_data:
            st.warning("No standard packets could be parsed from this file.")
            return

        # 1. Display Data Summary Table (Interactive)
        st.subheader("📊 Network Traffic (Select a row to inspect)")
        
        df = pd.DataFrame(parsed_data)
        
        # We create a display dataframe that hides the massive "Deep_Details" column from the main table
        display_df = df.drop(columns=["Deep_Details"])

        # Render the dataframe with interactive row selection enabled
        selection_event = st.dataframe(
            display_df, 
            use_container_width=True, 
            hide_index=True,
            on_select="rerun",           # Forces the app to update when a row is clicked
            selection_mode="single-row"  # Only allow inspecting one packet at a time
        )

        # 1.5 Render the Deep Dive Pane if a packet is selected
        selected_rows = selection_event.selection.rows
        if selected_rows:
            # Get the index of the clicked row
            selected_index = selected_rows[0]
            selected_packet = parsed_data[selected_index]
            
            st.markdown(f"### 🔍 Deep Inspection: Packet #{selected_packet['No']}")
            
            # Display the full PyShark layer dump in a clean, scrollable code block
            st.code(selected_packet['Deep_Details'], language="text")
        else:
            st.info("👆 Click any packet in the table above to view its full layer breakdown.")

        # Convert ONLY the summary data to JSON for the LLM prompt (Context Window Optimization)
        # We do not send the Deep_Details to the LLM to avoid token overflow.
        pcap_json_string = json.dumps(display_df.to_dict(orient="records"), indent=2)

        st.divider()

        # 2. Trigger AI Analysis
        st.subheader(f"🧠 AI Analysis Report ({selected_persona})")
        
        if st.button("Generate AI Report", type="primary"):
            with st.spinner("Gemini 2.5 Pro is analyzing the traffic context..."):
                report_markdown = generate_ai_report(pcap_json_string, selected_persona, analyze_intent)
                
            if report_markdown:
                # Render the Markdown response in a clean container
                with st.container(border=True):
                    st.markdown(report_markdown)

if __name__ == "__main__":
    main()