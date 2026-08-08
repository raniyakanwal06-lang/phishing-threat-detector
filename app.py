import streamlit as st
import re

# Page Configuration
st.set_page_config(page_title="AI Phishing Threat Detector", layout="centered")
st.title("🛡️ AI-Powered Phishing Threat Detector")
st.write("Analyze suspicious URLs or email text to determine social engineering threat risk.")

# Threat Detection Logic
def extract_heuristics(input_text):
    flags = []
    score = 0

    if len(input_text) > 75:
        flags.append("Excessive text/link length (>75 chars)")
        score += 20
    if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', input_text):
        flags.append("Raw IP address used instead of domain name")
        score += 35
    if "@" in input_text:
        flags.append("Contains '@' symbol (credential harvesting pattern)")
        score += 25
    if re.search(r'urgent|verify|suspended|bank|update|login|account|claim', input_text, re.I):
        flags.append("High-risk social engineering keywords detected")
        score += 20

    return min(score, 99), flags

# User Input
user_input = st.text_area("Paste suspicious link or email body text here:")

if st.button("Evaluate Threat Score"):
    if not user_input.strip():
        st.warning("Please enter text or a URL to analyze.")
    else:
        risk_score, indicators = extract_heuristics(user_input)

        st.subheader("Analysis Summary")
        if risk_score >= 60:
            st.error(f"⚠️ HIGH THREAT RISK: {risk_score}%")
        elif risk_score >= 30:
            st.warning(f"⚡ MODERATE RISK: {risk_score}%")
        else:
            st.success(f"✅ LOW RISK: {risk_score}%")

        st.write("### Flagged Risk Indicators")
        if indicators:
            for ind in indicators:
                st.write(f"- 🔴 {ind}")
        else:
            st.write("- 🟢 No major suspicious heuristics flagged.")
