import streamlit as st
import re

st.set_page_config(page_title="AI Phishing Threat Detector", page_icon="🛡️")

st.title("🛡️ AI-Powered Phishing Threat Detector")
st.write("Analyze incoming web links and URLs for potential security threats in real time.")

url_input = st.text_input("Enter URL to analyze:", placeholder="https://example.com")

if st.button("Evaluate Threat Score"):
    if url_input:
        score = 0
        indicators = []

        # Heuristic 1: IP Address Host
        if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url_input):
            score += 40
            indicators.append("IP address host detected")

        # Heuristic 2: Suspicious Keyword Stacking
        keywords = ["login", "verify", "account", "update", "security", "paypal", "bank"]
        found = [kw for kw in keywords if kw in url_input.lower()]
        if len(found) >= 2:
            score += 30
            indicators.append(f"Suspicious keyword stacking detected: {', '.join(found)}")

        # Heuristic 3: Non-HTTPS Unencrypted Protocol
        if url_input.startswith("http://"):
            score += 20
            indicators.append("Unencrypted HTTP protocol in use")

        # Display Results
        st.subheader("Analysis Results")
        st.write(f"**Threat Risk Score:** {score}%")

        if score >= 60:
            st.error("🚨 HIGH THREAT RISK DETECTED")
        elif score >= 30:
            st.warning("⚠️ MODERATE THREAT RISK")
        else:
            st.success("✅ LOW THREAT RISK (SAFE)")

        if indicators:
            st.write("### Flagged Risk Indicators:")
            for ind in indicators:
                st.write(f"- 🔴 {ind}")
    else:
        st.info("Please enter a valid URL to analyze.")
