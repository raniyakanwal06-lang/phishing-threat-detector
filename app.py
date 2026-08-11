{
  "nbformat": 4,
  "nbformat_minor": 0,
  "metadata": {
    "colab": {
      "provenance": [],
      "authorship_tag": "ABX9TyN3IPvwB8yraXK8D/HtyjVO"
    },
    "kernelspec": {
      "name": "python3",
      "display_name": "Python 3"
    },
    "language_info": {
      "name": "python"
    }
  },
  "cells": [
    {
      "cell_type": "code",
      "execution_count": 1,
      "metadata": {
        "id": "EtYy34VNCWEW"
      },
      "outputs": [],
      "source": [
        "import re\n",
        "\n",
        "def check_phishing_url(url):\n",
        "    score = 0\n",
        "    flags = []\n",
        "\n",
        "    # Check for IP address in URL\n",
        "    if re.search(r\"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\", url):\n",
        "        score += 40\n",
        "        flags.append(\"IP address host detected\")\n",
        "\n",
        "    # Check for suspicious keywords\n",
        "    keywords = [\"login\", \"verify\", \"account\", \"update\", \"security\"]\n",
        "    found = [kw for kw in keywords if kw in url.lower()]\n",
        "    if len(found) >= 2:\n",
        "        score += 30\n",
        "        flags.append(f\"Suspicious keywords: {', '.join(found)}\")\n",
        "\n",
        "    # Check for HTTP protocol\n",
        "    if url.startswith(\"http://\"):\n",
        "        score += 20\n",
        "        flags.append(\"Unencrypted HTTP protocol\")\n",
        "\n",
        "    return score, flags"
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "!pip install streamlit -q\n",
        "!npm install -g localtunnel\n"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "09PvVzGhDyna",
        "outputId": "c7bc7344-b5fe-4bde-f086-4698410d95dd"
      },
      "execution_count": 3,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "\u001b[1G\u001b[0K⠙\u001b[1G\u001b[0K⠹\u001b[1G\u001b[0K⠸\u001b[1G\u001b[0K⠼\u001b[1G\u001b[0K⠴\u001b[1G\u001b[0K⠦\u001b[1G\u001b[0K⠧\u001b[1G\u001b[0K\n",
            "changed 22 packages in 938ms\n",
            "\u001b[1G\u001b[0K⠧\u001b[1G\u001b[0K\n",
            "\u001b[1G\u001b[0K⠧\u001b[1G\u001b[0K3 packages are looking for funding\n",
            "\u001b[1G\u001b[0K⠧\u001b[1G\u001b[0K  run `npm fund` for details\n",
            "\u001b[1G\u001b[0K⠧\u001b[1G\u001b[0K"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "%%writefile app.py\n",
        "import streamlit as st\n",
        "import re\n",
        "\n",
        "st.set_page_config(page_title=\"AI Phishing Threat Detector\", page_icon=\"🛡️\")\n",
        "\n",
        "st.title(\"🛡️ AI-Powered Phishing Threat Detector\")\n",
        "st.write(\"Analyze incoming web links and URLs for potential security threats in real time.\")\n",
        "\n",
        "url_input = st.text_input(\"Enter URL to analyze:\", placeholder=\"https://example.com\")\n",
        "\n",
        "if st.button(\"Evaluate Threat Score\"):\n",
        "    if url_input:\n",
        "        score = 0\n",
        "        indicators = []\n",
        "\n",
        "        # Heuristic 1: IP Address Host\n",
        "        if re.search(r\"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\", url_input):\n",
        "            score += 40\n",
        "            indicators.append(\"IP address host detected\")\n",
        "\n",
        "        # Heuristic 2: Suspicious Keyword Stacking\n",
        "        keywords = [\"login\", \"verify\", \"account\", \"update\", \"security\", \"paypal\", \"bank\"]\n",
        "        found = [kw for kw in keywords if kw in url_input.lower()]\n",
        "        if len(found) >= 2:\n",
        "            score += 30\n",
        "            indicators.append(f\"Suspicious keyword stacking detected: {', '.join(found)}\")\n",
        "\n",
        "        # Heuristic 3: Non-HTTPS Unencrypted Protocol\n",
        "        if url_input.startswith(\"http://\"):\n",
        "            score += 20\n",
        "            indicators.append(\"Unencrypted HTTP protocol in use\")\n",
        "\n",
        "        # Display Results\n",
        "        st.subheader(\"Analysis Results\")\n",
        "        st.write(f\"**Threat Risk Score:** {score}%\")\n",
        "\n",
        "        if score >= 60:\n",
        "            st.error(\"🚨 HIGH THREAT RISK DETECTED\")\n",
        "        elif score >= 30:\n",
        "            st.warning(\"⚠️ MODERATE THREAT RISK\")\n",
        "        else:\n",
        "            st.success(\"✅ LOW THREAT RISK (SAFE)\")\n",
        "\n",
        "        if indicators:\n",
        "            st.write(\"### Flagged Risk Indicators:\")\n",
        "            for ind in indicators:\n",
        "                st.write(f\"- 🔴 {ind}\")\n",
        "    else:\n",
        "        st.info(\"Please enter a valid URL to analyze.\")"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "VZnZ8FZmEIgS",
        "outputId": "d304bd78-1290-4167-c29b-c6ec5bc3fb6d"
      },
      "execution_count": 4,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "Writing app.py\n"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "!curl https://loca.lt/mytunnelpassword\n"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "NCBZ_4kjERUL",
        "outputId": "8ce757c7-de79-4d87-b4db-0518ad36b71c"
      },
      "execution_count": 5,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "34.81.157.228"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "!streamlit run app.py --server.port 8501 --server.enableCORS=false --server.enableXsrfProtection=false & npx localtunnel --port 8501"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "3RFnRhVCEcFg",
        "outputId": "5eb2ce82-b291-4f6d-ab2f-97786175c81e"
      },
      "execution_count": 7,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "\u001b[1G\u001b[0K⠙\n",
            "Collecting usage statistics. To deactivate, set browser.gatherUsageStats to false.\n",
            "\u001b[0m\n",
            "\u001b[1G\u001b[0K⠹\u001b[1G\u001b[0K⠸\u001b[1G\u001b[0K⠼\u001b[1G\u001b[0K⠴\u001b[1G\u001b[0K⠦\u001b[1G\u001b[0K2026-08-11 09:17:28.722 Uvicorn server started on :::8501\n",
            "\u001b[0m\n",
            "\u001b[34m\u001b[1m  You can now view your Streamlit app in your browser.\u001b[0m\n",
            "\u001b[0m\n",
            "\u001b[34m  Local URL: \u001b[0m\u001b[1mhttp://localhost:8501\u001b[0m\n",
            "\u001b[34m  Network URL: \u001b[0m\u001b[1mhttp://172.28.0.12:8501\u001b[0m\n",
            "\u001b[34m  External URL: \u001b[0m\u001b[1mhttp://34.81.157.228:8501\u001b[0m\n",
            "\u001b[0m\n",
            "your url is: https://lazy-moose-love.loca.lt\n",
            "\u001b[34m  Stopping...\u001b[0m\n",
            "^C\n"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "!wget -q -O cloudflared https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64\n",
        "!chmod +x cloudflared"
      ],
      "metadata": {
        "id": "mWiDkbYlJJad"
      },
      "execution_count": 8,
      "outputs": []
    },
    {
      "cell_type": "code",
      "source": [
        "!streamlit run app.py --server.port 8501 & ./cloudflared tunnel --url http://localhost:8501"
      ],
      "metadata": {
        "colab": {
          "base_uri": "https://localhost:8080/"
        },
        "id": "Q5ryTgVrJQH1",
        "outputId": "be9e8940-58dd-4f3b-ef69-4ae3f0779f96"
      },
      "execution_count": null,
      "outputs": [
        {
          "output_type": "stream",
          "name": "stdout",
          "text": [
            "\u001b[90m2026-08-11T09:26:28Z\u001b[0m \u001b[32mINF\u001b[0m Thank you for trying Cloudflare Tunnel. Doing so, without a Cloudflare account, is a quick way to experiment and try it out. However, be aware that these account-less Tunnels have no uptime guarantee, are subject to the Cloudflare Online Services Terms of Use (https://www.cloudflare.com/website-terms/), and Cloudflare reserves the right to investigate your use of Tunnels for violations of such terms. If you intend to use Tunnels in production you should use a pre-created named tunnel by following: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps\n",
            "\u001b[90m2026-08-11T09:26:28Z\u001b[0m \u001b[32mINF\u001b[0m Requesting new quick Tunnel on trycloudflare.com...\n",
            "\n",
            "Collecting usage statistics. To deactivate, set browser.gatherUsageStats to false.\n",
            "\u001b[0m\n",
            "2026-08-11 09:26:30.176 Uvicorn server started on :::8501\n",
            "\u001b[0m\n",
            "\u001b[34m\u001b[1m  You can now view your Streamlit app in your browser.\u001b[0m\n",
            "\u001b[0m\n",
            "\u001b[34m  Local URL: \u001b[0m\u001b[1mhttp://localhost:8501\u001b[0m\n",
            "\u001b[34m  Network URL: \u001b[0m\u001b[1mhttp://172.28.0.12:8501\u001b[0m\n",
            "\u001b[34m  External URL: \u001b[0m\u001b[1mhttp://34.81.157.228:8501\u001b[0m\n",
            "\u001b[0m\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m +--------------------------------------------------------------------------------------------+\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):  |\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m |  https://inf-declare-completely-videos.trycloudflare.com                                   |\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m +--------------------------------------------------------------------------------------------+\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Cannot determine default configuration path. No file [config.yml config.yaml] in [~/.cloudflared ~/.cloudflare-warp ~/cloudflare-warp /etc/cloudflared /usr/local/etc/cloudflared]\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Version 2026.7.3 (Checksum 9d71c677db00134c1bd4144b7783486b654ad281b1ea62b4972098d19f770f17)\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m GOOS: linux, GOVersion: go1.26.4, GoArch: amd64\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Settings: map[ha-connections:1 protocol:quic url:http://localhost:8501]\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m cloudflared will not automatically update when run from the shell. To enable auto-updates, run cloudflared as a service: https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/configure-tunnels/local-management/as-a-service/\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Generated Connector ID: b09eac59-83dc-4953-a74a-0378d91270eb\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Initial protocol quic\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m ICMP proxy will use 172.28.0.12 as source for IPv4\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m ICMP proxy will use ::1 in zone lo as source for IPv6\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m ICMP proxy will use 172.28.0.12 as source for IPv4\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m ICMP proxy will use ::1 in zone lo as source for IPv6\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Starting metrics server on 127.0.0.1:20241/metrics\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Tunnel connection curve preferences: [X25519MLKEM768 CurveID(65074) CurveP256] \u001b[36mconnIndex=\u001b[0m0 \u001b[36mevent=\u001b[0m0 \u001b[36mip=\u001b[0m198.41.192.7\n",
            "2026/08/11 09:26:37 failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB). See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.\n",
            "\u001b[90m2026-08-11T09:26:37Z\u001b[0m \u001b[32mINF\u001b[0m Registered tunnel connection \u001b[36mconnIndex=\u001b[0m0 \u001b[36mconnection=\u001b[0mb17c765b-3a47-41ee-9c0b-f8b25e5678c2 \u001b[36mevent=\u001b[0m0 \u001b[36mip=\u001b[0m198.41.192.7 \u001b[36mlocation=\u001b[0mhkg01 \u001b[36mprotocol=\u001b[0mquic\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m +-------------------------------------------------------------------------------------+\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |                               CONNECTIVITY PRE-CHECKS                               |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m +-------------------------------------------------------------------------------------+\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  COMPONENT         TARGET                     STATUS  DETAILS                       |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  DNS Resolution    region1.v2.argotunnel.com  PASS    DNS Resolved successfully     |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  DNS Resolution    region2.v2.argotunnel.com  PASS    DNS Resolved successfully     |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  UDP Connectivity  region1.v2.argotunnel.com  PASS    QUIC connection successful    |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  UDP Connectivity  region2.v2.argotunnel.com  PASS    QUIC connection successful    |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  TCP Connectivity  region1.v2.argotunnel.com  PASS    HTTP/2 connection successful  |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  TCP Connectivity  region2.v2.argotunnel.com  PASS    HTTP/2 connection successful  |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  Cloudflare API    api.cloudflare.com:443     PASS    API is reachable              |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |                                                                                     |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m |  SUMMARY: Environment is healthy. cloudflared will use 'quic' as primary protocol.  |\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m +-------------------------------------------------------------------------------------+\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"DNS Resolution\" \u001b[36mdetails=\u001b[0m\"DNS Resolved successfully\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion1.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"DNS Resolution\" \u001b[36mdetails=\u001b[0m\"DNS Resolved successfully\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion2.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"UDP Connectivity\" \u001b[36mdetails=\u001b[0m\"QUIC connection successful\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion1.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"UDP Connectivity\" \u001b[36mdetails=\u001b[0m\"QUIC connection successful\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion2.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"TCP Connectivity\" \u001b[36mdetails=\u001b[0m\"HTTP/2 connection successful\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion1.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"TCP Connectivity\" \u001b[36mdetails=\u001b[0m\"HTTP/2 connection successful\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mregion2.v2.argotunnel.com\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck \u001b[36mcomponent=\u001b[0m\"Cloudflare API\" \u001b[36mdetails=\u001b[0m\"API is reachable\" \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36mstatus=\u001b[0mpass \u001b[36mtarget=\u001b[0mapi.cloudflare.com:443\n",
            "\u001b[90m2026-08-11T09:26:43Z\u001b[0m \u001b[32mINF\u001b[0m precheck complete \u001b[36mhard_fail=\u001b[0mfalse \u001b[36mrun_id=\u001b[0m9cee72ef-4ac6-4061-81c6-154edea38412 \u001b[36msuggested_protocol=\u001b[0mquic\n"
          ]
        }
      ]
    },
    {
      "cell_type": "code",
      "source": [
        "%%writefile app.py\n",
        "import streamlit as st\n",
        "import re\n",
        "\n",
        "st.set_page_config(page_title=\"AI Phishing Threat Detector\", page_icon=\"🛡️\")\n",
        "\n",
        "st.title(\"🛡️ AI-Powered Phishing Threat Detector\")\n",
        "st.write(\"Analyze incoming web links and URLs for potential security threats in real time.\")\n",
        "\n",
        "url_input = st.text_input(\"Enter URL to analyze:\", placeholder=\"https://example.com\")\n",
        "\n",
        "if st.button(\"Evaluate Threat Score\"):\n",
        "    if url_input:\n",
        "        score = 0\n",
        "        indicators = []\n",
        "\n",
        "        # Heuristic 1: IP Address Host\n",
        "        if re.search(r\"\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\", url_input):\n",
        "            score += 40\n",
        "            indicators.append(\"IP address host detected\")\n",
        "\n",
        "        # Heuristic 2: Suspicious Keyword Stacking\n",
        "        keywords = [\"login\", \"verify\", \"account\", \"update\", \"security\", \"paypal\", \"bank\"]\n",
        "        found = [kw for kw in keywords if kw in url_input.lower()]\n",
        "        if len(found) >= 2:\n",
        "            score += 30\n",
        "            indicators.append(f\"Suspicious keyword stacking detected: {', '.join(found)}\")\n",
        "\n",
        "        # Heuristic 3: Non-HTTPS Unencrypted Protocol\n",
        "        if url_input.startswith(\"http://\"):\n",
        "            score += 20\n",
        "            indicators.append(\"Unencrypted HTTP protocol in use\")\n",
        "\n",
        "        # Display Results\n",
        "        st.subheader(\"Analysis Results\")\n",
        "        st.write(f\"**Threat Risk Score:** {score}%\")\n",
        "\n",
        "        if score >= 60:\n",
        "            st.error(\"🚨 HIGH THREAT RISK DETECTED\")\n",
        "        elif score >= 30:\n",
        "            st.warning(\"⚠️ MODERATE THREAT RISK\")\n",
        "        else:\n",
        "            st.success(\"✅ LOW THREAT RISK (SAFE)\")\n",
        "\n",
        "        if indicators:\n",
        "            st.write(\"### Flagged Risk Indicators:\")\n",
        "            for ind in indicators:\n",
        "                st.write(f\"- 🔴 {ind}\")\n",
        "    else:\n",
        "        st.info(\"Please enter a valid URL to analyze.\")"
      ],
      "metadata": {
        "id": "qW6yG4PCPfLt"
      },
      "execution_count": null,
      "outputs": []
    }
  ]
}