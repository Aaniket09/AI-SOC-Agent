# 🛡️ AI Agentic SOC Analyst

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Azure Sentinel](https://img.shields.io/badge/Azure-Sentinel-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![OpenAI](https://img.shields.io/badge/AI-OpenAI%20GPT4-green?style=for-the-badge&logo=openai&logoColor=white)
![Security](https://img.shields.io/badge/Security-MDE%20%7C%20Graph-red?style=for-the-badge)

### 📖 [Read the full Engineering Case Study on Medium](https://medium.com/@aniketagarwal57/beyond-the-hype-building-a-reliable-full-cycle-ai-soc-agent-12aaf9dfb004)

**An autonomous cybersecurity agent that translates natural language into KQL, hunts for threats across Microsoft Sentinel & Defender for Endpoint, performs automated remediation, and engineers detection rules.**

---

## 📖 Overview

The **AI Agentic SOC Analyst** is a CLI-based tool designed to act as a force multiplier for Security Operations Centers (SOC). It automates the end-to-end incident response lifecycle:

1.  **Observe:** Takes natural language queries (e.g., *"Check for password sprays on Host-A"*).
2.  **Orient:** Translates intent into optimized KQL queries with smart time-range handling.
3.  **Decide:** Analyzes returned logs using LLMs to identify high-fidelity threats mapped to MITRE ATT&CK.
4.  **Act:** Offers active remediation (VM Isolation, AV Scans) and automated detection engineering (deploying rules to Sentinel).

---

## ✨ Key Features

### 🧠 Cognitive Threat Hunting
* **NLP to KQL:** Converts English requests into precise KQL queries for `DeviceProcessEvents`, `DeviceLogonEvents`, `AzureActivity`, and more.
* **Smart Time Context:** Handles relative times ("last 2 hours") and specific ISO ranges ("2023-11-01 to 2023-11-03").
* **LLM Analysis:** Analyzes raw logs to determine threat confidence (High/Medium/Low) and extracts IOCs.

### 🛡️ Active Remediation
* **Host Isolation:** Isolate compromised VMs in Defender for Endpoint (MDE) directly from the CLI.
* **Antivirus Scans:** Trigger remote Quick/Full AV scans on suspicious hosts.

### ⚙️ Automated Detection Engineering
* **Rule Generation:** Automatically writes high-fidelity KQL detection rules based on confirmed threats.
* **Sentinel Deployment:** Pushes new rules directly to Microsoft Sentinel via Azure Management API.
* **Guardrails:** Validates KQL schema to prevent hallucinations and blocks destructive commands (`.drop`, `.delete`).

### 💰 Enterprise-Grade Controls
* **Cost Optimization:** Estimates token usage and asks for model confirmation before expensive tasks.
* **Table Output:** Renders log evidence in clean, readable ASCII tables.

---

## 🏗️ Architecture

The agent follows a modular architecture separating logic, API execution, and safety controls.

* **`main.py`**: The orchestrator loop handling the user workflow.
* **`executor.py`**: Handles API interactions (Azure Log Analytics, Graph API, Azure Management API).
* **`guardrails.py`**: Validation logic for KQL schema, destructive commands, and time limits.
* **`prompt_management.py`**: Stores system personas (Threat Hunter, Detection Engineer) and prompt builders.
* **`utilities.py`**: UI formatting (Tabulate) and log parsing.

<img width="20149" height="3736" alt="Binary Decision Flow-2025-12-10-212825" src="https://github.com/user-attachments/assets/12681ec8-5d91-4092-ac37-21251b00a91f" />

---

## 🚀 Getting Started

### Prerequisites
* Python 3.10+
* Azure Subscription with:
    * Microsoft Sentinel (Log Analytics Workspace)
    * Microsoft Defender for Endpoint (MDE)
* OpenAI API Key
* **Azure CLI** installed and logged in (`az login`)

### Installation

1.  **Clone the repository**
    ```bash
    git clone [https://github.com/yourusername/ai-soc-analyst.git](https://github.com/yourusername/ai-soc-analyst.git)
    cd ai-soc-analyst
    ```

2.  **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Set up Environment Variables**
    Create a `.env` file in the root directory. **Do not commit this file.**
    ```env
    OPENAI_API_KEY=sk-proj-xxxx...
    LOG_ANALYTICS_WORKSPACE_ID=your-workspace-guid
    
    # Required for Sentinel Rule Deployment
    SUBSCRIPTION_ID=your-subscription-id
    RESOURCE_GROUP_NAME=your-resource-group
    SENTINEL_WORKSPACE_NAME=your-workspace-name
    ```

---

## 💻 Usage Walkthrough

### 1. Threat Hunting
**User:** "I'm worried there might be some malicious PowerShell activities going on workstation aniket-ai-soc-l in the past 4 hours."

**Agent:** Generates KQL, queries Azure, and presents a structured table of evidence.

- User prompt and mapping to a relevant KQL query demo:
<img width="2132" height="875" alt="Screenshot 2025-12-10 163808" src="https://github.com/user-attachments/assets/b4bc730f-01a9-4449-8baf-7d42d18e9e6d" />

- Log Analytics result and model selection based on estimated cost:
<img width="1878" height="918" alt="Screenshot 2025-12-10 164219" src="https://github.com/user-attachments/assets/ebdab1ce-5108-4d18-859d-e0d31a3c19dd" />

- Threat hunt result displaying with severity levels and MITRE mapping:
<img width="2148" height="1363" alt="Screenshot 2025-12-10 164810" src="https://github.com/user-attachments/assets/66583c44-86aa-40ec-bcc5-683f47dfc4a5" />

### 2. Remediation
If a High Confidence threat is found, the agent offers immediate action.

**Agent:** "High confidence threat detected on host: aniket-ai-soc-l. Would you like to isolate this VM? (yes/no)"

<img width="1671" height="259" alt="Screenshot 2025-12-10 165117" src="https://github.com/user-attachments/assets/9a6f5273-da8f-495f-8e9e-4cd4ab05caf1" />

### 3. Rule Creation (Closing the Loop)
The agent generates a KQL rule to prevent future attacks and deploys it to Sentinel.

**Agent:** "Initiating detection rule generation... Proposed Sentinel Rule: 'User-launched PowerShell_ISE.exe invoked cmd.exe to write 'Initializing Attack' to C:\Temp\Steal_Data\init.txt'. Deploy to Sentinel?"

<img width="1880" height="741" alt="Screenshot 2025-12-10 165511" src="https://github.com/user-attachments/assets/a9c3460a-7161-4ca8-9563-7a90a53f256f" />

---

## 🔒 Permissions & Security

To fully utilize the agent, the executing Azure Identity (User or Service Principal) requires the following permissions:

| Feature | Required Role / Scope |
| :--- | :--- |
| **Log Search** | `Log Analytics Reader` |
| **VM Isolation** | MDE Security Admin or `Active Remediation` Role |
| **Sentinel Rules** | `Microsoft Sentinel Contributor` |

*Note: The agent includes fallback logic. If API deployment fails due to permissions, it will offer to save the rule to a local `local_rules.kql` file.*

---

## 📂 Project Structure

```text
.
├── main.py                 # Core logic loop
├── executor.py             # API handlers (Azure, OpenAI)
├── guardrails.py           # Safety checks and validation
├── prompt_management.py    # LLM System prompts and templates
├── model_management.py     # Token counting and cost estimation
├── utilities.py            # UI formatting (Tables, Colors)
├── _keys.py                # Environment variable loader
├── .env                    # Secrets (Not committed to Git)
└── requirements.txt        # Python dependencies
