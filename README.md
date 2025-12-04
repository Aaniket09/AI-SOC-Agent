# 🛡️ AI Agentic SOC Analyst

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white)
![Azure Sentinel](https://img.shields.io/badge/Azure-Sentinel-0078D4?style=for-the-badge&logo=microsoft-azure&logoColor=white)
![OpenAI](https://img.shields.io/badge/AI-OpenAI%20GPT4-green?style=for-the-badge&logo=openai&logoColor=white)
![Security](https://img.shields.io/badge/Security-MDE%20%7C%20Graph-red?style=for-the-badge)

**An autonomous cybersecurity agent that translates natural language into KQL, hunts for threats across Microsoft Sentinel & Defender for Endpoint, performs automated remediation, and engineers detection rules.**

---

## 📖 Overview

The **AI Agentic SOC Analyst** is a CLI-based tool designed to act as a force multiplier for Security Operations Centers (SOC). It automates the end-to-end incident response lifecycle:

1.  **Observe:** Takes natural language queries (e.g., *"Check for password sprays on Host-A"*).
2.  **Orient:** Translates intent into optimized KQL queries with smart time-range handling.
3.  **Decide:** Analyzes returned logs using LLMs to identify high-fidelity threats mapped to MITRE ATT&CK.
4.  **Act:** Offers active remediation (VM Isolation, AV Scans) and automated detection engineering (deploying rules to Sentinel).

![Agent Interface Demo](docs/images/agent_demo_placeholder.png)

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
**User:** "Check for any failed login attempts on device 'windows-target-1' in the last 24 hours."

**Agent:** Generates KQL, queries Azure, and presents a structured table of evidence.

![Threat Hunt Table Results](docs/images/hunt_table_placeholder.png)

### 2. Remediation
If a High Confidence threat is found, the agent offers immediate action.

**Agent:** "High confidence threat detected on host: windows-target-1. RECOMMENDATION: Isolate VM. Proceed? (yes/no)"

![Remediation Prompt](docs/images/remediation_placeholder.png)

### 3. Rule Creation (Closing the Loop)
The agent generates a KQL rule to prevent future attacks and deploys it to Sentinel.

**Agent:** "Initiating detection rule generation... Proposed Sentinel Rule: 'Brute Force from IP 10.x.x.x'. Deploy to Sentinel?"

![Rule Deployment Success](docs/images/rule_deployment_placeholder.png)

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
