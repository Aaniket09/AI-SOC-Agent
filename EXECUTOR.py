# Standard library
from datetime import timedelta, datetime
import json
import urllib.parse
import uuid 
import re 

# Third-party libraries
import pandas as pd
import requests
from colorama import Fore, Style
from openai import RateLimitError, OpenAIError
from azure.identity import DefaultAzureCredential

# Local modules
import PROMPT_MANAGEMENT


def get_bearer_token():
    credential = DefaultAzureCredential()
    token = credential.get_token("https://api.securitycenter.microsoft.com/.default")
    return token

def get_mde_workstation_id_from_name(token, device_name):
    headers = {"Authorization": f"Bearer {token.token}"}
    filter_q = urllib.parse.quote(f"startswith(computerDnsName,'{device_name}')")
    url = f"https://api.securitycenter.microsoft.com/api/machines?$filter={filter_q}"
    resp = requests.get(url, headers=headers, timeout=30)
    resp.raise_for_status()
    machines = resp.json().get("value", [])
    if not machines:
        raise Exception(f"No machine found starting with {device_name}")
    machine_id = machines[0]["id"]
    return machine_id


def quarantine_virtual_machine(token, machine_id):
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }
    payload = {
        "Comment": "Isolation via Python Agentic AI",
        "IsolationType": "Full"
    }
    resp = requests.post(
        f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/isolate",
        headers=headers,
        json=payload,
        timeout=30
    )
    if resp.status_code == 201 or resp.status_code == 200:
        return True
    return False

def run_antivirus_scan(token, machine_id, scan_type="Quick"):
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }
    payload = {
        "Comment": f"Triggered by AI SOC Analyst. Type: {scan_type}",
        "ScanType": scan_type
    }
    url = f"https://api.securitycenter.microsoft.com/api/machines/{machine_id}/runAntiVirusScan"
    try:
        resp = requests.post(url, headers=headers, json=payload, timeout=30)
        if resp.status_code == 201 or resp.status_code == 200:
            return True
        return False
    except Exception:
        return False

def normalize_sentinel_tactic(tactic_string):
    """
    Converts human-readable MITRE tactics into Azure Sentinel PascalCase Enum.
    Logic: "Defense Evasion" -> Title Case -> "DefenseEvasion" (Remove Spaces)
    """
    if not tactic_string:
        return None
    clean_text = tactic_string.title()
    normalized = re.sub(r'[^a-zA-Z0-9]', '', clean_text)
    return normalized


def create_sentinel_alert_rule(subscription_id, resource_group, workspace_name, rule_name, kql_query, description, severity, mitre_tactic=None, mitre_technique=None):
    print(f"{Fore.CYAN}Authenticating to Azure Management API (Sentinel)...")
    credential = DefaultAzureCredential()
    token = credential.get_token("https://management.azure.com/.default")
    
    headers = {
        "Authorization": f"Bearer {token.token}",
        "Content-Type": "application/json"
    }

    rule_id = str(uuid.uuid4())

    # --- GENERALIZED MAPPING LOGIC ---
    # 1. Tactics: Normalize the input string
    tactics_list = []
    if mitre_tactic:
        normalized_tactic = normalize_sentinel_tactic(mitre_tactic)
        if normalized_tactic:
            tactics_list.append(normalized_tactic)
    
    # 2. Techniques: STRICT FORMATTING (T#### only)
    # The API rejects 'T1059.001', so we must strip the suffix.
    techniques_list = []
    if mitre_technique:
        # Regex explanation:
        # T\d{4}  -> Matches exactly 'T' followed by 4 digits (e.g., T1059)
        # We IGNORE any following characters like .001
        ids = re.findall(r'T\d{4}', mitre_technique)
        if ids:
            techniques_list = list(set(ids)) # Deduplicate

    # Guardrail: If tactic is missing, default to Execution
    if not tactics_list:
        print(f"{Fore.YELLOW}[WARN] No MITRE Tactic provided. Defaulting to 'Execution'.")
        tactics_list = ["Execution"]

    url = (
        f"https://management.azure.com/subscriptions/{subscription_id}/"
        f"resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/"
        f"workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/"
        f"alertRules/{rule_id}?api-version=2024-01-01-preview"
    )

    payload = {
        "kind": "Scheduled",
        "properties": {
            "displayName": rule_name,
            "description": f"{description} (AI Generated)",
            "severity": severity,
            "enabled": True,
            "query": kql_query,
            "queryFrequency": "PT1H",
            "queryPeriod": "PT1H",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT1H",
            "suppressionEnabled": False,
            "tactics": tactics_list,     
            "techniques": techniques_list # Now contains only ['T1059'], not ['T1059.001']
        }
    }

    try:
        print(f"{Fore.LIGHTGREEN_EX}Sending rule to Sentinel with Tactics: {tactics_list} & Techniques: {techniques_list}...")
        resp = requests.put(url, headers=headers, json=payload, timeout=30)
        
        if resp.status_code in [200, 201]:
            return True, rule_id
        else:
            return False, f"HTTP {resp.status_code}: {resp.text}"

    except Exception as e:
        return False, str(e)


def hunt(openai_client, threat_hunt_system_message, threat_hunt_user_message, openai_model):
    results = []
    messages = [threat_hunt_system_message, threat_hunt_user_message]
    try:
        response = openai_client.chat.completions.create(
            model=openai_model,
            messages=messages,
            response_format={"type": "json_object"}
        )
        results = json.loads(response.choices[0].message.content)
        return results
    except RateLimitError as e:
        print(f"{Fore.LIGHTRED_EX}🚨ERROR: Rate limit or token overage detected!")
        return None
    except OpenAIError as e:
        print(f"{Fore.RED}Unexpected OpenAI API error:\n{e}")
        return None

def get_query_context(openai_client, user_message, model):
    print(f"{Fore.LIGHTGREEN_EX}\nDeciding log search parameters based on user request...\n")
    system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_TOOL_SELECTION
    response = openai_client.chat.completions.create(
        model=model,
        messages=[system_message, user_message],
        tools=PROMPT_MANAGEMENT.TOOLS,
        tool_choice="required"
    )
    function_call = response.choices[0].message.tool_calls[0]
    args = json.loads(function_call.function.arguments)
    return args 

def query_log_analytics(log_analytics_client, workspace_id, timerange_hours, table_name, device_name, fields, caller, user_principal_name, start_time, end_time):
    user_query = f"{table_name}\n"
    if start_time and end_time:
        user_query += f"| where TimeGenerated between (datetime({start_time}) .. datetime({end_time}))\n"
        try:
             s = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
             delta_to_start = datetime.now(s.tzinfo) - s
             sdk_hours = int(delta_to_start.total_seconds() / 3600) + 24
             sdk_timespan = timedelta(hours=sdk_hours)
        except:
             sdk_timespan = timedelta(days=7) 
    else:
        sdk_timespan = timedelta(hours=timerange_hours)

    if table_name == "AzureNetworkAnalytics_CL":
        user_query += f'| where FlowType_s == "MaliciousFlow"\n| project {fields}'
    elif table_name == "AzureActivity":
        user_query += f'| where isnotempty(Caller) and Caller !in ("d37a587a-4ef3-464f-a288-445e60ed248c","ef669d55-9245-4118-8ba7-f78e3e7d0212","3e4fe3d2-24ff-4972-92b3-35518d6e6462")\n'
        user_query += f'| where Caller startswith "{caller}"\n| project {fields}'
    elif table_name == "SigninLogs":
        user_query += f'| where UserPrincipalName startswith "{user_principal_name}"\n| project {fields}'
    else:
        user_query += f'| where DeviceName startswith "{device_name}"\n| project {fields}'
        
    print(f"{Fore.LIGHTGREEN_EX}Constructed KQL Query:")
    print(f"{Fore.WHITE}{user_query}\n")

    print(f"{Fore.LIGHTGREEN_EX}Querying Log Analytics Workspace ID: '{workspace_id}'...")

    response = log_analytics_client.query_workspace(
        workspace_id=workspace_id,
        query=user_query,
        timespan=sdk_timespan
    )

    if len(response.tables[0].rows) == 0:
        print(f"{Fore.WHITE}No data returned from Log Analytics.")
        return { "records": "", "count": 0 }
    
    table = response.tables[0]
    record_count = len(response.tables[0].rows)
    columns = table.columns 
    rows = table.rows 
    df = pd.DataFrame(rows, columns=columns)
    records = df.to_csv(index=False)
    return { "records": records, "count": record_count }