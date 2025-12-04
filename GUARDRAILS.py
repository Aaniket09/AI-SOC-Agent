from colorama import Fore, Style
from datetime import datetime
import re

# DEFINING THE TRUTH SOURCE
# We add 'ActionType' to DeviceLogonEvents explicitly here to fix your specific error
ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine", "FileName", "FolderPath", "SHA256", "Timestamp" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort", "LocalIP", "LocalPort", "Protocol", "Timestamp" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "LogonType", "RemoteIP", "RemoteDeviceName", "Timestamp", "LogonId" },
    "AlertInfo": { "TimeGenerated", "AlertId", "Title", "Severity", "ServiceSource", "DetectionSource" },
    "AlertEvidence": { "TimeGenerated", "AlertId", "EntityType", "EvidenceRole", "FileName", "SHA1", "SHA256", "IpAddress", "AccountName" },
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256", "Timestamp"},
    "DeviceRegistryEvents": {"TimeGenerated", "ActionType", "DeviceName", "RegistryKey", "RegistryValueName", "RegistryValueData", "Timestamp"},
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails", "Identity" },
}

ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}}
}

def validate_tables_and_fields(table, fields):
    print(f"{Fore.LIGHTGREEN_EX}Validating Initial Search Parameters...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: "f"Table '{table}' is not in allowed list — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    
    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not in allowed list for Table '{table}' — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
            exit(1)
    print(f"{Fore.WHITE}Fields and tables have been validated.\n")

def validate_time_range(start_time: str, end_time: str):
    if not start_time or not end_time:
        return 
    try:
        dt_start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        dt_end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        diff = dt_end - dt_start
        total_hours = diff.total_seconds() / 3600.0
        
        if total_hours < 0:
             print(f"{Fore.RED}{Style.BRIGHT}ERROR: End time is before start time! — {Style.RESET_ALL}exiting.")
             exit(1)
        if total_hours > 72:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Time range ({total_hours:.1f} hours) exceeds 72-hour limit. — {Style.RESET_ALL}exiting.")
            exit(1)
    except ValueError as e:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Invalid date format. ({e}) — {Style.RESET_ALL}exiting.")
        exit(1)

def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)

def validate_kql_safety(kql_query: str):
    """Scans for destructive commands."""
    print(f"{Fore.LIGHTGREEN_EX}Validating KQL Safety (Destructive Check)...")
    forbidden_keywords = [".drop", ".delete", ".alter", ".create table", "purge", "drop table", "alter table"]
    normalized_query = kql_query.lower()
    for kw in forbidden_keywords:
        if kw in normalized_query:
            raise ValueError(f"Security Guardrail Triggered: Destructive command '{kw}' found.")
    print(f"{Fore.WHITE}Safety Check Passed.\n")

def validate_generated_kql_columns(kql_query: str):
    """
    Parses the generated KQL to ensure the Table and Columns exist in the schema.
    This prevents 'BadRequest' errors from Azure when the LLM hallucinates columns (e.g. LogonResult).
    """
    print(f"{Fore.LIGHTGREEN_EX}Validating KQL Schema (Hallucination Check)...")
    
    # 1. Extract Table Name (Assumes table is the first word in the query)
    # Remove leading comments or whitespace
    clean_query = "\n".join([line for line in kql_query.split('\n') if not line.strip().startswith("//")])
    first_word_match = re.match(r"^\s*([a-zA-Z0-9_]+)", clean_query)
    
    if not first_word_match:
        raise ValueError("Could not parse table name from KQL query.")
    
    table_name = first_word_match.group(1)
    
    if table_name not in ALLOWED_TABLES:
        # It might be a complex query starting with a 'let' statement or similar.
        # For this specific guardrail, we warn but allow if table isn't strictly recognized at start,
        # but since we are generating simple rules, we enforce it.
        if "let " in kql_query:
             print(f"{Fore.YELLOW}Complex query detected (let statement). Schema validation skipped for table name.")
             return
        raise ValueError(f"Generated KQL targets unknown/unsupported table: '{table_name}'")

    valid_columns = ALLOWED_TABLES[table_name]

    # 2. Extract Columns used in filters
    # Regex looks for:  Word followed by operator (==, !=, in, contains, startswith)
    # Example: "ActionType == 'LogonFailed'" -> captures "ActionType"
    pattern = r"([a-zA-Z0-9_]+)\s*(?:==|!=|in~?|!in~?|contains|startswith|endswith|has)"
    matches = re.findall(pattern, clean_query)
    
    # KQL keywords that might look like columns in this regex
    kql_keywords = {"where", "and", "or", "summarize", "project", "extend", "bin", "count", "dcount", "iff", "datetime", "ago", "tostring", "iff"}

    print(f"{Fore.WHITE}  Table Identified: {table_name}")
    print(f"{Fore.WHITE}  Columns Checked: {list(set(matches))}")

    for col in matches:
        if col.lower() in kql_keywords:
            continue # Skip keywords
        
        # Check if column is valid
        if col not in valid_columns:
            # We found a hallucination!
            print(f"{Fore.RED}  [!] Invalid Column Detected: {col}")
            raise ValueError(f"Guardrail Failed: Column '{col}' does not exist in table '{table_name}'. (Did you mean 'ActionType'?)")

    print(f"{Fore.WHITE}Schema Check Passed. No hallucinated columns detected.\n")