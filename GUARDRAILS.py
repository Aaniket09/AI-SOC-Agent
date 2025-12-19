from colorama import Fore, Style
from datetime import datetime
import re

# DEFINING THE TRUTH SOURCE
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

def sanitize_kql_query(kql_query: str) -> str:
    """
    Auto-corrects common LLM syntax errors in KQL to prevent deployment failures.
    """
    original_query = kql_query

    # Fix 1: Windows File Paths (Single backslash to Double backslash)
    # This prevents the exact error "Query could not be parsed at '\'"
    if "\\" in kql_query and "\\\\" not in kql_query:
        # We replace single backslashes with double, but be careful not to break existing doubles
        # A simple replace is usually safe for KQL generated by LLMs which tend to forget escaping
        kql_query = kql_query.replace("\\", "\\\\")

    # Fix 2: 'between' range syntax (SQL style 'and' -> KQL style '..')
    pattern = r"between\s*\(\s*(.+?)\s+and\s+(.+?)\s*\)"
    kql_query = re.sub(pattern, r"between (\1 .. \2)", kql_query, flags=re.IGNORECASE)

    # Fix 3: Common Column Hallucinations
    replacements = {
        "FirstSeen": "TimeGenerated",
        "LogonResult": "ActionType",
        "SourceIp": "RemoteIP",
        "DestinationIp": "RemoteIP",
        "MalwareName": "FileName" # Context dependent, but safe fallback
    }
    
    for bad_col, good_col in replacements.items():
        if bad_col in kql_query:
            kql_query = kql_query.replace(bad_col, good_col)
            
    if kql_query != original_query:
        print(f"{Fore.YELLOW}[Guardrail] Auto-corrected KQL syntax errors (Backslashes/Schema).")
    
    return kql_query 


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
    Uses regex to extract potential column names.
    """
    print(f"{Fore.LIGHTGREEN_EX}Validating KQL Schema (Hallucination Check)...")
    
    # 1. Extract Table Name
    clean_query = "\n".join([line for line in kql_query.split('\n') if not line.strip().startswith("//")])
    first_word_match = re.match(r"^\s*([a-zA-Z0-9_]+)", clean_query)
    
    if not first_word_match:
        # If the query starts with 'let', we skip table validation but continue to columns
        if "let " in clean_query:
             print(f"{Fore.YELLOW}Complex query detected (let statement). Skipping strict table name check.")
             return
        else:
             raise ValueError("Could not parse table name from KQL query.")
    
    table_name = first_word_match.group(1)
    
    # Only validate table if it's not a variable or special command
    if table_name in ALLOWED_TABLES:
        valid_columns = ALLOWED_TABLES[table_name]
    else:
        # If table isn't in our whitelist, we warn but don't crash (could be a join)
        print(f"{Fore.YELLOW}Warning: Target table '{table_name}' not in strict whitelist. Proceeding with caution.")
        return

    # 2. Extract Columns used in filters
    # FIXED REGEX: Uses \b (Word Boundary) to prevent matching "in" inside "String"
    # Matches: Word followed by space followed by Operator
    pattern = r"([a-zA-Z0-9_]+)\s*(?:==|!=|<>|>=|<=|>(?!=)|<(?!=)|\b(?:in~?|!in~?|contains|startswith|endswith|has|has_any|has_cs)\b)"
    
    matches = re.findall(pattern, clean_query)
    
    # KQL keywords to ignore if they get caught
    kql_keywords = {
        "where", "and", "or", "summarize", "project", "extend", "bin", "count", 
        "dcount", "iff", "datetime", "ago", "tostring", "iff", "join", "on", 
        "kind", "inner", "leftouter", "let", "union", "mv-expand"
    }

    print(f"{Fore.WHITE}  Table Identified: {table_name}")
    
    # Clean matches (remove duplicates)
    unique_matches = list(set(matches))
    print(f"{Fore.WHITE}  Columns/Keywords Checked: {unique_matches}")

    for col in unique_matches:
        if col.lower() in kql_keywords:
            continue 
        
        # --- NEW FIX: IGNORE SUPER LONG STRINGS ---
        # If the "column" is longer than 50 chars, it's definitely 
        # a base64 string or hash that the LLM forgot to quote.
        if len(col) > 50:
            print(f"{Fore.YELLOW}[Guardrail] Warning: Ignoring potential column '{col[:15]}...' (Too long, likely an unquoted value).")
            continue
        # ------------------------------------------

        if col not in valid_columns:
            print(f"{Fore.RED}  [!] Invalid Column Detected: {col}")
            raise ValueError(f"Guardrail Failed: Column '{col}' does not exist in table '{table_name}'.")

    print(f"{Fore.WHITE}Schema Check Passed. No hallucinated columns detected.\n")