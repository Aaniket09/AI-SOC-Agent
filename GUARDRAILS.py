from colorama import Fore, Style
from datetime import datetime

# TODO: Provide allowed fields later
ALLOWED_TABLES = {
    "DeviceProcessEvents": { "TimeGenerated", "AccountName", "ActionType", "DeviceName", "InitiatingProcessCommandLine", "ProcessCommandLine" },
    "DeviceNetworkEvents": { "TimeGenerated", "ActionType", "DeviceName", "RemoteIP", "RemotePort" },
    "DeviceLogonEvents": { "TimeGenerated", "AccountName", "DeviceName", "ActionType", "RemoteIP", "RemoteDeviceName" },
    "AlertInfo": {},  # No fields specified in tools
    "AlertEvidence": {},  # No fields specified in tools
    "DeviceFileEvents": {"TimeGenerated","ActionType","DeviceName","FileName","FolderPath","InitiatingProcessAccountName","SHA256"},
    "DeviceRegistryEvents": {},  # No fields specified in tools
    "AzureNetworkAnalytics_CL": { "TimeGenerated", "FlowType_s", "SrcPublicIPs_s", "DestIP_s", "DestPort_d", "VM_s", "AllowedInFlows_d", "AllowedOutFlows_d", "DeniedInFlows_d", "DeniedOutFlows_d" },
    "AzureActivity": {"TimeGenerated", "OperationNameValue", "ActivityStatusValue", "ResourceGroup", "Caller", "CallerIpAddress", "Category" },
    "SigninLogs": {"TimeGenerated", "UserPrincipalName", "OperationName", "Category", "ResultSignature", "ResultDescription", "AppDisplayName", "IPAddress", "LocationDetails" },
}

# https://platform.openai.com/docs/models/compare
ALLOWED_MODELS = {
    "gpt-4.1-nano": {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 0.10, "cost_per_million_output": 0.40,  "tier": {"free": 40_000, "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 150_000_000}},
    "gpt-4.1":      {"max_input_tokens": 1_047_576, "max_output_tokens": 32_768,  "cost_per_million_input": 1.00, "cost_per_million_output": 8.00,  "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 30_000_000}},
    "gpt-5-mini":   {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 0.25, "cost_per_million_output": 2.00,  "tier": {"free": None,   "1": 200_000, "2": 2_000_000, "3": 4_000_000, "4": 10_000_000, "5": 180_000_000}},
    "gpt-5":        {"max_input_tokens": 272_000,   "max_output_tokens": 128_000, "cost_per_million_input": 1.25, "cost_per_million_output": 10.00, "tier": {"free": None,   "1": 30_000,  "2": 450_000,   "3": 800_000,   "4": 2_000_000,  "5": 40_000_000}}
}

def validate_tables_and_fields(table, fields):

    print(f"{Fore.LIGHTGREEN_EX}Validating Tables and Fields...")
    if table not in ALLOWED_TABLES:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: "f"Table '{table}' is not in allowed list — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    
    fields = fields.replace(' ','').split(',')

    for field in fields:
        if field not in ALLOWED_TABLES[table]:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Field '{field}' is not in allowed list for Table '{table}' — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
            exit(1)
    
    print(f"{Fore.WHITE}Fields and tables have been validated and comply with the allowed guidelines.\n")

def validate_time_range(start_time: str, end_time: str):
    """
    Validates that the difference between start_time and end_time does not exceed 72 hours.
    Takes strings in ISO format.
    """
    if not start_time or not end_time:
        return # Skip validation if using relative hours

    try:
        # Parse common formats, primarily ISO 8601
        dt_start = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        dt_end = datetime.fromisoformat(end_time.replace('Z', '+00:00'))
        
        diff = dt_end - dt_start
        total_hours = diff.total_seconds() / 3600.0
        
        print(f"{Fore.LIGHTGREEN_EX}Validating time range: {total_hours:.2f} hours requested...")

        if total_hours < 0:
             print(f"{Fore.RED}{Style.BRIGHT}ERROR: End time is before start time! — {Style.RESET_ALL}exiting.")
             exit(1)

        if total_hours > 72:
            print(f"{Fore.RED}{Style.BRIGHT}ERROR: Requested time range ({total_hours:.1f} hours) exceeds the 72-hour safety limit. — {Style.RESET_ALL}exiting.")
            print(f"{Fore.WHITE}Please narrow your search to a 3-day window.")
            exit(1)
        
        print(f"{Fore.WHITE}Time range is within safety limits.\n")

    except ValueError as e:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Invalid date format provided. Please use ISO format. ({e}) — {Style.RESET_ALL}exiting.")
        exit(1)


def validate_model(model):
    if model not in ALLOWED_MODELS:
        print(f"{Fore.RED}{Style.BRIGHT}ERROR: Model '{model}' is not allowed — {Fore.RED}{Style.BRIGHT}{Style.RESET_ALL}exiting.")
        exit(1)
    else:
        print(f"{Fore.LIGHTGREEN_EX}Selected model is valid: {Fore.CYAN}{model}\n{Style.RESET_ALL}")