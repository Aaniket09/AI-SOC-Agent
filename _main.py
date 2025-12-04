# Standard library
import time

# Third-party libraries
from colorama import Fore, init, Style
from openai import OpenAI
from azure.identity import DefaultAzureCredential
from azure.monitor.query import LogsQueryClient

# Local modules + MCP
import UTILITIES
import _keys
import MODEL_MANAGEMENT
import PROMPT_MANAGEMENT
import EXECUTOR
import GUARDRAILS

# Build the Log Analytics Client which is used to Query Log Analytics Workspace
# Requires you to use 'az login' at the command line first and log into Azure
law_client = LogsQueryClient(credential=DefaultAzureCredential())

# Builds the Open AI client which is used to send requests to the OpenAI API
# and have conversations with ChatGPT
openai_client = OpenAI(api_key=_keys.OPENAI_API_KEY)

# Assign the default model to be used.
# Logic will be used later to select a more appropriate model if needed
model = MODEL_MANAGEMENT.DEFAULT_MODEL

# Get the message from the user (What do you wan to hunt for?)
user_message = PROMPT_MANAGEMENT.get_user_message() #TODO: Remove comment
# Example: I'm worried that windows-target-1 might have been maliciously logged into in the last few days

# return an object that describes the user's request as well as where and how the agent has decided to search
unformatted_query_context = EXECUTOR.get_query_context(openai_client, user_message, model=model)

# sanitizing unformatted_query_context values, and normalizing field formats.
query_context = UTILITIES.sanitize_query_context(unformatted_query_context)

# Show the user where we are going to search based on their request
UTILITIES.display_query_context(query_context)

# Ensure the table and fields returned by the model are allowed to be queried
GUARDRAILS.validate_tables_and_fields(query_context["table_name"], query_context["fields"])

# Ensure the time range does not exceed 72 hours if specific dates are used
GUARDRAILS.validate_time_range(query_context["start_time"], query_context["end_time"])

# Query Log Analytics Workspace
law_query_results = EXECUTOR.query_log_analytics(
    log_analytics_client=law_client,
    workspace_id=_keys.LOG_ANALYTICS_WORKSPACE_ID,
    timerange_hours=query_context["time_range_hours"],
    start_time=query_context["start_time"],
    end_time=query_context["end_time"],
    table_name=query_context["table_name"],
    device_name=query_context["device_name"],
    fields=query_context["fields"],
    caller=query_context["caller"],
    user_principal_name=query_context["user_principal_name"])

number_of_records = law_query_results['count']

print(f"{Fore.WHITE}{number_of_records} record(s) returned.\n")

# Exit the program if no recores are returned
if number_of_records == 0:
    print("Exiting.")
    exit(0)

threat_hunt_user_message = PROMPT_MANAGEMENT.build_threat_hunt_prompt(
    user_prompt=user_message["content"],
    table_name=query_context["table_name"],
    log_data=law_query_results["records"]
)

# Grab the threat hunt system prompt
threat_hunt_system_message = PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT

# Place the system and user prompts in an array
threat_hunt_messages = [threat_hunt_system_message, threat_hunt_user_message]

# Count / estimate total input tokens
number_of_tokens = MODEL_MANAGEMENT.count_tokens(threat_hunt_messages, model)

# Observe rate limits, estimated cost, and select an model for analysis
model = MODEL_MANAGEMENT.choose_model(model, number_of_tokens)

# Ensure the selected model is allowed / valid
GUARDRAILS.validate_model(model)
print(f"{Fore.LIGHTGREEN_EX}Initiating cognitive threat hunt against targete logs...\n")

# Grab the time the analysis started for calculating analysis duration
start_time = time.time()

# Execute the threat hunt 
hunt_results = EXECUTOR.hunt(
    openai_client=openai_client,
    threat_hunt_system_message=PROMPT_MANAGEMENT.SYSTEM_PROMPT_THREAT_HUNT,
    threat_hunt_user_message=threat_hunt_user_message,
    openai_model=model
)

# Exit if no hunt results are returned
if not hunt_results:
    exit()

# Grab the time the anslysis finished and calculated the total time elapsed
elapsed = time.time() - start_time

# Notify the user of hunt anaylsis duration and findings
print(f"{Fore.WHITE}Cognitive hunt complete. Took {elapsed:.2f} seconds and found {Fore.LIGHTRED_EX}{len(hunt_results['findings'])} {Fore.WHITE}potential threat(s)!\n")

# Pause before displaying the results
input(f"Press {Fore.LIGHTGREEN_EX}[Enter]{Fore.WHITE} or {Fore.LIGHTGREEN_EX}[Return]{Fore.WHITE} to see results.")

# Display the threat hunt analysis results.
UTILITIES.display_threats(threat_list=hunt_results['findings'])

token = EXECUTOR.get_bearer_token()

machine_is_isolated = False
user_account_is_disabled = False

query_is_about_individual_host = query_context["about_individual_host"]
query_is_about_individual_user = query_context["about_individual_user"]
query_is_about_network_security_group = query_context["about_network_security_group"]

for threat in hunt_results['findings']:

    # Assess the confidence of the threat
    threat_confidence_is_high = threat["confidence"].lower() == "high"
    threat_confidence_is_medium = threat["confidence"].lower() == "medium"
    
    # Block of code for dealing with host-related threats
    if query_is_about_individual_host:
        
        
        # If the machine is already isolated, don't isolate it again in the same session (wastes API calls)
        if threat_confidence_is_high and (not machine_is_isolated):

            print(Fore.YELLOW + "[!] High confidence threat detected on host:" + Style.RESET_ALL, query_context["device_name"])
            print(Fore.LIGHTRED_EX + threat['title'])
            confirm = input(f"{Fore.RED}{Style.BRIGHT}Would you like to isolate this VM? (yes/no): " + Style.RESET_ALL).strip().lower()
            
            if confirm in ["y", "yes"]:
                machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                    token=token,
                    device_name=query_context["device_name"]
                )
                machine_is_isolated = EXECUTOR.quarantine_virtual_machine(
                    token=token,
                    machine_id=machine_id
                )
                if machine_is_isolated:
                    print(Fore.GREEN + "[+] VM successfully isolated." + Style.RESET_ALL)
                    print(Fore.CYAN + "Reminder: Release the VM from isolation when appropriate at: " + Style.RESET_ALL + "https://security.microsoft.com/")
            else:
                print(Fore.CYAN + "[i] Isolation skipped by user." + Style.RESET_ALL)
        
        elif (threat_confidence_is_medium or threat_confidence_is_high) and (not machine_is_isolated):
            print(Fore.YELLOW + "[!] Suspicious activity detected on host." + Style.RESET_ALL)
            
            confirm = input(f"{Fore.LIGHTYELLOW_EX}RECOMMENDATION: Run remote Antivirus Scan? (yes/no): " + Style.RESET_ALL).strip().lower()
            
            # FIXED: Strict check for "yes" or "y"
            if confirm in ["y", "yes"]:
                machine_id = EXECUTOR.get_mde_workstation_id_from_name(
                    token=token,
                    device_name=query_context["device_name"]
                )
                scan_launched = EXECUTOR.run_antivirus_scan(
                    token=token,
                    machine_id=machine_id,
                    scan_type="Quick" 
                )
                if scan_launched:
                    print(Fore.GREEN + "[+] Antivirus scan initiated successfully." + Style.RESET_ALL)
                else:
                    print(Fore.RED + "[-] Failed to initiate scan." + Style.RESET_ALL)
            
    # Block of code for dealing with user related threats
    elif query_is_about_individual_user:
        pass

    # Block of code for dealing with NSG related threats
    elif query_is_about_network_security_group:
        pass