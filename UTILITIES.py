import json
import pandas as pd
from colorama import Fore, Style, init
from tabulate import tabulate

def display_query_context(query_context):
    print(f"{Fore.LIGHTGREEN_EX}Query context and metadata:")
    print(f"{Fore.WHITE}Table Name:   {query_context['table_name']}")
    
    if query_context.get('start_time') and query_context.get('end_time'):
         print(f"{Fore.WHITE}Time Range:   {Fore.CYAN}{query_context['start_time']} to {query_context['end_time']}{Fore.WHITE}")
    else:
        print(f"{Fore.WHITE}Time Range:   {query_context['time_range_hours']} hour(s) lookback")

    print(f"{Fore.WHITE}Fields:       {query_context['fields']}")
    if query_context['device_name'] != "":
        print(f"{Fore.WHITE}Device:       {query_context['device_name']}")
    if query_context['caller'] != "":
        print(f"{Fore.WHITE}Caller:       {query_context['caller']}")
    if query_context['user_principal_name'] != "":
        print(f"{Fore.WHITE}Username:     {query_context['user_principal_name']}")
    print(f"{Fore.WHITE}User Related: {query_context['about_individual_user']}")
    print(f"{Fore.WHITE}Host Related: {query_context['about_individual_host']}")
    print(f"{Fore.WHITE}NSG Related:  {query_context['about_network_security_group']}")
    print(f"{Fore.WHITE}Rationale:\n{query_context['rationale']}\n")

def display_log_evidence_table(log_lines):
    """
    Parses log lines and prints them as a pretty ASCII grid table.
    """
    if not log_lines:
        print(f"{Fore.WHITE}No specific log lines cited.")
        return

    # 1. Try to structure the data
    structured_data = []
    
    for line in log_lines:
        # Sanitize: Remove markdown code blocks if the LLM added them
        clean_line = line.replace("```json", "").replace("```", "").strip()
        
        try:
            # Attempt to parse as JSON (Sentinel logs often come as JSON strings)
            parsed = json.loads(clean_line)
            if isinstance(parsed, dict):
                structured_data.append(parsed)
            else:
                structured_data.append({"Log Evidence": clean_line})
        except json.JSONDecodeError:
            # If not JSON, treat as raw text row
            structured_data.append({"Log Evidence": clean_line})

    # 2. Convert to DataFrame
    df = pd.DataFrame(structured_data)

    # 3. Clean up the DataFrame for Viewability
    # Drop columns that are completely empty
    df.dropna(axis=1, how='all', inplace=True)
    
    # Fill NaNs with empty string
    df.fillna("", inplace=True)

    # Truncate very long cells (like massive command lines) to keep table readable
    # You can adjust '100' to whatever width fits your screen
    df = df.map(lambda x: (str(x)[:100] + '...') if len(str(x)) > 100 else str(x))

    # 4. Print using Tabulate
    # 'grid' format looks like SQL/Excel
    print(Fore.WHITE + tabulate(df, headers='keys', tablefmt='grid', showindex=False))
    print(Style.RESET_ALL)

def display_threats(threat_list):
    count = 0
    for threat in threat_list:
        count += 1
        print(f"\n{Fore.MAGENTA}" + "="*80)
        print(f"{Fore.MAGENTA} POTENTIAL THREAT #{count} ")
        print(f"{Fore.MAGENTA}" + "="*80 + f"{Style.RESET_ALL}\n")
        
        print(f"{Fore.LIGHTCYAN_EX}Title:       {Fore.WHITE}{threat.get('title')}")
        
        confidence = threat.get('confidence', '').lower()
        if confidence == 'high': conf_color = Fore.LIGHTRED_EX
        elif confidence == 'medium': conf_color = Fore.LIGHTYELLOW_EX
        else: conf_color = Fore.LIGHTBLUE_EX
        
        print(f"{Fore.LIGHTCYAN_EX}Confidence:  {conf_color}{threat.get('confidence').upper()}{Style.RESET_ALL}")
        print(f"{Fore.LIGHTCYAN_EX}Description: {Fore.WHITE}{threat.get('description')}\n")

        print(f"{Fore.YELLOW}--- MITRE ATT&CK ---{Style.RESET_ALL}")
        mitre = threat.get('mitre', {})
        print(f"Tactic:      {mitre.get('tactic')}")
        print(f"Technique:   {mitre.get('technique')} ({mitre.get('id')})")
        
        print(f"\n{Fore.YELLOW}--- LOG EVIDENCE ---{Style.RESET_ALL}")
        # CALL THE NEW TABLE FUNCTION HERE
        display_log_evidence_table(threat.get('log_lines', []))

        print(f"\n{Fore.YELLOW}--- RECOMMENDATIONS ---{Style.RESET_ALL}")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")
            
        print(f"\n{Fore.YELLOW}--- IOCs ---{Style.RESET_ALL}")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\n" + "_"*80 + "\n")
    
    append_threats_to_jsonl(threat_list=threat_list)

def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    count = 0
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")
            count += 1
        # Optional: Commented out to reduce noise
        # print(f"{Fore.LIGHTBLUE_EX}\nLogged {count} threats to {filename}.\n")

def sanitize_literal(s: str) -> str:
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")

def sanitize_query_context(query_context):
    if 'caller' not in query_context:
        query_context['caller'] = ''
    
    if 'device_name' not in query_context:
        query_context['device_name'] = ''

    if 'user_principal_name' not in query_context:
        query_context['user_principal_name'] = ''

    if 'start_time' not in query_context:
        query_context['start_time'] = ''
    if 'end_time' not in query_context:
        query_context['end_time'] = ''

    if 'device_name' in query_context:
        query_context['device_name'] = sanitize_literal(query_context['device_name'])

    if 'caller' in query_context:
        query_context['caller'] = sanitize_literal(query_context['caller'])

    if "user_principal_name" in query_context:
        query_context['user_principal_name'] = sanitize_literal(query_context['user_principal_name'])

    if isinstance(query_context["fields"], list):
        query_context["fields"] = ', '.join(query_context["fields"])
    
    return query_context