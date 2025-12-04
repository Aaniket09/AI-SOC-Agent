import json
from colorama import Fore, Style, init

def display_query_context(query_context):
    print(f"{Fore.LIGHTGREEN_EX}Query context and metadata:")
    print(f"{Fore.WHITE}Table Name:   {query_context['table_name']}")
    
    # Check if we are using relative hours or specific range
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

def display_threats(threat_list):
    count = 0
    for threat in threat_list:
        count += 1
        print(f"\n=============== Potential Threat #{count} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)  # Automatically resets to default after each print

        confidence = threat.get('confidence', '').lower()

        if confidence == 'high':
            color = Fore.LIGHTRED_EX
        elif confidence == 'medium':
            color = Fore.LIGHTYELLOW_EX
        elif confidence == 'low':
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL  # Default/no color

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get('mitre', {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get('log_lines', []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get('indicators_of_compromise', []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get('tags', []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get('recommendations', []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")

        print("=" * 51)
    
    append_threats_to_jsonl(threat_list=threat_list)

def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    count = 0
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")
            count += 1
        print(f"{Fore.LIGHTBLUE_EX}\nLogged {count} threats to {filename}.\n")

def sanitize_literal(s: str) -> str:
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")

def sanitize_query_context(query_context):
    if 'caller' not in query_context:
        query_context['caller'] = ''
    
    if 'device_name' not in query_context:
        query_context['device_name'] = ''

    if 'user_principal_name' not in query_context:
        query_context['user_principal_name'] = ''

    # Handle optional date fields
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

    query_context["fields"] = ', '.join(query_context["fields"])
    
    return query_context