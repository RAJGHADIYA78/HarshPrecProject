import pandas as pd
import json
import requests
import datetime

severity_type = {
    1:"LOW",
    2:"MEDIUM",
    3:"HIGH",
    4:"CRITICAL"
}


def generate_xlsx(userInput):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV3Severity={severity_type[userInput]}"

        payload = {}
        headers = {}

        response = requests.request("GET", url, headers=headers, data=payload)

        data = json.loads(response.text)
        vulnerabilities = []
        for vuln in data['vulnerabilities']:
            cve = vuln['cve']
            print(cve['id'])
            vulnerabilities.append({
                'CVE ID': cve['id'],
                'Published': cve['published'],
                'Last Modified': cve['lastModified'],
                'Source Identifier': cve['sourceIdentifier'],
                'Description': cve['descriptions'][0]['value'] if cve['descriptions'] else '',
                'Base Severity': cve['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'] if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] else cve['metrics']['cvssMetricV30'][0]['cvssData']['baseSeverity'] if 'metrics' in cve and 'cvssMetricV30' in cve['metrics'] else '',
                'Attack Vector': cve['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'] if 'metrics' in cve and 'cvssMetricV31' in cve['metrics'] else cve['metrics']['cvssMetricV30'][0]['cvssData']['attackVector'] if 'metrics' in cve and 'cvssMetricV30' in cve['metrics'] else '',
                # 'Attack Vector': cve['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'] if cve['metrics'] and cve['metrics']['cvssMetricV31'] else '',
            })

        # Create a DataFrame
        df = pd.DataFrame(vulnerabilities)

        data_time = datetime.datetime.now()

        name = f'vulnerabilities_{data_time.strftime("%Y")}_{data_time.strftime("%m")}_{data_time.strftime("%d")}_{data_time.strftime("%M")}_{data_time.strftime("%S")}.xlsx'
        # Save to Excel
        df.to_excel(f'{name}.xlsx', index=False)

        return True
    
    except Exception as e:
        print("Exception ::", e)
        return False


def get_user_inpout():
    # ANSI escape codes for green text
    GREEN = "\033[92m"
    RESET = "\033[0m"


    RED = "\033[91m"
    RED_RESET = "\033[0m"


    YELLOW = "\033[93m"
    YELLOW_RESET = "\033[0m"

    # Example usage
    print(f"{GREEN}'Ask not what can country can do for you, but what can you do for your country?'{RESET}")
    print(f"{RED}'Ask not what can country can do for you, but what can you do for your country?'{RED_RESET}")


    print(f"{YELLOW}what minimum security vulnerability would you like to be notified about?{YELLOW_RESET}")

    print(f"{YELLOW}1. Low{YELLOW_RESET}")
    print(f"{YELLOW}2. Medium{YELLOW_RESET}")
    print(f"{YELLOW}3. High{YELLOW_RESET}")
    print(f"{YELLOW}4. Critical{YELLOW_RESET}")
    print(f"{YELLOW}5. Exit{YELLOW_RESET}")


    userInput = int(input())

    if userInput == 5:
        return None

    return generate_xlsx(userInput)

def main():
    return get_user_inpout()


if __name__ == "__main__":
    response = main()
