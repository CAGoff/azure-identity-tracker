import requests
from auth import get_access_token

def get_service_principals():
    print("📡 Calling Microsoft Graph for SPNs...")

    token = get_access_token()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=50"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        print("✅ SPNs pulled successfully.")
        return response.json().get("value", [])
    except requests.exceptions.Timeout:
        print("⏱️ Request to Microsoft Graph timed out.")
        return {
            "error": "Request timed out",
            "status_code": 504
        }
    except requests.exceptions.RequestException as e:
        print(f"❌ Error getting SPNs: {e}")
        return {
            "error": str(e),
            "status_code": response.status_code if 'response' in locals() else None,
            "details": response.text if 'response' in locals() else None
        }
def get_spn_overview():
    print("📄 Generating SPN overview report...")

    token = get_access_token()
    url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=50"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json().get("value", [])

        report = []
        for spn in data.get("value", []):
            report.append({
                "displayName": spn.get("displayName"),
                "appId": spn.get("appId"),
                "enabled": spn.get("accountEnabled"),
                "createdDateTime": spn.get("createdDateTime")
            })

        print(f"✅ Report created with {len(report)} SPNs.")
        return report

    except requests.exceptions.Timeout:
        print("⏱️ SPN report request timed out.")
        return {
            "error": "Request timed out",
            "status_code": 504
        }
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to generate SPN report: {e}")
        return {
            "error": str(e),
            "status_code": response.status_code if 'response' in locals() else None,
            "details": response.text if 'response' in locals() else None
        }
    
