import os
from msal import ConfidentialClientApplication
from dotenv import load_dotenv

print("✅ Loaded environment:")
print("TENANT_ID:", os.getenv("TENANT_ID"))
print("CLIENT_ID:", os.getenv("CLIENT_ID"))
print("CLIENT_SECRET:", os.getenv("CLIENT_SECRET")[:4], "...masked")


load_dotenv()

def get_access_token():
    app = ConfidentialClientApplication(
        client_id=os.getenv("CLIENT_ID"),
        authority=f"https://login.microsoftonline.com/{os.getenv('TENANT_ID')}",
        client_credential=os.getenv("CLIENT_SECRET")
    )

    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

    if "access_token" in result:
        return result["access_token"]
    else:
        print("❌ Failed to acquire token:")
        print(result)
        raise Exception("Authentication failed. See console for details.")
