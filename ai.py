import os
import json
from openai import AzureOpenAI
import hashlib
import os
from pathlib import Path


def get_input_hash(data):
    """Hash the normalized SPN input"""
    if isinstance(data, str):
        data = json.loads(data)
    normalized = json.dumps(data, sort_keys=True)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ✅ Azure OpenAI configuration
client = AzureOpenAI(
    api_key=os.getenv("OPENAI_API_KEY"),
    api_version="2025-01-01-preview",
    azure_endpoint="https://ai-credigyopenai-dev-eus.openai.azure.com"
)

def assess_spn_risk(spns):
    try:
        if isinstance(spns, str):
            spns = json.loads(spns)

        if not isinstance(spns, list):
            raise ValueError("SPN data must be a list of dictionaries")

        # Step 1: Cache key
        hash_key = get_input_hash(spns)
        cache_dir = Path(".cache")
        cache_dir.mkdir(exist_ok=True)
        cache_path = cache_dir / f"{hash_key}.json"

        # Step 2: If cached, return it
        if cache_path.exists():
            with open(cache_path, "r") as f:
                return json.load(f)["report"]

        # Step 3: Build prompt
        spn_summary = "\n".join([
            f"- Name: {spn.get('displayName', 'Unknown')}, AppID: {spn.get('appId', 'No AppID')}, Enabled: {spn.get('accountEnabled', 'Unknown')}"
            for spn in spns
        ])

        prompt = f"""You are a security analyst. Analyze the following Azure service principals and identify potential risks, overprivileged identities, or unused entries:\n\n{spn_summary}\n\nProvide a concise report."""

        # Step 4: Call Azure OpenAI
        response = client.chat.completions.create(
            model="gpt-4o-security",
            temperature=0,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert."},
                {"role": "user", "content": prompt}
            ]
        )

        report = response.choices[0].message.content

        # Step 5: Cache the result
        with open(cache_path, "w") as f:
            json.dump({"report": report}, f)

        return report

    except Exception as e:
        return f"Error while analyzing SPNs: {str(e)}"
