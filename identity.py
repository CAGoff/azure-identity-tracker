import requests
from auth import get_access_token
from typing import List, Dict, Any
import json
from datetime import datetime, timedelta, timezone

def get_service_principals():
    """Get service principals with error handling and retry logic"""
    print("📡 Calling Microsoft Graph for SPNs...")

    try:
        token = get_access_token()
        url = "https://graph.microsoft.com/v1.0/servicePrincipals?$top=50&$select=id,appId,displayName,accountEnabled,createdDateTime,servicePrincipalType,appDisplayName,description"
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        data = response.json()
        spns = data.get("value", [])
        
        print(f"✅ Successfully retrieved {len(spns)} SPNs.")
        return spns
        
    except requests.exceptions.Timeout:
        print("⏱️ Request to Microsoft Graph timed out.")
        return {
            "error": "Request timed out after 10 seconds",
            "status_code": 504,
            "retry_after": 30
        }
    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error getting SPNs: {e}")
        return {
            "error": f"HTTP {e.response.status_code}: {e.response.text}",
            "status_code": e.response.status_code,
            "details": e.response.text
        }
    except requests.exceptions.RequestException as e:
        print(f"❌ Error getting SPNs: {e}")
        return {
            "error": str(e),
            "status_code": None,
            "details": "Network or connection error"
        }
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return {
            "error": f"Unexpected error: {str(e)}",
            "status_code": 500,
            "details": "Internal error occurred"
        }

def get_spn_overview():
    """Generate enhanced SPN overview report with risk indicators"""
    print("📄 Generating enhanced SPN overview report...")

    try:
        spns = get_service_principals()
        
        # If there was an error getting SPNs, return the error
        if isinstance(spns, dict) and "error" in spns:
            return spns

        report = []
        risk_summary = {
            "total_spns": len(spns),
            "enabled_spns": 0,
            "disabled_spns": 0,
            "app_spns": 0,
            "managed_identity_spns": 0,
            "legacy_spns": 0,
            "suspicious_spns": 0
        }

        for spn in spns:
            # Basic info
            spn_info = {
                "displayName": spn.get("displayName"),
                "appId": spn.get("appId"),
                "enabled": spn.get("accountEnabled"),
                "createdDateTime": spn.get("createdDateTime"),
                "servicePrincipalType": spn.get("servicePrincipalType"),
                "appDisplayName": spn.get("appDisplayName"),
                "description": spn.get("description"),
                "risk_indicators": []
            }

            # Risk analysis
            if spn.get("accountEnabled"):
                risk_summary["enabled_spns"] += 1
            else:
                risk_summary["disabled_spns"] += 1
                spn_info["risk_indicators"].append("Disabled account")

            # Check SPN type
            spn_type = spn.get("servicePrincipalType", "").lower()
            if spn_type == "application":
                risk_summary["app_spns"] += 1
            elif spn_type == "managedidentity":
                risk_summary["managed_identity_spns"] += 1

            # Check for legacy SPNs (older than 2 years)
            created_date = spn.get("createdDateTime")
            if created_date:
                try:
                    created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                    age_days = (datetime.now().replace(tzinfo=created.tzinfo) - created).days
                    
                    if age_days > 365 * 2:  # Older than 2 years
                        risk_summary["legacy_spns"] += 1
                        spn_info["risk_indicators"].append(f"Legacy SPN ({age_days} days old)")
                        
                    spn_info["age_days"] = age_days
                except Exception:
                    spn_info["age_days"] = "Unknown"

            # Check for suspicious naming patterns
            display_name = spn.get("displayName", "").lower()
            suspicious_patterns = ["test", "temp", "dev", "old", "backup", "deprecated", "demo"]
            for pattern in suspicious_patterns:
                if pattern in display_name:
                    risk_summary["suspicious_spns"] += 1
                    spn_info["risk_indicators"].append(f"Suspicious name pattern: '{pattern}'")
                    break

            # Check for missing critical fields
            if not spn.get("displayName"):
                spn_info["risk_indicators"].append("Missing display name")
            
            if not spn.get("appId"):
                spn_info["risk_indicators"].append("Missing application ID")

            report.append(spn_info)

        print(f"✅ Enhanced report created with {len(report)} SPNs and risk analysis.")
        
        return {
            "spns": report,
            "risk_summary": risk_summary,
            "timestamp": datetime.now().isoformat()
        }

    except Exception as e:
        print(f"❌ Failed to generate enhanced SPN report: {e}")
        return {
            "error": str(e),
            "status_code": 500,
            "details": "Failed to generate enhanced report"
        }

def get_spn_permissions(spn_id: str):
    """Get detailed permissions for a specific SPN"""
    print(f"🔍 Getting permissions for SPN: {spn_id}")
    
    try:
        token = get_access_token()
        
        # Get app role assignments
        roles_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{spn_id}/appRoleAssignments"
        
        # Get OAuth2 permission grants
        oauth_url = f"https://graph.microsoft.com/v1.0/servicePrincipals/{spn_id}/oauth2PermissionGrants"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        # Fetch both types of permissions
        roles_response = requests.get(roles_url, headers=headers, timeout=10)
        oauth_response = requests.get(oauth_url, headers=headers, timeout=10)
        
        permissions = {
            "app_roles": roles_response.json().get("value", []) if roles_response.status_code == 200 else [],
            "oauth2_permissions": oauth_response.json().get("value", []) if oauth_response.status_code == 200 else [],
            "permission_analysis": {}
        }

        # Analyze permission risks
        permissions["permission_analysis"] = analyze_permissions(permissions)
        
        print(f"✅ Retrieved permissions for SPN {spn_id}")
        return permissions

    except Exception as e:
        print(f"❌ Error getting permissions for SPN {spn_id}: {e}")
        return {
            "error": str(e),
            "app_roles": [],
            "oauth2_permissions": [],
            "permission_analysis": {"risk_level": "unknown", "issues": ["Failed to analyze permissions"]}
        }

def analyze_permissions(permissions: Dict) -> Dict[str, Any]:
    """Analyze permissions for security risks"""
    analysis = {
        "risk_level": "low",
        "risk_score": 0,
        "issues": [],
        "recommendations": []
    }
    
    app_roles = permissions.get("app_roles", [])
    oauth2_perms = permissions.get("oauth2_permissions", [])
    
    # High-risk app roles
    high_risk_roles = [
        "Application.ReadWrite.All",
        "Directory.ReadWrite.All", 
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "RoleManagement.ReadWrite.Directory"
    ]
    
    # Check for high-risk permissions
    for role in app_roles:
        role_id = role.get("appRoleId", "")
        # In a real implementation, you'd map role IDs to names
        # For now, we'll do basic risk assessment
        if role_id:
            analysis["risk_score"] += 10
            analysis["issues"].append(f"High-privilege app role detected: {role_id}")
    
    # Check OAuth2 permissions
    for perm in oauth2_perms:
        scope = perm.get("scope", "")
        if "write" in scope.lower() or "all" in scope.lower():
            analysis["risk_score"] += 5
            analysis["issues"].append(f"Broad OAuth2 permission: {scope}")
    
    # Determine overall risk level
    if analysis["risk_score"] > 50:
        analysis["risk_level"] = "high"
        analysis["recommendations"].append("Review and reduce excessive permissions")
    elif analysis["risk_score"] > 20:
        analysis["risk_level"] = "medium"
        analysis["recommendations"].append("Consider implementing principle of least privilege")
    else:
        analysis["risk_level"] = "low"
        analysis["recommendations"].append("Permission levels appear appropriate")
    
    if len(app_roles) + len(oauth2_perms) == 0:
        analysis["issues"].append("No permissions found - may indicate misconfiguration")
    
    return analysis

def get_spn_sign_in_activity(spn_id: str, days: int = 30):
    """Get sign-in activity for SPN (requires additional permissions)"""
    print(f"📊 Getting sign-in activity for SPN: {spn_id}")
    
    try:
        token = get_access_token()
        
        # Note: This requires additional Graph permissions that may not be available
        # in all tenants. This is a placeholder for the functionality.
        url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=servicePrincipalId eq '{spn_id}'"
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 403:
            return {
                "error": "Insufficient permissions to access sign-in logs",
                "sign_ins": [],
                "activity_summary": {"status": "unavailable"}
            }
        
        sign_ins = response.json().get("value", []) if response.status_code == 200 else []
        
        # Analyze activity
        activity_summary = analyze_sign_in_activity(sign_ins, days)
        
        return {
            "sign_ins": sign_ins[:10],  # Return only recent 10
            "activity_summary": activity_summary,
            "total_sign_ins": len(sign_ins)
        }

    except Exception as e:
        print(f"❌ Error getting sign-in activity: {e}")
        return {
            "error": str(e),
            "sign_ins": [],
            "activity_summary": {"status": "error"}
        }

def analyze_sign_in_activity(sign_ins: List[Dict], days: int) -> Dict[str, Any]:
    """Analyze sign-in patterns for anomalies"""
    if not sign_ins:
        return {
            "status": "no_activity",
            "last_sign_in": None,
            "risk_indicators": ["No recent sign-in activity"],
            "recommendations": ["Verify if SPN is still needed"]
        }
    
    # Sort by date
    sorted_sign_ins = sorted(sign_ins, key=lambda x: x.get("createdDateTime", ""), reverse=True)
    
    analysis = {
        "status": "active",
        "last_sign_in": sorted_sign_ins[0].get("createdDateTime"),
        "total_sign_ins": len(sign_ins),
        "unique_ips": len(set(si.get("ipAddress", "") for si in sign_ins)),
        "risk_indicators": [],
        "recommendations": []
    }
    
    # Check for unusual patterns
    if analysis["unique_ips"] > 10:
        analysis["risk_indicators"].append(f"Sign-ins from {analysis['unique_ips']} different IP addresses")
    
    # Check for failed sign-ins
    failed_sign_ins = [si for si in sign_ins if si.get("status", {}).get("errorCode") != 0]
    if len(failed_sign_ins) > len(sign_ins) * 0.1:  # More than 10% failed
        analysis["risk_indicators"].append(f"{len(failed_sign_ins)} failed sign-in attempts")
    
    if not analysis["risk_indicators"]:
        analysis["recommendations"].append("Sign-in activity appears normal")
    else:
        analysis["recommendations"].append("Review unusual sign-in patterns")
    
    return analysis

def get_comprehensive_spn_report(spn_id: str = None):
    """Get a comprehensive security report for SPNs"""
    print("📋 Generating comprehensive SPN security report...")
    
    try:
        # Get all SPNs
        spns_data = get_spn_overview()
        
        if isinstance(spns_data, dict) and "error" in spns_data:
            return spns_data
        
        spns = spns_data["spns"]
        risk_summary = spns_data["risk_summary"]
        
        # If specific SPN requested, get detailed info
        detailed_analysis = None
        if spn_id:
            target_spn = next((spn for spn in spns if spn.get("id") == spn_id), None)
            if target_spn:
                detailed_analysis = {
                    "spn_info": target_spn,
                    "permissions": get_spn_permissions(spn_id),
                    "activity": get_spn_sign_in_activity(spn_id)
                }
        
        # Generate security recommendations
        recommendations = generate_security_recommendations(risk_summary, spns)
        
        report = {
            "summary": risk_summary,
            "spns": spns,
            "detailed_analysis": detailed_analysis,
            "security_recommendations": recommendations,
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "total_spns_analyzed": len(spns),
                "risk_categories": calculate_risk_categories(spns)
            }
        }
        
        print(f"✅ Comprehensive report generated for {len(spns)} SPNs")
        return report
        
    except Exception as e:
        print(f"❌ Error generating comprehensive report: {e}")
        return {
            "error": str(e),
            "status_code": 500,
            "details": "Failed to generate comprehensive report"
        }

def generate_security_recommendations(risk_summary: Dict, spns: List[Dict]) -> List[Dict]:
    """Generate actionable security recommendations"""
    recommendations = []
    
    # Check for disabled SPNs
    if risk_summary["disabled_spns"] > 0:
        recommendations.append({
            "priority": "high",
            "category": "cleanup",
            "title": "Remove Disabled Service Principals",
            "description": f"Found {risk_summary['disabled_spns']} disabled service principals that should be removed to reduce attack surface",
            "action": "Review and delete unused service principals",
            "affected_count": risk_summary["disabled_spns"]
        })
    
    # Check for legacy SPNs
    if risk_summary["legacy_spns"] > 0:
        recommendations.append({
            "priority": "medium",
            "category": "modernization", 
            "title": "Update Legacy Service Principals",
            "description": f"Found {risk_summary['legacy_spns']} service principals older than 2 years",
            "action": "Review legacy SPNs for continued business need and update or retire",
            "affected_count": risk_summary["legacy_spns"]
        })
    
    # Check for suspicious naming
    if risk_summary["suspicious_spns"] > 0:
        recommendations.append({
            "priority": "medium",
            "category": "naming",
            "title": "Review Suspicious Service Principal Names",
            "description": f"Found {risk_summary['suspicious_spns']} SPNs with potentially problematic naming patterns",
            "action": "Rename or retire test/temp/dev service principals in production",
            "affected_count": risk_summary["suspicious_spns"]
        })
    
    # Overall security posture
    total_risks = risk_summary["disabled_spns"] + risk_summary["legacy_spns"] + risk_summary["suspicious_spns"]
    risk_percentage = (total_risks / risk_summary["total_spns"]) * 100 if risk_summary["total_spns"] > 0 else 0
    
    if risk_percentage > 20:
        recommendations.append({
            "priority": "high",
            "category": "governance",
            "title": "Implement SPN Lifecycle Management",
            "description": f"High risk percentage ({risk_percentage:.1f}%) indicates need for better SPN governance",
            "action": "Establish regular SPN review and cleanup processes",
            "affected_count": total_risks
        })
    
    return recommendations

def calculate_risk_categories(spns: List[Dict]) -> Dict[str, int]:
    """Calculate risk category distribution"""
    categories = {
        "low_risk": 0,
        "medium_risk": 0, 
        "high_risk": 0,
        "critical_risk": 0
    }
    
    for spn in spns:
        risk_count = len(spn.get("risk_indicators", []))
        
        if risk_count == 0:
            categories["low_risk"] += 1
        elif risk_count <= 2:
            categories["medium_risk"] += 1
        elif risk_count <= 4:
            categories["high_risk"] += 1
        else:
            categories["critical_risk"] += 1
    
    return categories

def get_spn_sign_in_logs(app_id: str, days: int = 30):
    """Retrieve sign-in logs for a specific SPN using appId"""
    print(f"📊 Retrieving sign-in logs for SPN with appId: {app_id} (last {days} days)...")
    
    try:
        token = get_access_token()
        
        # Calculate the start date for filtering
        start_date = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Filter sign-ins for the specific appId within the last `days` days
        url = f"https://graph.microsoft.com/v1.0/auditLogs/signIns?$filter=appId eq '{app_id}' and createdDateTime ge {start_date}"

        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }

        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        sign_in_logs = response.json().get("value", [])
        
        print(f"✅ Retrieved {len(sign_in_logs)} sign-in logs for SPN with appId {app_id}.")
        return sign_in_logs

    except requests.exceptions.HTTPError as e:
        print(f"❌ HTTP Error retrieving sign-in logs: {e}")
        return {
            "error": f"HTTP {e.response.status_code}: {e.response.text}",
            "status_code": e.response.status_code,
            "details": e.response.text
        }
    except requests.exceptions.RequestException as e:
        print(f"❌ Error retrieving sign-in logs: {e}")
        return {
            "error": str(e),
            "status_code": None,
            "details": "Network or connection error"
        }
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return {
            "error": f"Unexpected error: {str(e)}",
            "status_code": 500,
            "details": "Internal error occurred"
        }
        
# Force a new commit for staging environment

