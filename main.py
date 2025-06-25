from fastapi import FastAPI, Request, APIRouter, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from typing import Optional, Dict, List, Any
import re
import json
import datetime
from datetime import datetime, timedelta

from auth import get_access_token
from identity import get_service_principals, get_spn_overview
from ai import assess_spn_risk
from markdown import markdown

app = FastAPI()
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# In-memory cache for dashboard stats (in production, use Redis or database)
dashboard_cache = {
    "last_scan": None,
    "risk_factors": 0,
    "security_score": 0,
    "analysis_history": []
}

def analyze_risk_factors(spns: List[Dict]) -> Dict[str, Any]:
    """
    Analyze SPNs for actual risk factors and return detailed metrics
    """
    if not isinstance(spns, list) or not spns:
        return {
            "total_spns": 0,
            "risk_factors": 0,
            "critical_risks": 0,
            "warnings": 0,
            "security_score": 0,
            "risk_details": []
        }
    
    total_spns = len(spns)
    risk_factors = 0
    critical_risks = 0
    warnings = 0
    risk_details = []
    
    for spn in spns:
        spn_risks = []
        
        # Check for disabled SPNs (potential orphaned identities)
        if not spn.get('accountEnabled', True):
            risk_factors += 1
            warnings += 1
            spn_risks.append("Disabled service principal (potential orphan)")
        
        # Check for SPNs without display names
        if not spn.get('displayName') or spn.get('displayName', '').strip() == '':
            risk_factors += 1
            warnings += 1
            spn_risks.append("Missing display name")
        
        # Check for very old SPNs (potential legacy)
        created_date = spn.get('createdDateTime')
        if created_date:
            try:
                created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                age_days = (datetime.now().replace(tzinfo=created.tzinfo) - created).days
                
                if age_days > 365 * 2:  # Older than 2 years
                    risk_factors += 1
                    warnings += 1
                    spn_risks.append(f"Legacy SPN (created {age_days} days ago)")
                elif age_days > 365 * 5:  # Older than 5 years
                    risk_factors += 1
                    critical_risks += 1
                    spn_risks.append(f"Very old SPN (created {age_days} days ago)")
            except:
                pass
        
        # Check for SPNs with suspicious patterns in names
        display_name = spn.get('displayName', '').lower()
        suspicious_patterns = ['test', 'temp', 'dev', 'old', 'backup', 'deprecated']
        for pattern in suspicious_patterns:
            if pattern in display_name:
                risk_factors += 1
                warnings += 1
                spn_risks.append(f"Suspicious name pattern: '{pattern}'")
                break
        
        # Check for SPNs without app IDs (unusual)
        if not spn.get('appId'):
            risk_factors += 1
            critical_risks += 1
            spn_risks.append("Missing application ID")
        
        if spn_risks:
            risk_details.append({
                "spn_name": spn.get('displayName', 'Unknown'),
                "app_id": spn.get('appId', 'N/A'),
                "risks": spn_risks
            })
    
    # Calculate security score (0-100, higher is better)
    if total_spns == 0:
        security_score = 100
    else:
        risk_percentage = (risk_factors / total_spns) * 100
        security_score = max(0, 100 - risk_percentage)
    
    return {
        "total_spns": total_spns,
        "risk_factors": risk_factors,
        "critical_risks": critical_risks,
        "warnings": warnings,
        "security_score": round(security_score, 1),
        "risk_details": risk_details
    }

def markdown_to_html(text: str) -> str:
    """Convert markdown-style text to HTML"""
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'^### (.*?)$', r'<h3>\1</h3>', text, flags=re.MULTILINE)
    text = re.sub(r'^## (.*?)$', r'<h2>\1</h2>', text, flags=re.MULTILINE)
    text = re.sub(r'^# (.*?)$', r'<h1>\1</h1>', text, flags=re.MULTILINE)
    text = re.sub(r'^- (.*?)$', r'<li>\1</li>', text, flags=re.MULTILINE)
    if "<li>" in text:
        text = "<ul>" + text + "</ul>"
    return text.replace("\n", "<br>\n")

@app.get("/favicon.ico")
async def favicon():
    return Response(content="", media_type="image/x-icon")

@app.get("/token")
def test_token():
    """Test endpoint to verify authentication"""
    try:
        token = get_access_token()
        return {"status": "success", "token_preview": token[:40] + "...", "length": len(token)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Authentication failed: {str(e)}")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """Enhanced home page with real dashboard data"""
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """
    API endpoint that provides real dashboard statistics
    This is what the home page JavaScript calls to populate the stats
    """
    try:
        # Get fresh SPN data
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            return JSONResponse(
                content={
                    "error": spns["error"],
                    "stats": {
                        "spn_count": "Error",
                        "risk_factors": "Error", 
                        "security_score": "Error",
                        "last_scan": "Error",
                        "status": "🔴"
                    }
                },
                status_code=500
            )
        
        # Analyze risks
        risk_analysis = analyze_risk_factors(spns)
        
        # Update cache
        dashboard_cache.update({
            "last_scan": datetime.now().isoformat(),
            "risk_factors": risk_analysis["risk_factors"],
            "security_score": risk_analysis["security_score"]
        })
        
        return {
            "status": "success",
            "stats": {
                "spn_count": risk_analysis["total_spns"],
                "risk_factors": risk_analysis["risk_factors"],
                "security_score": f"{risk_analysis['security_score']}%",
                "last_scan": "Just now",
                "status": "🟢" if risk_analysis["critical_risks"] == 0 else "🟡" if risk_analysis["critical_risks"] < 3 else "🔴"
            },
            "details": {
                "critical_risks": risk_analysis["critical_risks"],
                "warnings": risk_analysis["warnings"],
                "risk_details": risk_analysis["risk_details"][:5]  # Top 5 for summary
            }
        }
        
    except Exception as e:
        return JSONResponse(
            content={
                "error": str(e),
                "stats": {
                    "spn_count": "Error",
                    "risk_factors": "Error",
                    "security_score": "Error", 
                    "last_scan": "Error",
                    "status": "🔴"
                }
            },
            status_code=500
        )

@app.get("/spns")
def list_spns():
    """Enhanced SPN listing with risk analysis"""
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            return spns
            
        # Add risk analysis to each SPN
        risk_analysis = analyze_risk_factors(spns)
        
        return {
            "spns": spns,
            "summary": {
                "total": risk_analysis["total_spns"],
                "risk_factors": risk_analysis["risk_factors"],
                "security_score": risk_analysis["security_score"]
            },
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/risk-analysis")
async def get_risk_analysis():
    """
    Dedicated endpoint for detailed risk analysis
    This is what the "Risk Factors" card links to
    """
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            raise HTTPException(status_code=500, detail=spns["error"])
            
        risk_analysis = analyze_risk_factors(spns)
        
        return {
            "analysis": risk_analysis,
            "recommendations": generate_risk_recommendations(risk_analysis),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def generate_risk_recommendations(risk_analysis: Dict) -> List[str]:
    """Generate actionable recommendations based on risk analysis"""
    recommendations = []
    
    if risk_analysis["critical_risks"] > 0:
        recommendations.append("🔴 Immediate action required: Review and remediate critical security risks")
    
    if risk_analysis["warnings"] > 5:
        recommendations.append("🟡 Consider reviewing service principals with suspicious naming patterns")
    
    if risk_analysis["security_score"] < 70:
        recommendations.append("📊 Security score below 70% - implement regular SPN hygiene practices")
    
    # Check for specific risk patterns
    for detail in risk_analysis["risk_details"]:
        if any("Very old SPN" in risk for risk in detail["risks"]):
            recommendations.append("🕐 Archive or update legacy service principals older than 5 years")
            break
    
    for detail in risk_analysis["risk_details"]:
        if any("Disabled service principal" in risk for risk in detail["risks"]):
            recommendations.append("🗑️ Remove disabled service principals to reduce attack surface")
            break
    
    if not recommendations:
        recommendations.append("✅ No immediate security concerns identified")
    
    return recommendations

@app.get("/report/html", response_class=HTMLResponse)
async def render_report(request: Request):
    """Enhanced report with risk analysis"""
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            return templates.TemplateResponse("error.html", {
                "request": request,
                "error": spns["error"]
            })
            
        risk_analysis = analyze_risk_factors(spns)
        
        return templates.TemplateResponse("report.html", {
            "request": request,
            "report": spns,
            "risk_analysis": risk_analysis,
            "recommendations": generate_risk_recommendations(risk_analysis),
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        
    except Exception as e:
        return templates.TemplateResponse("error.html", {
            "request": request,
            "error": str(e)
        })

@app.get("/analyze", response_class=HTMLResponse)
async def analyze(request: Request):
    """Enhanced analysis page with real AI analysis"""
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            return templates.TemplateResponse("analyze.html", {
                "request": request,
                "error": spns["error"]
            })
            
        # Get AI analysis
        ai_report = assess_spn_risk(spns)
        
        # Get risk analysis for summary cards
        risk_analysis = analyze_risk_factors(spns)
        
        # Parse AI report into sections
        sections = parse_ai_report(ai_report)
        
        return templates.TemplateResponse("analyze.html", {
            "request": request,
            "sections": sections,
            "risk_analysis": risk_analysis,
            "ai_report": ai_report
        })
        
    except Exception as e:
        return templates.TemplateResponse("analyze.html", {
            "request": request,
            "error": str(e)
        })

@router.api_route("/analyze", methods=["GET", "POST"])
async def analyze_spns_api(request: Request):
    """API endpoint for running analysis"""
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            raise HTTPException(status_code=500, detail=spns["error"])
            
        # Run AI analysis
        ai_report = assess_spn_risk(spns)
        
        # Get risk metrics
        risk_analysis = analyze_risk_factors(spns)
        
        # Update cache
        dashboard_cache["analysis_history"].append({
            "timestamp": datetime.now().isoformat(),
            "risk_factors": risk_analysis["risk_factors"],
            "security_score": risk_analysis["security_score"]
        })
        
        # Keep only last 10 analyses
        dashboard_cache["analysis_history"] = dashboard_cache["analysis_history"][-10:]
        
        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            sections = parse_ai_report(ai_report)
            return templates.TemplateResponse("analyze.html", {
                "request": request,
                "sections": sections,
                "risk_analysis": risk_analysis
            })

        return JSONResponse(content={
            "analysis": ai_report,
            "risk_metrics": risk_analysis,
            "recommendations": generate_risk_recommendations(risk_analysis),
            "timestamp": datetime.now().isoformat()
        }, status_code=200)

    except Exception as e:
        error_msg = str(e)
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(content=f"<h2>Error</h2><p>{error_msg}</p>", status_code=500)
        return JSONResponse(
            content={
                "error": error_msg, 
                "message": "An error occurred while analyzing service principals."
            },
            status_code=500
        )

@app.get("/api/analysis/history")
async def get_analysis_history():
    """Get historical analysis data for trending"""
    return {
        "history": dashboard_cache["analysis_history"],
        "current": {
            "risk_factors": dashboard_cache["risk_factors"],
            "security_score": dashboard_cache["security_score"],
            "last_scan": dashboard_cache["last_scan"]
        }
    }

def parse_ai_report(text: str) -> dict:
    """Parse AI report into structured sections"""
    sections = {}
    current_section = None
    buffer = []

    for line in text.splitlines():
        if line.strip().startswith("#### "):  # heading
            if current_section:
                sections[current_section] = markdown("\n".join(buffer))
                buffer = []
            current_section = line.replace("####", "").strip()
        else:
            buffer.append(line)

    if current_section and buffer:
        sections[current_section] = markdown("\n".join(buffer))

    # Move overview to top if exists
    if "Overview" in sections:
        sections = {"overview": sections.pop("Overview"), **sections}

    return sections

@app.get("/api/docs", response_class=HTMLResponse)
async def api_documentation(request: Request):
    """API Documentation page that the home page links to"""
    api_docs = {
        "title": "Azure Identity Tracker API",
        "version": "1.0.0",
        "description": "REST API for Azure Active Directory Service Principal security analysis",
        "endpoints": [
            {
                "method": "GET",
                "path": "/",
                "description": "Main dashboard with real-time statistics",
                "response": "HTML dashboard page"
            },
            {
                "method": "GET", 
                "path": "/api/dashboard/stats",
                "description": "Get real-time dashboard statistics",
                "response": {
                    "stats": {
                        "spn_count": "number",
                        "risk_factors": "number", 
                        "security_score": "string",
                        "last_scan": "string",
                        "status": "emoji"
                    },
                    "details": {
                        "critical_risks": "number",
                        "warnings": "number",
                        "risk_details": "array"
                    }
                }
            },
            {
                "method": "GET",
                "path": "/spns", 
                "description": "List all service principals with risk analysis",
                "response": {
                    "spns": "array",
                    "summary": "object",
                    "timestamp": "string"
                }
            },
            {
                "method": "GET",
                "path": "/api/risk-analysis",
                "description": "Get detailed risk analysis for all SPNs",
                "response": {
                    "analysis": "object",
                    "recommendations": "array",
                    "timestamp": "string"
                }
            },
            {
                "method": "POST",
                "path": "/analyze",
                "description": "Run AI-powered security analysis",
                "headers": {
                    "Accept": "application/json OR text/html"
                },
                "response": {
                    "analysis": "string",
                    "risk_metrics": "object", 
                    "recommendations": "array"
                }
            },
            {
                "method": "GET",
                "path": "/api/analysis/history",
                "description": "Get historical analysis data for trending",
                "response": {
                    "history": "array",
                    "current": "object"
                }
            },
            {
                "method": "GET",
                "path": "/report/html",
                "description": "Generate formatted HTML security report",
                "response": "HTML report page"
            },
            {
                "method": "GET",
                "path": "/token",
                "description": "Test authentication token (debug endpoint)",
                "response": {
                    "status": "string",
                    "token_preview": "string"
                }
            }
        ],
        "authentication": "Microsoft Entra ID (Azure AD)",
        "rate_limits": "50 requests per minute per user",
        "examples": [
            {
                "title": "Get Dashboard Stats",
                "curl": "curl -X GET 'https://your-app.azurewebsites.net/api/dashboard/stats'",
                "javascript": """
fetch('/api/dashboard/stats')
  .then(response => response.json())
  .then(data => console.log(data.stats));
"""
            },
            {
                "title": "Run Security Analysis",
                "curl": "curl -X POST 'https://your-app.azurewebsites.net/analyze' -H 'Accept: application/json'",
                "javascript": """
fetch('/analyze', {
  method: 'POST',
  headers: { 'Accept': 'application/json' }
})
.then(response => response.json())
.then(data => console.log(data.analysis));
"""
            }
        ]
    }
    
    return templates.TemplateResponse("api_docs.html", {
        "request": request,
        "api_docs": api_docs
    })

@app.get("/api/export/report")
async def export_report(format: str = "json"):
    """Export security report in various formats"""
    try:
        spns = get_service_principals()
        
        if isinstance(spns, dict) and "error" in spns:
            raise HTTPException(status_code=500, detail=spns["error"])
            
        risk_analysis = analyze_risk_factors(spns)
        ai_report = assess_spn_risk(spns)
        
        report_data = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "Azure Identity Security Analysis",
                "version": "1.0.0"
            },
            "executive_summary": {
                "total_spns": risk_analysis["total_spns"],
                "risk_factors": risk_analysis["risk_factors"],
                "security_score": risk_analysis["security_score"],
                "critical_risks": risk_analysis["critical_risks"],
                "warnings": risk_analysis["warnings"]
            },
            "detailed_analysis": ai_report,
            "risk_breakdown": risk_analysis["risk_details"],
            "recommendations": generate_risk_recommendations(risk_analysis)
        }
        
        if format.lower() == "json":
            return JSONResponse(content=report_data)
        elif format.lower() == "text":
            # Convert to plain text
            text_report = f"""Azure Identity Tracker - Security Report
Generated: {report_data['report_metadata']['generated_at']}

EXECUTIVE SUMMARY
=================
Total Service Principals: {report_data['executive_summary']['total_spns']}
Risk Factors Identified: {report_data['executive_summary']['risk_factors']}
Security Score: {report_data['executive_summary']['security_score']}%
Critical Risks: {report_data['executive_summary']['critical_risks']}
Warnings: {report_data['executive_summary']['warnings']}

DETAILED ANALYSIS
================
{report_data['detailed_analysis']}

RECOMMENDATIONS
===============
"""
            for i, rec in enumerate(report_data['recommendations'], 1):
                text_report += f"{i}. {rec}\n"
            
            return Response(content=text_report, media_type="text/plain")
        else:
            raise HTTPException(status_code=400, detail="Unsupported format. Use 'json' or 'text'")
            
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

app.include_router(router)