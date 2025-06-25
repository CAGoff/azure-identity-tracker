from fastapi import FastAPI, Request, APIRouter
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from typing import Optional
import re
import json

from auth import get_access_token
from identity import get_service_principals, get_spn_overview
from ai import assess_spn_risk
from markdown import markdown

app = FastAPI()
router = APIRouter()
templates = Jinja2Templates(directory="templates")

# Optional: if you want markdown-style formatting converted manually
def markdown_to_html(text: str) -> str:
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
    token = get_access_token()
    return {"token": token[:40] + "..."}

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/spns")
def list_spns():
    return get_service_principals()

@app.get("/report/html", response_class=HTMLResponse)
async def render_report(request: Request):
    spns = get_service_principals()
    return templates.TemplateResponse("report.html", {
        "request": request,
        "report": spns  # Jinja template expects this list of SPNs
    })

@app.get("/analyze", response_class=HTMLResponse)
async def analyze(request: Request):
    spns = get_service_principals()
    report = assess_spn_risk(spns)
    sections = parse_ai_report(report)
    return templates.TemplateResponse("analyze.html", {
        "request": request,
        "sections": sections
    })


# Optional: JSON + HTML hybrid route for API consumers
@router.api_route("/analyze", methods=["GET", "POST"])
async def analyze_spns(request: Request):
    try:
        spns = get_service_principals()
        report = assess_spn_risk(spns)

        accept_header = request.headers.get("accept", "")
        if "text/html" in accept_header:
            formatted_report = markdown_to_html(report)
            return templates.TemplateResponse("analyze.html", {
                "request": request,
                "report": formatted_report
            })

        return JSONResponse(content={"analysis": report}, status_code=200)

    except Exception as e:
        error_msg = str(e)
        if "text/html" in request.headers.get("accept", ""):
            return HTMLResponse(content=f"<h2>Error</h2><p>{error_msg}</p>", status_code=500)
        return JSONResponse(
            content={"error": error_msg, "message": "An error occurred while analyzing service principals."},
            status_code=500
        )

def parse_ai_report(text: str) -> dict:
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

    # Optional: move summary to top
    if "Overview" in sections:
        sections = {"overview": sections.pop("Overview"), **sections}

    return sections


app.include_router(router)
