from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session, selectinload

from app.config import BASE_DIR, settings
from app.database import get_db
from app.models import AuditLog, CloudResource, Finding, FindingNote, Policy, RepositoryAssessment, Scan
from app.services.analytics import chart_data, compliance_matrix, dashboard_stats, iam_graph, repository_score
from app.services.policies import import_policies
from app.services.reporting import scan_csv, scan_json, scan_pdf
from app.services.scanner import compare_scans, scan_file
from app.services.seed import seed_demo

router = APIRouter()
templates = Jinja2Templates(directory=str(BASE_DIR / "app" / "templates"))


def csrf_token(request: Request) -> str:
    token = request.session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        request.session["csrf_token"] = token
    return token


templates.env.globals["csrf_token"] = csrf_token


def verify_csrf(request: Request, token: str) -> None:
    expected = request.session.get("csrf_token")
    if not expected or not secrets.compare_digest(expected, token):
        raise HTTPException(403, "Invalid CSRF token")


def context(request: Request, **kwargs: Any) -> dict[str, Any]:
    return {"request": request, "app_name": settings.app_name, **kwargs}


def paginate(query, db: Session, page: int, per_page: int = 20):
    page = max(1, page)
    total = db.scalar(select(func.count()).select_from(query.order_by(None).subquery())) or 0
    items = list(db.scalars(query.offset((page - 1) * per_page).limit(per_page)).all())
    pages = max(1, (total + per_page - 1) // per_page)
    return items, total, pages


def parse_evidence(finding: Finding) -> dict:
    try:
        return json.loads(finding.evidence or "{}")
    except json.JSONDecodeError:
        return {}


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
    stats = dashboard_stats(db)
    recent_scans = list(db.scalars(select(Scan).order_by(desc(Scan.id)).limit(6)).all())
    findings = list(db.scalars(select(Finding).options(selectinload(Finding.policy)).order_by(desc(Finding.id)).limit(8)).all())
    frameworks = compliance_matrix(db, stats["latest"].id if stats["latest"] else None)
    return templates.TemplateResponse(request=request, name="dashboard.html", context=context(request, title="Cloud Security Overview", stats=stats, recent_scans=recent_scans, findings=findings, frameworks=frameworks))


@router.get("/scans", response_class=HTMLResponse)
def scans_page(request: Request, db: Session = Depends(get_db), page: int = 1, q: str = "", grade: str = ""):
    query = select(Scan).order_by(desc(Scan.id))
    if q:
        query = query.where(or_(Scan.name.ilike(f"%{q}%"), Scan.source_name.ilike(f"%{q}%")))
    if grade:
        query = query.where(Scan.grade == grade)
    items, total, pages = paginate(query, db, page)
    return templates.TemplateResponse(request=request, name="scans.html", context=context(request, title="Security Scans", scans=items, total=total, pages=pages, page=page, q=q, grade=grade))


@router.get("/scans/new", response_class=HTMLResponse)
def new_scan(request: Request):
    return templates.TemplateResponse(request=request, name="new_scan.html", context=context(request, title="New Terraform Scan"))


@router.post("/scans/upload")
async def upload_scan(request: Request, name: str = Form(...), csrf: str = Form(...), file: UploadFile = File(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    filename = Path(file.filename or "upload").name
    if not filename.endswith((".tf", ".json", ".tf.json", ".zip")):
        raise HTTPException(400, "Upload a .tf, .json, .tf.json, or .zip file.")
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        raise HTTPException(413, "File exceeds the configured upload limit.")
    target = settings.upload_dir / f"{secrets.token_hex(8)}-{filename}"
    target.write_bytes(data)
    try:
        scan = scan_file(db, target, name.strip() or filename, "analyst")
    except Exception as exc:
        raise HTTPException(400, f"Scan failed: {exc}") from exc
    finally:
        target.unlink(missing_ok=True)
    return RedirectResponse(f"/scans/{scan.id}?toast=Scan+completed+successfully", status_code=303)


@router.post("/scans/demo")
def demo_scan(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    scan = seed_demo(db)
    return RedirectResponse(f"/scans/{scan.id}?toast=Demo+environment+loaded", status_code=303)


@router.get("/scans/{scan_id}", response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings).selectinload(Finding.policy), selectinload(Scan.findings).selectinload(Finding.resource), selectinload(Scan.resources)))
    if not scan:
        raise HTTPException(404, "Scan not found")
    return templates.TemplateResponse(request=request, name="scan_detail.html", context=context(request, title=scan.name, scan=scan, comparison=compare_scans(db, scan), compliance=compliance_matrix(db, scan.id)))


@router.get("/findings", response_class=HTMLResponse)
def findings_page(request: Request, db: Session = Depends(get_db), page: int = 1, q: str = "", severity: str = "", status: str = "", category: str = ""):
    query = select(Finding).options(selectinload(Finding.policy)).order_by(desc(Finding.id))
    if q:
        query = query.where(or_(Finding.title.ilike(f"%{q}%"), Finding.resource_address.ilike(f"%{q}%"), Finding.control_id.ilike(f"%{q}%")))
    if severity:
        query = query.where(Finding.severity == severity)
    if status:
        query = query.where(Finding.status == status)
    if category:
        query = query.where(Finding.category == category)
    items, total, pages = paginate(query, db, page)
    categories = list(db.scalars(select(Finding.category).distinct().order_by(Finding.category)).all())
    return templates.TemplateResponse(request=request, name="findings.html", context=context(request, title="Security Findings", findings=items, total=total, pages=pages, page=page, q=q, severity=severity, status=status, category=category, categories=categories))


@router.get("/findings/{finding_id}", response_class=HTMLResponse)
def finding_detail(finding_id: int, request: Request, db: Session = Depends(get_db)):
    finding = db.scalar(select(Finding).where(Finding.id == finding_id).options(selectinload(Finding.policy), selectinload(Finding.resource), selectinload(Finding.scan), selectinload(Finding.notes)))
    if not finding:
        raise HTTPException(404, "Finding not found")
    return templates.TemplateResponse(request=request, name="finding_detail.html", context=context(request, title=f"Finding #{finding.id}", finding=finding, evidence=parse_evidence(finding)))


@router.post("/findings/{finding_id}/update")
def finding_update(finding_id: int, request: Request, status: str = Form(...), assignee: str = Form(""), csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    finding.status = status
    finding.assignee = assignee.strip() or None
    db.add(AuditLog(action="finding_updated", entity_type="finding", entity_id=str(finding.id), actor="analyst", details=json.dumps({"status": status, "assignee": assignee})))
    db.commit()
    return RedirectResponse(f"/findings/{finding.id}?toast=Finding+updated", status_code=303)


@router.post("/findings/{finding_id}/notes")
def finding_note(finding_id: int, request: Request, body: str = Form(...), author: str = Form("Analyst"), csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    finding = db.get(Finding, finding_id)
    if not finding:
        raise HTTPException(404, "Finding not found")
    if body.strip():
        db.add(FindingNote(finding_id=finding.id, author=author.strip() or "Analyst", body=body.strip()))
        db.add(AuditLog(action="note_added", entity_type="finding", entity_id=str(finding.id), actor=author or "Analyst"))
        db.commit()
    return RedirectResponse(f"/findings/{finding.id}?toast=Note+added", status_code=303)


@router.get("/resources", response_class=HTMLResponse)
def resources_page(request: Request, db: Session = Depends(get_db), page: int = 1, q: str = "", provider: str = "", rtype: str = ""):
    query = select(CloudResource).order_by(desc(CloudResource.risk_score), CloudResource.address)
    if q:
        query = query.where(or_(CloudResource.address.ilike(f"%{q}%"), CloudResource.name.ilike(f"%{q}%")))
    if provider:
        query = query.where(CloudResource.provider == provider)
    if rtype:
        query = query.where(CloudResource.resource_type == rtype)
    items, total, pages = paginate(query, db, page)
    providers = list(db.scalars(select(CloudResource.provider).distinct().order_by(CloudResource.provider)).all())
    types = list(db.scalars(select(CloudResource.resource_type).distinct().order_by(CloudResource.resource_type)).all())
    return templates.TemplateResponse(request=request, name="resources.html", context=context(request, title="Cloud Resources", resources=items, total=total, pages=pages, page=page, q=q, provider=provider, rtype=rtype, providers=providers, types=types))


@router.get("/iam-graph", response_class=HTMLResponse)
def iam_page(request: Request, db: Session = Depends(get_db), scan_id: int | None = None):
    scans = list(db.scalars(select(Scan).order_by(desc(Scan.id))).all())
    return templates.TemplateResponse(request=request, name="iam_graph.html", context=context(request, title="IAM Risk Graph", scans=scans, scan_id=scan_id, graph_json=json.dumps(iam_graph(db, scan_id))))


@router.get("/compliance", response_class=HTMLResponse)
def compliance_page(request: Request, db: Session = Depends(get_db), scan_id: int | None = None):
    scans = list(db.scalars(select(Scan).order_by(desc(Scan.id))).all())
    return templates.TemplateResponse(request=request, name="compliance.html", context=context(request, title="Compliance Matrix", matrix=compliance_matrix(db, scan_id), scans=scans, scan_id=scan_id))


@router.get("/policies", response_class=HTMLResponse)
def policies_page(request: Request, db: Session = Depends(get_db), q: str = "", severity: str = "", category: str = ""):
    query = select(Policy).order_by(Policy.policy_key)
    if q:
        query = query.where(or_(Policy.title.ilike(f"%{q}%"), Policy.policy_key.ilike(f"%{q}%"), Policy.control_id.ilike(f"%{q}%")))
    if severity:
        query = query.where(Policy.severity == severity)
    if category:
        query = query.where(Policy.category == category)
    policies = list(db.scalars(query).all())
    categories = list(db.scalars(select(Policy.category).distinct().order_by(Policy.category)).all())
    return templates.TemplateResponse(request=request, name="policies.html", context=context(request, title="Policy Studio", policies=policies, q=q, severity=severity, category=category, categories=categories))


@router.get("/policies/{policy_id}", response_class=HTMLResponse)
def policy_detail(policy_id: int, request: Request, db: Session = Depends(get_db)):
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(404, "Policy not found")
    count = db.scalar(select(func.count()).select_from(Finding).where(Finding.policy_id == policy.id)) or 0
    return templates.TemplateResponse(request=request, name="policy_detail.html", context=context(request, title=policy.policy_key, policy=policy, finding_count=count))


@router.post("/policies/{policy_id}/toggle")
def policy_toggle(policy_id: int, request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    policy = db.get(Policy, policy_id)
    if not policy:
        raise HTTPException(404, "Policy not found")
    policy.enabled = not policy.enabled
    db.add(AuditLog(action="policy_toggled", entity_type="policy", entity_id=str(policy.id), actor="analyst", details=json.dumps({"enabled": policy.enabled})))
    db.commit()
    return RedirectResponse(f"/policies/{policy.id}?toast=Policy+status+updated", status_code=303)


@router.post("/policies/import")
def policies_import(request: Request, csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    created, updated = import_policies(db)
    return RedirectResponse(f"/policies?toast=Imported+{created}+and+updated+{updated}+policies", status_code=303)


@router.get("/repository-security", response_class=HTMLResponse)
def repository_page(request: Request, db: Session = Depends(get_db)):
    assessments = list(db.scalars(select(RepositoryAssessment).order_by(desc(RepositoryAssessment.id)).limit(10)).all())
    return templates.TemplateResponse(request=request, name="repository.html", context=context(request, title="Repository Security", assessments=assessments))


@router.post("/repository-security/assess")
def repository_assess(request: Request, repository: str = Form(...), visibility: str = Form("public"), default_branch: str = Form("main"), branch_protection: bool = Form(False), secret_scanning: bool = Form(False), code_scanning: bool = Form(False), dependabot: bool = Form(False), dependency_review: bool = Form(False), security_policy: bool = Form(False), actions_pinning: bool = Form(False), openssf_score: float = Form(0), csrf: str = Form(...), db: Session = Depends(get_db)):
    verify_csrf(request, csrf)
    values = {"repository": repository, "visibility": visibility, "default_branch": default_branch, "branch_protection": branch_protection, "secret_scanning": secret_scanning, "code_scanning": code_scanning, "dependabot": dependabot, "dependency_review": dependency_review, "security_policy": security_policy, "actions_pinning": actions_pinning, "openssf_score": openssf_score}
    values["security_score"] = repository_score(values)
    db.add(RepositoryAssessment(**values))
    db.add(AuditLog(action="repository_assessed", entity_type="repository", entity_id=repository, actor="analyst", details=json.dumps({"score": values["security_score"]})))
    db.commit()
    return RedirectResponse("/repository-security?toast=Repository+assessment+saved", status_code=303)


@router.get("/audit", response_class=HTMLResponse)
def audit_page(request: Request, db: Session = Depends(get_db), page: int = 1):
    items, total, pages = paginate(select(AuditLog).order_by(desc(AuditLog.id)), db, page, 30)
    return templates.TemplateResponse(request=request, name="audit.html", context=context(request, title="Audit Log", logs=items, total=total, pages=pages, page=page))


@router.get("/reports/scans/{scan_id}.{format}")
def scan_report(scan_id: int, format: str, db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).where(Scan.id == scan_id).options(selectinload(Scan.findings)))
    if not scan:
        raise HTTPException(404, "Scan not found")
    if format == "pdf":
        data, media = scan_pdf(scan), "application/pdf"
    elif format == "csv":
        data, media = scan_csv(scan), "text/csv"
    elif format == "json":
        data, media = scan_json(scan), "application/json"
    else:
        raise HTTPException(400, "Unsupported report format")
    return Response(data, media_type=media, headers={"Content-Disposition": f'attachment; filename="cloudsentinel-scan-{scan.id}.{format}"'})


@router.get("/api/health")
def health():
    return {"status": "ok", "service": settings.app_name, "version": "1.0.0"}


@router.get("/api/stats")
def stats_api(db: Session = Depends(get_db)):
    summary = dashboard_stats(db)
    summary.pop("latest", None)
    return {"summary": summary, "charts": chart_data(db)}


@router.get("/api/iam-graph")
def graph_api(scan_id: int | None = None, db: Session = Depends(get_db)):
    return iam_graph(db, scan_id)
