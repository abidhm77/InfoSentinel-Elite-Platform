"""
MSP Reporting API for InfoSentinel.

This module provides REST API endpoints for MSP cross-tenant reporting,
enabling aggregated security posture views and comparative analysis.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, Depends, HTTPException, Header, Path, Query, Body
from pydantic import BaseModel, Field

from backend.services.msp_reporting_service import MSPReportingService
from backend.api.auth import get_current_user, require_permissions
from ...compliance.grc.grc_manager import GRCManager


# Models for API requests and responses
class TenantListRequest(BaseModel):
    tenant_ids: List[str] = Field(..., min_items=1)
    metrics: Optional[List[str]] = None


# Create router
router = APIRouter(
    prefix="/api/v1/msp/reports",
    tags=["msp_reports"],
    responses={404: {"description": "Not found"}},
)

# Initialize MSP reporting service
msp_reporting_service = MSPReportingService()
grc_manager = GRCManager()


@router.get("/managed-tenants", response_model=Dict[str, Any])
async def get_managed_tenants(
    current_user: Dict = Depends(get_current_user),
):
    """
    Get tenants managed by the current MSP user.
    """
    # Check permissions
    require_permissions(current_user, ["view_managed_tenants"])
    
    # Get managed tenants
    tenants = msp_reporting_service.get_managed_tenants(current_user.get("id"))
    
    return {
        "success": True,
        "tenants": tenants,
        "count": len(tenants)
    }


@router.post("/security-posture", response_model=Dict[str, Any])
async def get_security_posture_summary(
    request: TenantListRequest,
    current_user: Dict = Depends(get_current_user),
):
    """
    Get aggregated security posture summary across multiple tenants.
    """
    # Check permissions
    require_permissions(current_user, ["view_cross_tenant_reports"])
    
    # Get security posture summary
    result = msp_reporting_service.get_security_posture_summary(request.tenant_ids)
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to generate security posture summary"))
    
    return result


@router.post("/compliance", response_model=Dict[str, Any])
async def get_compliance_summary(
    request: TenantListRequest,
    current_user: Dict = Depends(get_current_user),
):
    """
    Get compliance status summary across multiple tenants.
    """
    # Check permissions
    require_permissions(current_user, ["view_cross_tenant_reports"])
    
    # Get compliance summary
    result = msp_reporting_service.get_compliance_summary(request.tenant_ids)
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to generate compliance summary"))
    
    return result


@router.post("/comparative", response_model=Dict[str, Any])
async def generate_comparative_report(
    request: TenantListRequest,
    current_user: Dict = Depends(get_current_user),
):
    """
    Generate a comparative analysis report across multiple tenants.
    """
    # Check permissions
    require_permissions(current_user, ["view_cross_tenant_reports"])
    
    # Generate comparative report
    result = msp_reporting_service.generate_comparative_report(
        request.tenant_ids,
        request.metrics
    )
    
    if not result.get("success"):
        raise HTTPException(status_code=400, detail=result.get("error", "Failed to generate comparative report"))
    
    return result


@router.get("/enterprise-dashboard", response_model=Dict[str, Any])
async def get_enterprise_dashboard(
    current_user: Dict = Depends(get_current_user),
    visualization_type: str = Query(default='chart', regex='^(table|chart|metric)$'),
    time_range: str = Query(default='7d', regex='^(7d|30d|90d)$'),
    business_unit: Optional[str] = None
):
    """
    Enterprise dashboard endpoint with customizable visualization outputs
    
    - Integrates risk trends, compliance status, and predictive analytics
    - Supports multiple visualization formats for BI integration
    """
    require_permissions(current_user, ["view_enterprise_dashboard"])
    
    # Aggregate data from multiple sources
    dashboard_data = {
        "risk_metrics": msp_reporting_service.get_risk_trends(time_range),
        "compliance_status": msp_reporting_service.get_compliance_summary([]),  # Empty list gets all tenants
        "predictive_analytics": msp_reporting_service.get_predictive_metrics()
    }

    # Format response based on visualization type
    return {
        "config": {
            "visualization": visualization_type,
            "time_range": time_range,
            "business_unit": business_unit
        },
        "data": dashboard_data
    }

@router.get("/bi-export/{platform}", response_model=Dict[str, Any])
async def export_to_bi(
    platform: str = Path(..., description="BI platform: powerbi, tableau, qlik"),
    current_user: Dict = Depends(get_current_user)
):
    """
    Export formatted data for business intelligence platforms
    """
    require_permissions(current_user, ["export_bi_data"])
    
    raw_data = await get_enterprise_dashboard(current_user)
    
    # Transform data structure based on BI platform requirements
    transform_map = {
        "powerbi": lambda d: {"datasets": [d]},
        "tableau": lambda d: {"columns": list(d["data"].keys()), "rows": [d["data"].values()]},
        "qlik": lambda d: {"qData": d}
    }
    
    return transform_map.get(platform.lower(), lambda x: x)(raw_data)


@router.post("/grc-board-report", response_model=Dict[str, Any])
async def generate_grc_board_report(
    request: TenantListRequest,
    current_user: Dict = Depends(get_current_user),
):
    """
    Generate board-level GRC report with risk quantification and compliance overview.
    """
    # Check permissions
    require_permissions(current_user, ["view_cross_tenant_reports"])
    
    # Get vulnerabilities for tenants (assuming a method to fetch them)
    vulnerabilities = msp_reporting_service.get_aggregated_vulnerabilities(request.tenant_ids)
    
    # Assess risk using GRCManager
    risk_assessment = grc_manager.assess_risk(vulnerabilities)
    
    # Generate compliance summary
    compliance_summary = msp_reporting_service.get_compliance_summary(request.tenant_ids)
    
    # Compile board report
    report = {
        "risk_assessment": risk_assessment,
        "compliance_summary": compliance_summary,
        "executive_overview": "High-level insights for board review."
    }
    
    return {
        "success": True,
        "report": report
    }