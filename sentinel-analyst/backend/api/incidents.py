from fastapi import APIRouter, HTTPException, UploadFile, File, Form, Query, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional
import os
import pandas as pd
import tempfile
from datetime import datetime

from ..services.analysis import get_analyzer

router = APIRouter(prefix="/incidents", tags=["incidents"])

# Path to sample data
SAMPLE_DATA_PATH = os.path.join("03 extracted data", "data_15aprl", "security_incidents_20250415_124725.xlsx")

@router.get("/")
async def get_incidents(
    tenant_id: Optional[str] = None,
    incident_id: Optional[str] = None
):
    """
    Get security incidents with optional filtering
    """
    analyzer = get_analyzer()
    
    # Use sample data if available (for demo purposes)
    if os.path.exists(SAMPLE_DATA_PATH):
        try:
            result = analyzer.analyze_incident(SAMPLE_DATA_PATH, incident_id, tenant_id)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error analyzing incidents: {str(e)}")
    else:
        return {"error": "No sample data found. Please upload incident data."}

@router.post("/upload")
async def upload_incident_data(
    file: UploadFile = File(...),
    tenant_id: Optional[str] = Form(None),
    incident_id: Optional[str] = Form(None)
):
    """
    Upload and analyze incident data from an Excel file
    """
    analyzer = get_analyzer()
    
    # Save the uploaded file to a temporary location
    with tempfile.NamedTemporaryFile(delete=False, suffix=".xlsx") as temp_file:
        temp_file.write(await file.read())
        temp_file_path = temp_file.name
    
    try:
        # Analyze the incident data
        result = analyzer.analyze_incident(temp_file_path, incident_id, tenant_id)
        
        # Clean up the temporary file
        os.unlink(temp_file_path)
        
        return result
    except Exception as e:
        # Clean up the temporary file
        os.unlink(temp_file_path)
        raise HTTPException(status_code=500, detail=f"Error analyzing incidents: {str(e)}")

@router.get("/{incident_id}/timeline")
async def get_incident_timeline(
    incident_id: str,
    tenant_id: Optional[str] = None
):
    """
    Get the timeline for a specific incident
    """
    analyzer = get_analyzer()
    
    if os.path.exists(SAMPLE_DATA_PATH):
        try:
            result = analyzer.analyze_incident(SAMPLE_DATA_PATH, incident_id, tenant_id)
            
            if "error" in result:
                raise HTTPException(status_code=404, detail=result["error"])
            
            if not result["results"]:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
            
            # Extract the timeline for the requested incident
            timeline = result["results"][0]["timeline"]
            
            return timeline
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error retrieving incident timeline: {str(e)}")
    else:
        raise HTTPException(status_code=404, detail="No sample data found. Please upload incident data.")

@router.get("/{incident_id}/analysis")
async def get_incident_analysis(
    incident_id: str,
    tenant_id: Optional[str] = None
):
    """
    Get the detailed analysis for a specific incident
    """
    analyzer = get_analyzer()
    
    if os.path.exists(SAMPLE_DATA_PATH):
        try:
            result = analyzer.analyze_incident(SAMPLE_DATA_PATH, incident_id, tenant_id)
            
            if "error" in result:
                raise HTTPException(status_code=404, detail=result["error"])
            
            if not result["results"]:
                raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")
            
            # Extract the analysis for the requested incident
            analysis = result["results"][0]["analysis"]
            
            return analysis
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Error retrieving incident analysis: {str(e)}")
    else:
        raise HTTPException(status_code=404, detail="No sample data found. Please upload incident data.") 