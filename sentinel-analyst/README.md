# Sentinel Analyst

A tool for security analysts to explore, analyze, and visualize security data.

## Project Structure

```
sentinel-analyst/
├── backend/       # FastAPI backend
├── frontend/      # Frontend application
└── shared/        # Shared code between frontend and backend
```

## Setup Instructions

### Backend Setup

1. Navigate to the project directory:
   ```
   cd sentinel-analyst
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   ```

3. Activate the virtual environment:
   - Windows:
     ```
     venv\Scripts\activate
     ```
   - Linux/Mac:
     ```
     source venv/bin/activate
     ```

4. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

5. Run the backend server:
   ```
   uvicorn backend.main:app --reload
   ```

6. Access the API documentation at:
   - http://localhost:8000/docs
   - http://localhost:8000/redoc

## Features

- Data ingestion and analysis
- Security event visualization
- Threat intelligence integration
- Customizable dashboards 