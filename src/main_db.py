from config import HTML_INFO
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from elastic_search import VulnerabilityDatabase
from typing import Optional
from utils import load_json


app = FastAPI()
db = VulnerabilityDatabase(clear_index=True)


@app.get("/info", response_class=HTMLResponse)
def get_info():
    return HTML_INFO

@app.get("/init-db")
def init_db():
    db.initialize_database("cves.json")
    return {"result" : "done"}

@app.get("/get/all")
def get_all_cve():
    return db.get_all()

@app.get("/get/new")
def get_new_cve():
    return db.get_new()

@app.get("/get/known")
def get_known_cve():
    return db.get_known()

@app.get("/get")
def get_cve_by_query(query: Optional[str] = Query(None,
                     description="Search CVEs by keyword (or keywords).")):

    res = db.get_by_query(query)
    return res