from config import HTML_INFO
from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from parse_cve_json import CVEParser
from typing import Optional
from utils import load_json


app = FastAPI()
parser = CVEParser(load_json("cves.json"))


@app.get("/info", response_class=HTMLResponse)
def get_info():
    return HTML_INFO

@app.get("/init-db")
def init_db():
    return {"result": "success"}

@app.get("/get/all")
def get_all_cve():
    res = parser.get_all()
    return res

@app.get("/get/new")
def get_new_cve():
    res = parser.get_new()
    return res

@app.get("/get/critical")
def get_critical_cve():
    res = parser.get_critical()
    return res

@app.get("/get")
def get_cve_by_query(query: Optional[str] = Query(None,
                     description="Search CVEs by keyword (or keywords).")):

    res = parser.get_by_query(query)
    return res