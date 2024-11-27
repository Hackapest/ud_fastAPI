import asyncio
from config import SERVER_UNREACHABLE_MESSAGE, API_KEY
from fastapi import FastAPI, Query
from nist_api_access import NISTAPI
from typing import Optional
import time


lock = asyncio.Lock()
app = FastAPI()
nistapi = NISTAPI(api_key=None)


@app.get("/info")
async def get_info():
    pass

@app.get("/get/all")
async def get_all_cve():
    async with lock: 
        time.sleep(15)
        res = nistapi.get_all(results_per_page=1)
        if res == 503:
            return SERVER_UNREACHABLE_MESSAGE
        time.sleep(20)
        start_index = res["totalResults"] - 40
        res = nistapi.get_all(start_index=start_index)
        return res

@app.get("/get/new")
async def get_new_cve():
    async with lock:
        time.sleep(15) 
        res = nistapi.get_new(results_per_page=1)
        if res == 503:
            return SERVER_UNREACHABLE_MESSAGE
        time.sleep(15)
        start_index = res["totalResults"] - 10
        return nistapi.get_new(start_index=start_index)

@app.get("/get/critical")
async def get_critical_cve():
    async with lock:
        time.sleep(15)
        res = nistapi.get_critical(results_per_page=1)
        if res == 503:
            return SERVER_UNREACHABLE_MESSAGE
        time.sleep(15)
        start_index = res["totalResults"] - 10
        return nistapi.get_new(start_index=start_index)

@app.get("/get")
async def get_cve_by_query(query: Optional[str] = Query(None,
                           description="Search CVEs by keyword (or keywords).")):
    async with lock: 
        time.sleep(15)
        res = nistapi.get_by_keyword(query, results_per_page=1)
        if res == 503:
            return SERVER_UNREACHABLE_MESSAGE
        time.sleep(15)
        start_index = res["totalResults"] - 10
        return nistapi.get_by_keyword(query, start_index=start_index)


#Uncomment for debugging

#if __name__ == "__main__":
#    import uvicorn
#    uvicorn.run(app, host="0.0.0.0", port=8000)