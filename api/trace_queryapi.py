from fastapi import FastAPI, Query, HTTPException
# from sqlalchemy import create_engine, text
from datetime import date
from typing import List, Optional, Dict
from fastapi import APIRouter
from fastapi.responses import JSONResponse
from util.logger_util import logger
from typing import Union

log_router = APIRouter()

@log_router.get("/")
async def read_root():
    return {"Hello": "World"}

@log_router.get("/hello")
async def hello_python():
    return {"Hello": "Python"}

@log_router.get("/items/{item_id}")
async def read_item(item_id: int, q: Union[str, None] = None):
    return {"item_id": item_id, "q": q}

@log_router.get("/getallLogdata-sortorder")
async def sort_order_log(
    sortOrder: str = Query(...),  
    # fromDate: Optional[date] = None,
    # toDate: Optional[date] = None,
    minutesAgo: Optional[int] = None,
    serviceNameList: Optional[List[str]] = Query(...),
    severityTextList: Optional[List[str]] = Query(None)
):
    try:
        # final_query = LOGSQLQueries.construct_query(fromDate, toDate, minutesAgo, serviceNameList, severityTextList, sortOrder)
        # response_data = get_all_log_result_response(final_query, severityTextList)
        # return JSONResponse(content=response_data)
        data = {
            "sortOrder": sortOrder,
            # fromDate: fromDate,
            # toDate: toDate,
            "minutesAgo": minutesAgo,
            # serviceNameList: 
        }
        return JSONResponse(content=data)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
