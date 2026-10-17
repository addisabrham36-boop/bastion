"""
Minimal dummy upstream web application for testing reverse proxying.
"""

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

upstream_app = FastAPI(title="Test Upstream App")


@upstream_app.get("/hello")
async def hello():
    return {"message": "Hello from upstream!"}


@upstream_app.post("/echo")
async def echo(request: Request):
    body = await request.body()
    return {
        "headers": dict(request.headers),
        "query": dict(request.query_params),
        "body": body.decode("utf-8", errors="replace"),
    }


@upstream_app.get("/status/{code}")
async def status_code(code: int):
    return JSONResponse(status_code=code, content={"status": code})
