import time
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
import os
import uvicorn

from .config import API_PREFIX, API_DEBUG, API_HOST, API_PORT, CORS_ORIGINS
from .logging_config import get_logger
from .routers import url_analyzer
from .services.model_service import ModelService

# get logger
logger = get_logger(__name__)

# initialize app
app = FastAPI(
    title="Phisher Extension API",
    description="API for the Phisher browser extension - Lightweight URL Analysis",
    version="1.0.0",
    debug=API_DEBUG
)

# add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# middleware for request logging and timing
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    
    # get client IP
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0]
    else:
        client_ip = request.client.host
    
    # log request details
    logger.info(f"Request {request.method} {request.url.path} from {client_ip}")
    
    response = await call_next(request)
    
    # calculate and log processing time
    process_time = time.time() - start_time
    logger.info(f"Request completed in {process_time:.4f} seconds")
    
    # add custom header with processing time
    response.headers["X-Process-Time"] = str(process_time)
    
    return response

# error handlers
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred"}
    )

# include routers
app.include_router(url_analyzer.router, prefix=API_PREFIX)

# health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "healthy", "version": "1.0.0"}

if __name__ == "__main__":
    # initialize model service
    logger.info("Initializing model service...")
    ModelService()
    
    # run the API server
    logger.info(f"Starting API server at {API_HOST}:{API_PORT}")
    uvicorn.run("src.main:app", host=API_HOST, port=API_PORT, reload=API_DEBUG)