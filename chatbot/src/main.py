import time
from fastapi import FastAPI, Request, HTTPException
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
    title="Phisher Chatbot API",
    description="API for the Phisher chatbot - Deep URL Analysis",
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
    client_ip = request.client.host
    
    # log the request
    logger.info(f"Request received: {request.method} {request.url} from {client_ip}")
    
    # process the request
    response = await call_next(request)
    
    # calculate processing time
    process_time = time.time() - start_time
    
    # add custom header with processing time
    response.headers["X-Process-Time"] = str(process_time)
    
    # log the response
    logger.info(f"Response: {response.status_code} in {process_time:.4f}s")
    
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
    logger.info("Initializing chatbot model service...")
    ModelService()
    
    # run the API server
    logger.info(f"Starting Chatbot API server at {API_HOST}:{API_PORT}")
    uvicorn.run("src.main:app", host=API_HOST, port=API_PORT, reload=API_DEBUG)