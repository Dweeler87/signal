"""FastAPI application entry point for the Forelight API."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import account, batch, billing, health, keys, signals, signup, watchlists, webhooks

app = FastAPI(
    title="Forelight API",
    description="Real-time go-to-market signals from Certificate Transparency logs.",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(account.router)
app.include_router(signals.router)
app.include_router(batch.router)
app.include_router(watchlists.router)
app.include_router(keys.router)
app.include_router(webhooks.router)
app.include_router(signup.router)
app.include_router(billing.router)
