"""obol web surface — a localhost FastAPI app that mirrors and drives the one
`.obol` workspace state. Read the module docstring in ``server.py``.

FastAPI/uvicorn are an optional extra (``pip install "obol[web]"``); importing this
package without them raises a clear message only when you actually start the
server, so the terminal core keeps working without the web dependencies.
"""
from .server import create_app, serve

__all__ = ["create_app", "serve"]
