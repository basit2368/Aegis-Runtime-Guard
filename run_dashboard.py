#!/usr/bin/env python3
"""Launch the AEGIS operator dashboard on http://127.0.0.1:8766."""

from aegis.dashboard import serve

if __name__ == "__main__":
    serve()
