import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# Ensure UTF-8 console output on Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8")

env_path = Path(__file__).parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

API_KEY = os.environ.get("TYPESAFE_API_KEY", "")
MODEL = os.environ.get("TYPESAFE_MODEL", "jev-latest")

if not API_KEY:
    print("[WARN] TYPESAFE_API_KEY is not set!")
