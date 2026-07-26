# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import sys

print("[demo_app.py] Starting demo application...")
print(f"[demo_app.py] sys.path: {sys.path[:3]} (truncated)")

try:
    import colorama
    from colorama import Fore, Style
    print(Fore.GREEN + "[demo_app.py] Successfully imported colorama and printed green text!" + Style.RESET_ALL)
    print(f"[demo_app.py] colorama path: {colorama.__file__}")
except ImportError as e:
    print(f"[demo_app.py] IMPORT BLOCKED OR FAILED: {e}")
except Exception as e:
    print(f"[demo_app.py] Unexpected error: {e}")

print("\n[demo_app.py] Testing requests (should be blocked as it is not in the vault)...")
try:
    import requests
    print(f"[demo_app.py] Successfully imported requests! Path: {requests.__file__}")
except ImportError as e:
    print(f"[demo_app.py] IMPORT BLOCKED OR FAILED FOR REQUESTS (EXPECTED): {e}")

