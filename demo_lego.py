# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import os
import sys
import shutil

def run_test():
    print("=== [LocalGate LEGO Modularity Test] ===")
    
    # 1. Before importing localgate or packing: import colorama from standard site-packages
    print("\n[Step 1] Prior to importing LocalGate:")
    import colorama
    print(f"  - Successfully imported colorama from: {colorama.__file__}")
    
    # 2. Prepare a test vault containing ONLY colorama
    test_vault_path = os.path.join(os.getcwd(), ".vault", "test_colorama.bin")
    print(f"\n[*] Preparing test vault with ONLY colorama: {test_vault_path}")
    
    # We use LocalGatePacker directly to build it
    from localgate.packer import LocalGatePacker
    LocalGatePacker.pack(["colorama"], output_vault_path=test_vault_path)
    
    # Clear sys.modules cache to force re-import
    if "colorama" in sys.modules:
        del sys.modules["colorama"]
    
    # 3. Installing LocalGate (Plug-In)
    print("\n[Step 2] Installing LocalGate Shield...")
    import localgate
    # Re-initialize finder with our custom test vault path
    localgate.uninstall()
    localgate.install(vault_path=test_vault_path)
    
    # Clear sys.modules cache to force re-import
    if "colorama" in sys.modules:
        del sys.modules["colorama"]
    if "requests" in sys.modules:
        del sys.modules["requests"]
        
    # 4. Verification with Shield Active
    print("\n[Step 3] Verification with Shield Active:")
    
    # Standard library should work
    try:
        import json
        print("  - [SUCCESS] Standard library 'json' imported normally.")
    except Exception as e:
        print(f"  - [FAIL] Standard library 'json' import error: {e}")
        
    # Colorama should load from vault
    try:
        import colorama
        print(f"  - [SUCCESS] colorama imported from VAULT: {colorama.__file__}")
    except Exception as e:
        print(f"  - [FAIL] colorama import error: {e}")
        
    # Requests (which exists in site-packages but is not in our test vault) should be BLOCKED!
    try:
        import requests
        print(f"  - [FAIL] requests import succeeded from: {requests.__file__} (Should have been blocked!)")
    except ImportError as e:
        print(f"  - [SUCCESS] requests import BLOCKED (Expected behavior):\n    {e}")
        
    # 5. Uninstalling LocalGate (Plug-Out)
    print("\n[Step 4] Uninstalling LocalGate Shield (Plug-Out)...")
    localgate.uninstall()
    
    # Clear sys.modules cache
    if "colorama" in sys.modules:
        del sys.modules["colorama"]
    if "requests" in sys.modules:
        del sys.modules["requests"]
        
    # 6. Verification with Shield Removed
    print("\n[Step 5] Verification with Shield Removed:")
    
    # Requests should now import successfully from standard site-packages
    try:
        import requests
        print(f"  - [SUCCESS] requests imported from site-packages: {requests.__file__}")
    except Exception as e:
        print(f"  - [FAIL] requests import failed: {e}")
        
    # Colorama should also load from standard site-packages
    try:
        import colorama
        print(f"  - [SUCCESS] colorama imported from site-packages: {colorama.__file__}")
    except Exception as e:
        print(f"  - [FAIL] colorama import failed: {e}")
        
    # Clean up test vault
    if os.path.exists(test_vault_path):
        os.remove(test_vault_path)
    print("\n=== [LocalGate LEGO Test Completed Successfully] ===")

if __name__ == "__main__":
    run_test()
