# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import os
import sys
import argparse
from localgate.packer import LocalGatePacker

def main():
    parser = argparse.ArgumentParser(
        description="LocalGate: Zero-Trust Package Isolation and In-Memory Execution OS Core CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  localgate init
  localgate pack requests colorama
  localgate run main.py --verbose
"""
    )
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Subcommands")
    
    # Init subcommand
    subparsers.add_parser("init", help="Initialize an empty .vault/ directory in current folder")
    
    # Pack subcommand
    pack_parser = subparsers.add_parser("pack", help="Scan, trace, and pack dependencies into secure vault")
    pack_parser.add_argument("packages", nargs="+", help="Package names to secure (e.g. requests, colorama)")
    pack_parser.add_argument("-o", "--output", help="Custom path for packages.bin (default: .vault/packages.bin)")
    
    # Run subcommand
    run_parser = subparsers.add_parser("run", help="Execute a script in LocalGate zero-trust sandbox mode")
    run_parser.add_argument("script", help="Path to the python script to run")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments to forward to the script")
    
    parsed_args = parser.parse_args()
    
    if parsed_args.command == "init":
        vault_dir = os.path.join(os.getcwd(), ".vault")
        os.makedirs(vault_dir, exist_ok=True)
        print(f"[+] LocalGate vault directory initialized at: {vault_dir}")
        print("[!] Ready to pack dependencies using: localgate pack <packages>")
        
    elif parsed_args.command == "pack":
        try:
            LocalGatePacker.pack(parsed_args.packages, parsed_args.output)
        except Exception as e:
            print(f"[-] Packaging Error: {e}", file=sys.stderr)
            sys.exit(1)
            
    elif parsed_args.command == "run":
        script_path = parsed_args.script
        if not os.path.exists(script_path):
            print(f"[-] Execution Error: Script '{script_path}' not found.", file=sys.stderr)
            sys.exit(1)
            
        # Reconstruct sys.argv for the target script
        sys.argv = [script_path] + parsed_args.args
        
        # Add script directory to sys.path so it can resolve relative imports
        script_dir = os.path.dirname(os.path.abspath(script_path))
        sys.path.insert(0, script_dir)
        
        # Load and bootstrap LocalGate sys.meta_path hijack guard
        print("[*] LocalGate: Bootstrapping security shield...")
        try:
            import localgate
        except Exception as e:
            print(f"[-] LocalGate Bootstrapping failed: {e}", file=sys.stderr)
            sys.exit(1)
            
        print(f"[+] Security shield active. Launching script: {script_path}\n" + "="*50)
        
        # Execute target script in clean global namespace
        try:
            with open(script_path, "rb") as f:
                code_content = f.read()
            # Compile and run as __main__
            compiled_code = compile(code_content, script_path, "exec")
            
            global_ns = {
                "__name__": "__main__",
                "__file__": script_path,
                "__builtins__": __builtins__
            }
            exec(compiled_code, global_ns)
        except SystemExit as se:
            sys.exit(se.code)
        except Exception as e:
            import traceback
            traceback.print_exc()
            sys.exit(1)

if __name__ == "__main__":
    main()
