# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import os
import sys
import zipfile
import io
import importlib.util
import importlib.metadata
from localgate.security import LocalGateCrypto

class LocalGatePacker:
    """
    Fast-Packer Engine.
    Recursively scans dependency tree, reads source codes, 
    and packages them into a single AES-encrypted RAM-loadable vault.
    """
    ALLOWED_EXTENSIONS = (".py", ".pem", ".txt", ".json", ".csv", ".dat", ".ini")
    
    @classmethod
    def get_import_names(cls, dist_name: str) -> list:
        """
        Maps a distribution name (e.g. PySocks) to its actual importable module names (e.g. socks).
        """
        # Try top_level.txt first
        try:
            dist = importlib.metadata.distribution(dist_name)
            top_level = dist.read_text("top_level.txt")
            if top_level:
                return [line.strip() for line in top_level.splitlines() if line.strip()]
        except Exception:
            pass
            
        # Fallback 1: Analyze distribution file list
        try:
            dist = importlib.metadata.distribution(dist_name)
            if dist.files:
                roots = set()
                for f in dist.files:
                    parts = list(f.parts)
                    if parts:
                        root = parts[0]
                        if root.endswith(".py"):
                            roots.add(root[:-3])
                        elif root != "site-packages" and not root.endswith(".dist-info") and not root.endswith(".egg-info") and root != "..":
                            roots.add(root)
                if roots:
                    return list(roots)
        except Exception:
            pass
            
        # Fallback 2: Return sanitized name
        normalized = dist_name.replace("-", "_").lower()
        return [normalized]

    @classmethod
    def resolve_dependencies(cls, main_packages: list) -> set:
        """
        Recursively resolves all downstream dependencies for the list of main packages.
        """
        all_dists = set()
        to_visit = list(main_packages)
        visited = set()
        
        while to_visit:
            curr = to_visit.pop(0)
            # Normalize to compare distributions
            curr_norm = curr.replace("_", "-").lower()
            if curr_norm in visited:
                continue
            visited.add(curr_norm)
            
            # Find the actual distribution name on system
            try:
                dist = importlib.metadata.distribution(curr)
                all_dists.add(dist.metadata["Name"])
                
                # Get requirements
                reqs = dist.requires
                if reqs:
                    for req in reqs:
                        # Parse package name, ignore qualifiers (e.g. urllib3 (<3,>=1.21.1))
                        # First split by semicolon for environment markers
                        parts = req.split(";")[0].strip()
                        # Then take the first token
                        name = parts.split()[0]
                        # Strip comparison operators
                        name = name.split("<")[0].split(">")[0].split("=")[0].split("!")[0].split("[")[0].strip()
                        if name:
                            to_visit.append(name)
            except importlib.metadata.PackageNotFoundError:
                # If metadata not found, it might be a single module or local file,
                # we still treat it as a direct importable package.
                all_dists.add(curr)
                
        return all_dists

    @classmethod
    def pack(cls, packages: list, output_vault_path: str = None) -> str:
        """
        Builds the encrypted vault package.
        """
        if not output_vault_path:
            output_vault_path = os.path.join(os.getcwd(), ".vault", "packages.bin")
            
        # Temporarily disable Zero-Trust block and finder to allow scanning packages from filesystem
        from localgate.finder import LocalGateFinder
        original_block = LocalGateFinder.block_external
        original_disabled = LocalGateFinder.disabled
        LocalGateFinder.block_external = False
        LocalGateFinder.disabled = True
        
        try:
            print(f"[*] LocalGate Fast-Packer starting dependencies scan for: {packages}")
            
            # 1. Resolve distributions
            distributions = cls.resolve_dependencies(packages)
            print(f"[*] Resolved distribution dependency tree: {list(distributions)}")
            
            # 2. Map distributions to importable module names
            import_names = set()
            for dist in distributions:
                imports = cls.get_import_names(dist)
                import_names.update(imports)
                
            # Add the main packages themselves just in case
            for p in packages:
                import_names.add(p)
                
            print(f"[*] Importable modules to pack: {list(import_names)}")
            
            # Create in-memory zip file
            zip_buffer = io.BytesIO()
            packed_files_count = 0
            
            with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zip_file:
                for imp_name in sorted(import_names):
                    spec = None
                    try:
                        spec = importlib.util.find_spec(imp_name)
                    except Exception as e:
                        print(f"[!] Warning: find_spec failed for '{imp_name}': {e}")
                        continue
                        
                    if not spec:
                        print(f"[!] Warning: Module '{imp_name}' spec not found.")
                        continue
                    
                    # Check if it is a directory package
                    if spec.submodule_search_locations:
                        for search_dir in spec.submodule_search_locations:
                            if not os.path.exists(search_dir):
                                continue
                            for root, _, files in os.walk(search_dir):
                                for file in files:
                                    if file.lower().endswith(cls.ALLOWED_EXTENSIONS):
                                        full_path = os.path.join(root, file)
                                        # Compute relative path in ZIP (e.g. requests/models.py)
                                        rel_path = os.path.relpath(full_path, os.path.dirname(search_dir))
                                        rel_path = rel_path.replace("\\", "/")
                                        
                                        with open(full_path, "rb") as f:
                                            content = f.read()
                                        zip_file.writestr(rel_path, content)
                                        packed_files_count += 1
                    else:
                        # Single file module
                        file_path = spec.origin
                        if file_path and os.path.exists(file_path) and file_path.lower().endswith(cls.ALLOWED_EXTENSIONS):
                            filename = os.path.basename(file_path)
                            with open(file_path, "rb") as f:
                                content = f.read()
                            zip_file.writestr(filename, content)
                            packed_files_count += 1
                            
            if packed_files_count == 0:
                raise ValueError("No module source files were found to pack. Verify your package names.")
                
            # Get raw zip bytes
            zip_bytes = zip_buffer.getvalue()
            
            # 3. Encrypt zip bytes
            print(f"[*] Encrypting vault data ({len(zip_bytes)} bytes, {packed_files_count} files)...")
            encrypted_data = LocalGateCrypto.encrypt(zip_bytes)
            
            # 4. Write to disk
            out_dir = os.path.dirname(os.path.abspath(output_vault_path))
            os.makedirs(out_dir, exist_ok=True)
            
            with open(output_vault_path, "wb") as f:
                f.write(encrypted_data)
                
            print(f"[+] Secure vault created successfully: {output_vault_path}")
            print(f"[+] Total packed files: {packed_files_count}")
            return output_vault_path
        finally:
            LocalGateFinder.block_external = original_block
            LocalGateFinder.disabled = original_disabled
