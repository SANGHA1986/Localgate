# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
import os
import sys
import zipfile
import io
import importlib.abc
import importlib.machinery
from localgate.security import LocalGateCrypto

class LocalGateResourceReader:
    """
    Standard Python ResourceReader interface to resolve non-python files
    (like certifi's cacert.pem) directly from memory ZIP.
    """
    def __init__(self, zip_archive, package_path):
        self.zip_archive = zip_archive
        self.package_path = package_path

    def open_resource(self, resource):
        path = f"{self.package_path}/{resource}"
        if self.zip_archive and path in self.zip_archive.namelist():
            return io.BytesIO(self.zip_archive.read(path))
        raise FileNotFoundError(f"Resource '{resource}' not found in vault package '{self.package_path}'")

    def resource_path(self, resource):
        # Return FileNotFoundError to force importlib.resources to write to temp file on disk
        raise FileNotFoundError("LocalGate resources are memory-only")

    def is_resource(self, name):
        path = f"{self.package_path}/{name}"
        return self.zip_archive and path in self.zip_archive.namelist()

    def contents(self):
        if not self.zip_archive:
            return []
        names = []
        prefix = f"{self.package_path}/"
        for name in self.zip_archive.namelist():
            if name.startswith(prefix):
                rel = name[len(prefix):]
                if "/" not in rel:
                    names.append(rel)
        return names


class LocalGateLoader(importlib.abc.SourceLoader):
    """
    In-memory module loader. Decrypts code from vault in RAM and executes it.
    Leaves no plain-text traces on disk.
    """
    def __init__(self, fullname, data, filename, is_package=False, zip_archive=None):
        self.fullname = fullname
        self.data = data
        self.filename = filename
        self.is_package = is_package
        self.zip_archive = zip_archive

    def get_filename(self, fullname):
        return self.filename

    def get_data(self, path):
        return self.data

    def get_resource_reader(self, fullname):
        if not self.is_package or not self.zip_archive:
            return None
        package_path = fullname.replace(".", "/")
        return LocalGateResourceReader(self.zip_archive, package_path)

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        module.__file__ = self.filename
        module.__loader__ = self
        if self.is_package:
            module.__path__ = [os.path.dirname(self.filename)]
            module.__package__ = self.fullname
        else:
            module.__package__ = self.fullname.rpartition('.')[0]
            
        # Code caching optimization using LocalGateFinder._code_cache
        cache_key = (self.fullname, hash(self.data))
        if cache_key in LocalGateFinder._code_cache:
            code = LocalGateFinder._code_cache[cache_key]
        else:
            code = compile(self.data, self.filename, "exec")
            LocalGateFinder._code_cache[cache_key] = code
            
        # Local Module-level Virtual File System interceptor for open()
        original_open = open
        def virtual_open(file, mode='r', *args, **kwargs):
            file_str = str(file).replace('\\', '/')
            if 'localgate://vault/' in file_str:
                zip_path = file_str.split('localgate://vault/')[-1]
                if self.zip_archive and zip_path in self.zip_archive.namelist():
                    data = self.zip_archive.read(zip_path)
                    if 'b' in mode:
                        return io.BytesIO(data)
                    else:
                        encoding = kwargs.get('encoding', 'utf-8')
                        return io.StringIO(data.decode(encoding))
            return original_open(file, mode, *args, **kwargs)
            
        module.__dict__['open'] = virtual_open
        exec(code, module.__dict__)


class LocalGateFinder(importlib.abc.MetaPathFinder):
    """
    Custom finder registered at sys.meta_path[0].
    Enforces Zero-Trust by redirecting imports to .vault/ and blocking site-packages.
    """
    block_external = True
    disabled = False
    _code_cache = {}

    def __init__(self, vault_path=None):
        self.vault_path = vault_path or self._detect_vault_path()
        self.zip_archive = None
        self._resolving = set()
        self._load_vault()

    def _detect_vault_path(self) -> str:
        # 1. Environment Variable
        env_path = os.environ.get("LOCALGATE_VAULT_PATH")
        if env_path:
            return env_path
            
        # 2. Main Entry Directory
        if sys.argv and sys.argv[0]:
            main_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            candidate = os.path.join(main_dir, ".vault", "packages.bin")
            if os.path.exists(candidate):
                return candidate
                
        # 3. Current Working Directory
        cwd_candidate = os.path.join(os.getcwd(), ".vault", "packages.bin")
        return cwd_candidate

    def _load_vault(self):
        if not self.vault_path or not os.path.exists(self.vault_path):
            return
            
        try:
            with open(self.vault_path, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = LocalGateCrypto.decrypt(encrypted_data)
            self.zip_archive = zipfile.ZipFile(io.BytesIO(decrypted_data))
        except Exception as e:
            # We don't crash here so that bootstrap/cli can run to pack files.
            # But we print a warning to stderr if debugging.
            if os.environ.get("LOCALGATE_DEBUG"):
                sys.stderr.write(f"[LocalGate Warning] Failed to load vault at {self.vault_path}: {e}\n")

    def _find_in_vault(self, fullname: str):
        if not self.zip_archive:
            return None
            
        # Convert fullname (e.g. requests.models) to path in zip (e.g. requests/models)
        base_path = fullname.replace(".", "/")
        
        # Check if it is a package: requests/__init__.py
        package_path = f"{base_path}/__init__.py"
        module_path = f"{base_path}.py"
        
        namelist = self.zip_archive.namelist()
        
        if package_path in namelist:
            data = self.zip_archive.read(package_path)
            virtual_filename = f"localgate://vault/{package_path}"
            loader = LocalGateLoader(fullname, data, virtual_filename, is_package=True, zip_archive=self.zip_archive)
            spec = importlib.machinery.ModuleSpec(
                fullname, 
                loader, 
                origin=virtual_filename, 
                is_package=True
            )
            # Critical: for packages, submodule search locations must be present
            spec.submodule_search_locations = [f"localgate://vault/{base_path}"]
            return spec
            
        if module_path in namelist:
            data = self.zip_archive.read(module_path)
            virtual_filename = f"localgate://vault/{module_path}"
            loader = LocalGateLoader(fullname, data, virtual_filename, is_package=False, zip_archive=self.zip_archive)
            return importlib.machinery.ModuleSpec(
                fullname, 
                loader, 
                origin=virtual_filename, 
                is_package=False
            )
            
        return None

    def is_site_packages_spec(self, spec) -> bool:
        if not spec or not spec.origin:
            return False
        origin = str(spec.origin).replace("\\", "/").lower()
        return "site-packages" in origin or "dist-packages" in origin

    def find_spec(self, fullname, path=None, target=None):
        if self.disabled:
            return None

        # 1. Exempt localgate itself to avoid bootstrap deadlock
        if fullname == "localgate" or fullname.startswith("localgate."):
            return None

        # 2. Avoid infinite loop when resolving specs via other finders
        if fullname in self._resolving:
            return None
            
        self._resolving.add(fullname)
        try:
            # 3. Check inside the encrypted vault
            spec = self._find_in_vault(fullname)
            if spec:
                return spec
                
            # 4. Zero-Trust Check: Query the remaining finders on sys.meta_path
            for finder in sys.meta_path:
                if finder is self:
                    continue
                try:
                    other_spec = finder.find_spec(fullname, path, target)
                    if other_spec:
                        if self.block_external and self.is_site_packages_spec(other_spec):
                            raise ImportError(
                                f"\n[LocalGate Zero-Trust Security Exception]\n"
                                f"Access Denied: Import of external package '{fullname}' from global site-packages is strictly blocked.\n"
                                f"Resolved Path: {other_spec.origin}\n"
                                f"Please repack this package into your encrypted .vault/ using 'localgate pack'.\n"
                            )
                        return other_spec
                except ImportError:
                    raise
                except Exception:
                    pass
        finally:
            self._resolving.discard(fullname)
            
        return None


import builtins

_original_open = builtins.open

def _localgate_open(file, mode='r', *args, **kwargs):
    file_str = str(file).replace('\\', '/')
    if 'localgate://vault/' in file_str:
        zip_path = file_str.split('localgate://vault/')[-1]
        for finder in sys.meta_path:
            if isinstance(finder, LocalGateFinder) and finder.zip_archive:
                if zip_path in finder.zip_archive.namelist():
                    data = finder.zip_archive.read(zip_path)
                    if 'b' in mode:
                        return io.BytesIO(data)
                    else:
                        encoding = kwargs.get('encoding', 'utf-8')
                        return io.StringIO(data.decode(encoding))
    return _original_open(file, mode, *args, **kwargs)


def install(vault_path=None):
    """
    Registers LocalGateFinder as the absolute number 1 finder in sys.meta_path.
    Globally patches builtins.open to support Virtual File System calls.
    """
    # Check if already installed to prevent duplicates
    for finder in sys.meta_path:
        if isinstance(finder, LocalGateFinder):
            return
            
    finder = LocalGateFinder(vault_path)
    sys.meta_path.insert(0, finder)
    builtins.open = _localgate_open


def uninstall():
    """
    Removes LocalGateFinder from sys.meta_path and restores normal open behavior.
    """
    for finder in list(sys.meta_path):
        if isinstance(finder, LocalGateFinder):
            sys.meta_path.remove(finder)
    builtins.open = _original_open
