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
    def __init__(self, zip_archive, package_path, name_set):
        self.zip_archive = zip_archive
        self.package_path = package_path
        self._name_set = name_set

    def open_resource(self, resource):
        path = f"{self.package_path}/{resource}"
        if self.zip_archive and path in self._name_set:
            return io.BytesIO(self.zip_archive.read(path))
        raise FileNotFoundError(f"Resource '{resource}' not found in vault package '{self.package_path}'")

    def resource_path(self, resource):
        raise FileNotFoundError("LocalGate resources are memory-only")

    def is_resource(self, name):
        path = f"{self.package_path}/{name}"
        return bool(self.zip_archive and path in self._name_set)

    def contents(self):
        if not self.zip_archive:
            return []
        names = []
        prefix = f"{self.package_path}/"
        plen = len(prefix)
        for name in self._name_set:
            if name.startswith(prefix):
                rel = name[plen:]
                if rel and "/" not in rel:
                    names.append(rel)
        return names


class LocalGateLoader(importlib.abc.SourceLoader):
    """
    In-memory module loader. Decrypts code from vault in RAM and executes it.
    Leaves no plain-text traces on disk.
    """
    def __init__(self, fullname, data, filename, is_package=False, zip_archive=None, name_set=None):
        self.fullname = fullname
        self.data = data
        self.filename = filename
        self.is_package = is_package
        self.zip_archive = zip_archive
        self._name_set = name_set or frozenset()

    def get_filename(self, fullname):
        return self.filename

    def get_data(self, path):
        return self.data

    def get_resource_reader(self, fullname):
        if not self.is_package or not self.zip_archive:
            return None
        package_path = fullname.replace(".", "/")
        return LocalGateResourceReader(self.zip_archive, package_path, self._name_set)

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

        cache_key = (self.fullname, hash(self.data))
        code = LocalGateFinder._code_cache.get(cache_key)
        if code is None:
            code = compile(self.data, self.filename, "exec")
            LocalGateFinder._code_cache[cache_key] = code

        # Only shadow open when this module may touch the virtual FS.
        if self.zip_archive is not None:
            zip_archive = self.zip_archive
            name_set = self._name_set
            original_open = _original_open

            def virtual_open(file, mode='r', *args, **kwargs):
                file_str = str(file)
                if 'localgate://vault/' not in file_str:
                    return original_open(file, mode, *args, **kwargs)
                zip_path = file_str.replace('\\', '/').split('localgate://vault/')[-1]
                if zip_path in name_set:
                    data = zip_archive.read(zip_path)
                    if 'b' in mode:
                        return io.BytesIO(data)
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

    def __init__(self, vault_path=None, lazy: bool = True):
        self.vault_path = vault_path or self._detect_vault_path()
        self.zip_archive = None
        self._name_set = frozenset()
        self._vault_miss_cache = set()
        self._resolving = set()
        self._vault_loaded = False
        self._lazy = lazy
        if not lazy:
            self._ensure_vault()

    def _detect_vault_path(self) -> str:
        env_path = os.environ.get("LOCALGATE_VAULT_PATH")
        if env_path:
            return env_path

        if sys.argv and sys.argv[0]:
            main_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
            candidate = os.path.join(main_dir, ".vault", "packages.bin")
            if os.path.exists(candidate):
                return candidate

        return os.path.join(os.getcwd(), ".vault", "packages.bin")

    def _ensure_vault(self):
        if self._vault_loaded:
            return
        self._vault_loaded = True
        self._load_vault()

    def _load_vault(self):
        if not self.vault_path or not os.path.exists(self.vault_path):
            return

        try:
            with _original_open(self.vault_path, "rb") as f:
                encrypted_data = f.read()
            decrypted_data = LocalGateCrypto.decrypt(encrypted_data)
            self.zip_archive = zipfile.ZipFile(io.BytesIO(decrypted_data))
            self._name_set = frozenset(self.zip_archive.namelist())
        except Exception as e:
            if os.environ.get("LOCALGATE_DEBUG"):
                sys.stderr.write(f"[LocalGate Warning] Failed to load vault at {self.vault_path}: {e}\n")

    def _find_in_vault(self, fullname: str):
        self._ensure_vault()
        if not self.zip_archive:
            return None

        if fullname in self._vault_miss_cache:
            return None

        base_path = fullname.replace(".", "/")
        package_path = f"{base_path}/__init__.py"
        module_path = f"{base_path}.py"
        names = self._name_set

        if package_path in names:
            data = self.zip_archive.read(package_path)
            virtual_filename = f"localgate://vault/{package_path}"
            loader = LocalGateLoader(
                fullname, data, virtual_filename,
                is_package=True, zip_archive=self.zip_archive, name_set=names,
            )
            spec = importlib.machinery.ModuleSpec(
                fullname, loader, origin=virtual_filename, is_package=True
            )
            spec.submodule_search_locations = [f"localgate://vault/{base_path}"]
            return spec

        if module_path in names:
            data = self.zip_archive.read(module_path)
            virtual_filename = f"localgate://vault/{module_path}"
            loader = LocalGateLoader(
                fullname, data, virtual_filename,
                is_package=False, zip_archive=self.zip_archive, name_set=names,
            )
            return importlib.machinery.ModuleSpec(
                fullname, loader, origin=virtual_filename, is_package=False
            )

        self._vault_miss_cache.add(fullname)
        return None

    def is_site_packages_spec(self, spec) -> bool:
        if not spec or not spec.origin:
            return False
        origin = str(spec.origin).replace("\\", "/").lower()
        return "site-packages" in origin or "dist-packages" in origin

    def find_spec(self, fullname, path=None, target=None):
        if self.disabled:
            return None

        if fullname == "localgate" or fullname.startswith("localgate."):
            return None

        if fullname in self._resolving:
            return None

        self._resolving.add(fullname)
        try:
            spec = self._find_in_vault(fullname)
            if spec:
                return spec

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
_active_finder = None


def _localgate_open(file, mode='r', *args, **kwargs):
    # Fast path: almost all opens are normal filesystem paths
    file_str = file if isinstance(file, str) else str(file)
    if 'localgate://vault/' not in file_str:
        return _original_open(file, mode, *args, **kwargs)

    zip_path = file_str.replace('\\', '/').split('localgate://vault/')[-1]
    finder = _active_finder
    if finder is not None and finder.zip_archive and zip_path in finder._name_set:
        data = finder.zip_archive.read(zip_path)
        if 'b' in mode:
            return io.BytesIO(data)
        encoding = kwargs.get('encoding', 'utf-8')
        return io.StringIO(data.decode(encoding))
    return _original_open(file, mode, *args, **kwargs)


def install(vault_path=None, block_external=None, lazy: bool = True):
    """
    Registers LocalGateFinder as the absolute number 1 finder in sys.meta_path.
    Globally patches builtins.open to support Virtual File System calls.

    lazy=True (default): defer vault decrypt until a vault import is needed.
    block_external:
      None (default) — soft until vault is loaded; then True if vault has packages.
      True/False — force on/off. Use False when bundling with site-packages libs.
    """
    global _active_finder
    for finder in sys.meta_path:
        if isinstance(finder, LocalGateFinder):
            _active_finder = finder
            return

    finder = LocalGateFinder(vault_path, lazy=lazy)
    if block_external is None:
        # Don't block siblings at install time; enforce after vault actually loads
        if finder._vault_loaded:
            block_external = bool(finder._name_set)
        else:
            block_external = False
    finder.block_external = bool(block_external)
    sys.meta_path.insert(0, finder)
    _active_finder = finder
    builtins.open = _localgate_open


def uninstall():
    """
    Removes LocalGateFinder from sys.meta_path and restores normal open behavior.
    """
    global _active_finder
    for finder in list(sys.meta_path):
        if isinstance(finder, LocalGateFinder):
            sys.meta_path.remove(finder)
    _active_finder = None
    builtins.open = _original_open
