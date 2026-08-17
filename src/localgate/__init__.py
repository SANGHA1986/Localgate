# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
"""
LocalGate Zero-Trust Security Bootstrapper.
Import is lightweight by default. Call install() (or set LOCALGATE_AUTO_INSTALL=1)
to activate the sys.meta_path hijack guard.
"""
import os
from localgate.finder import install, uninstall

__all__ = ["install", "uninstall"]


def _is_auto_install_enabled() -> bool:
    """
    Opt-in switch for import-time auto install (web-safe default: off).
    LOCALGATE_AUTO_INSTALL=1/true/yes/on 이면 import 시 자동 설치합니다.
    """
    raw = os.environ.get("LOCALGATE_AUTO_INSTALL", "0").strip().lower()
    return raw in {"1", "true", "yes", "on"}


if _is_auto_install_enabled():
    install()
