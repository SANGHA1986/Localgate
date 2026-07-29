# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
"""
LocalGate Zero-Trust Security Bootstrapper.
Importing this package automatically installs the sys.meta_path hijack guard.
"""
import os
from localgate.finder import install, uninstall


def _is_auto_install_enabled() -> bool:
    """
    Opt-out switch for import-time auto install.
    LOCALGATE_AUTO_INSTALL=0/false/no/off 이면 자동 설치를 비활성화합니다.
    """
    raw = os.environ.get("LOCALGATE_AUTO_INSTALL", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


if _is_auto_install_enabled():
    install()
