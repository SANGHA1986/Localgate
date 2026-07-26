# Copyright (c) 2026 SANGHA1986. All rights reserved. Licensed under BUSL-1.1.
"""
LocalGate Zero-Trust Security Bootstrapper.
Importing this package automatically installs the sys.meta_path hijack guard.
"""
from localgate.finder import install, uninstall

# Automatically activate security shielding upon import
install()
