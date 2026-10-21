#!/usr/bin/env python3
"""Install/rollback the PHP 7.3.x Apache mitigation; plan unless --apply."""
import subprocess
import sys
from install_php74 import main

if __name__ == '__main__':
    try:
        raise SystemExit(main(branch='7.3'))
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print('INSTALLER_FAILED: ' + str(exc), file=sys.stderr)
        raise SystemExit(1)
