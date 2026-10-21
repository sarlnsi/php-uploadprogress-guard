#!/opt/hp-python/bin/python3
"""Test shim ONLY: emulate Apache systemctl using apache2ctl in a disposable container."""
import os
from pathlib import Path
import subprocess
import sys
import time

args = sys.argv[1:]
with Path('/tmp/hp-lab-service.log').open('a') as f:
    f.write(' '.join(args) + '\n')


def pid():
    try:
        value = int(Path('/var/run/apache2/apache2.pid').read_text())
        text = Path('/proc/{}/stat'.format(value)).read_text()
        return value if text.split(') ', 1)[1][0] != 'Z' else 0
    except (OSError, ValueError):
        return 0


if len(args) < 2 or args[1] != 'apache2.service':
    raise SystemExit(3)
if args[0] == 'is-active':
    print('active' if pid() else 'inactive')
    raise SystemExit(0 if pid() else 3)
if args[0] == 'show':
    print(pid())
    raise SystemExit(0)
if args[0] == 'stop':
    if pid():
        subprocess.run(['/usr/sbin/apache2ctl', '-k', 'stop'], check=True)
    for _ in range(100):
        if not pid():
            raise SystemExit(0)
        time.sleep(.05)
    raise SystemExit(1)
if args[0] == 'start':
    fault = Path('/tmp/hp-lab-fail-start-once')
    if fault.exists():
        fault.unlink()
        print('Simulated start failure', file=sys.stderr)
        raise SystemExit(1)
    subprocess.run(['/usr/sbin/apache2ctl', '-k', 'start'], check=True)
    for _ in range(100):
        if pid():
            raise SystemExit(0)
        time.sleep(.05)
raise SystemExit(1)
