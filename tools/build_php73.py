#!/usr/bin/env python3
"""Build for the installed PHP 7.3.x NTS/non-debug ABI, without installing."""
from build_php74 import main

if __name__ == '__main__':
    main(branch='7.3')
