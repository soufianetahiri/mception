"""Frozen-bundle entry point.

PyInstaller runs this as a standalone script, so it can't use relative imports
or the `src/` layout. It just calls into the installed package.
"""

from mception.cli import main

if __name__ == "__main__":
    main()
