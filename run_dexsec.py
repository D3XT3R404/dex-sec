"""Standalone entry point for the packaged executable.

    python run_dexsec.py scan --path . --target http://localhost:8000
    pyinstaller dexsec.spec   -> dist/dexsec.exe
"""

from dexsec.cli import main

if __name__ == "__main__":
    main()
