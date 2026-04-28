"""PyInstaller entry point — wraps the package CLI so relative imports work."""
from oss_sanitizer.cli import main

if __name__ == "__main__":
    main()
