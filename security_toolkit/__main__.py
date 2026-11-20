"""Allow running the toolkit with `python -m security_toolkit`."""

from security_toolkit.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
