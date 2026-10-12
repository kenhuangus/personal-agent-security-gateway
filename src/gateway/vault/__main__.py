"""Entry point: ``python -m gateway.vault --generate``."""

from .kms import main

if __name__ == "__main__":
    raise SystemExit(main())
