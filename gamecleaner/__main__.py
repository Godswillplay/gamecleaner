"""
Package entrypoint for GameCleaner.
Allows running via `python -m gamecleaner`.
"""
import sys
from gamecleaner.cli import main

if __name__ == "__main__":
    main()
