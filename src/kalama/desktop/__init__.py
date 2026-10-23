"""Desktop presentation adapter for VIPER.

The package intentionally depends on no scanner, Docker, or Metasploit code.
Its application facade is the only boundary used by the pywebview bridge.
"""

from .ui import main

__all__ = ["main"]
