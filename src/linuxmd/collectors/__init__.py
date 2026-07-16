"""Built-in diagnostic collectors."""

from linuxmd.collectors.security import SecurityCollector
from linuxmd.collectors.system import SystemCollector

__all__ = ["SecurityCollector", "SystemCollector"]
