"""Intel-specific security fact collectors."""

from linuxmd.collectors.vendors.intel.tdx import collect_intel_tdx

__all__ = ["collect_intel_tdx"]
