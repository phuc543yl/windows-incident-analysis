"""Raw Windows artifact collectors."""

from collection.artifacts.amcache_collector import AmcacheCollector
from collection.artifacts.evtx_collector import EvtxCollector
from collection.artifacts.file_collector import FileCollector
from collection.artifacts.firewall_log_collector import FirewallLogCollector
from collection.artifacts.memory_collector import MemoryCollector
from collection.artifacts.mft_collector import MftCollector
from collection.artifacts.prefetch_collector import PrefetchCollector
from collection.artifacts.registry_collector import RegistryCollector
from collection.artifacts.scheduled_task_collector import (
    ScheduledTaskCollector,
)

__all__ = [
    "AmcacheCollector",
    "EvtxCollector",
    "FileCollector",
    "FirewallLogCollector",
    "MemoryCollector",
    "MftCollector",
    "PrefetchCollector",
    "RegistryCollector",
    "ScheduledTaskCollector",
]
