# cipher_station/ipns_publisher.py
#
# Background, coalesced IPNS publishing.
#
# IPNS DHT publishes are slow (seconds to minutes on a full DHT node) and every
# mutation of public.json wants one. Doing the publish inline on the request
# path held an anyio worker thread for up to ~3 minutes per upload; clients time
# out sooner than that, Starlette cannot cancel a running threadpool function,
# and the abandoned threads accumulate until the 40-token pool is exhausted and
# the station stops answering entirely.
#
# Instead, request-path code calls request_publish(), which returns immediately.
# A single daemon thread performs the actual publish. Requests are coalesced:
# the publish always re-reads public.json from disk, so only the newest state
# matters and a burst of mutations collapses into one DHT publish.

import logging
import threading
import time

logger = logging.getLogger(__name__)

_wake = threading.Event()
_thread_lock = threading.Lock()
_thread: threading.Thread | None = None

# Let a burst of mutations (e.g. several queued uploads landing back to back)
# settle into a single publish.
_DEBOUNCE_SECONDS = 2.0


def request_publish() -> None:
    """
    Ask for public.json to be (re)published to IPFS + IPNS, without blocking.

    Safe to call from any thread, any number of times; concurrent calls fold
    into a single publish of whatever is on disk when the worker runs.
    """
    _ensure_thread()
    _wake.set()


def _ensure_thread() -> None:
    global _thread
    with _thread_lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(
                target=_worker, daemon=True, name="ipns-publisher"
            )
            _thread.start()


def _worker() -> None:
    # Imported here so importing this module never drags in the IPFS client
    # (and its config) at interpreter startup.
    from cipher_station.ipfs_client import publish_public_json_to_ipns

    while True:
        _wake.wait()
        time.sleep(_DEBOUNCE_SECONDS)
        # Clear BEFORE publishing: a mutation that lands mid-publish re-sets the
        # event and triggers another pass, so its state is never lost.
        _wake.clear()
        try:
            publish_public_json_to_ipns()
        except Exception as exc:  # never let the worker die
            logger.warning("Background IPNS publish failed: %s", exc)
