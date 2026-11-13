"""Answer the script collector before mitmcloak sees the request.

Loaded ahead of the cloak addon on purpose. mitmcloak leaves a request alone
when a response is already set, so the hook's report is not dialed upstream
and is not written into the page recording. The HTTP/2 capture stays in
record.py, which is loaded later so it can place itself last.
"""

from __future__ import annotations

from oby.scripts import answer_sink


class Collect:
    def request(self, flow) -> None:
        answer_sink(flow)


addons = [Collect()]
