# -*- coding: utf-8 -*-
"""
    proxy.py
    ~~~~~~~~
    ⚡⚡⚡ Fast, Lightweight, Pluggable, TLS interception capable proxy server focused on
    Network monitoring, controls & Application development, testing, debugging.

    :copyright: (c) 2013-present by Abhinav Singh and contributors.
    :license: BSD, see LICENSE for more details.
"""
import time


class Leakage:
    """Leaky Bucket algorithm."""

    def __init__(self, rate: int) -> None:
        """Initialize the leaky bucket with a specified leak rate in bytes per second."""
        # Maximum number of tokens the bucket can hold (bytes per second)
        self.rate = rate
        self.tokens = rate
        self.last_check = time.time()

    def _refill(self) -> None:
        """Refill tokens based on the elapsed time since the last check."""
        now = time.time()
        elapsed = now - self.last_check
        # Add tokens proportional to elapsed time, up to the rate
        self.tokens += int(elapsed * self.rate)
        # Cap tokens at the maximum rate to enforce the rate limit
        self.tokens = min(self.tokens, self.rate)
        self.last_check = now

    def release(self, tokens: int) -> None:
        """When you are unable to consume amount units of token, release them into the bucket.

        E.g. say you wanted to read 1024 units, but only 24 units were read, then put
        back unconsumed 1000 tokens back in the bucket."""
        if tokens < 0:
            raise ValueError('Cannot release a negative number of tokens')
        self.tokens += tokens
        self.tokens = min(self.tokens, self.rate)

    def consume(self, amount: int) -> int:
        """Attempt to consume the amount from the bucket.

        Returns the amount allowed to be sent, up to the available tokens (rate).
        """
        self._refill()
        allowed = min(amount, self.tokens)
        self.tokens -= allowed
        return allowed
