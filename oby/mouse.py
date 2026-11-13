"""Play Cursory trajectories through a Playwright mouse.

The pointer position is remembered on this object. Playwright does not report
where the cursor already is, so the first move starts at (0, 0).
"""

from __future__ import annotations

import random
import time

from cursory import generate_trajectory


class Pointer:
    def __init__(self, page, seed: int | None = None):
        self.page = page
        self.x = 0.0
        self.y = 0.0
        self.seed = seed
        self._step = 0

    def _next_seed(self) -> int | None:
        if self.seed is None:
            return None
        seed = self.seed + self._step
        self._step += 1
        return seed

    def move(self, x: float, y: float) -> None:
        points, timings = generate_trajectory(
            (self.x, self.y), (float(x), float(y)), seed=self._next_seed()
        )
        started = time.perf_counter()
        for (px, py), ms in zip(points, timings):
            delay = ms / 1000 - (time.perf_counter() - started)
            if delay > 0:
                time.sleep(delay)
            self.page.mouse.move(px, py)
        self.x, self.y = float(x), float(y)

    def click_point(self, x: float, y: float) -> None:
        self.move(x, y)
        self.page.mouse.down()
        time.sleep(0.04 + random.random() * 0.05)
        self.page.mouse.up()

    def click(self, selector: str) -> None:
        box = self.page.locator(selector).bounding_box()
        if not box:
            raise RuntimeError(f"no box for {selector}")
        rng = random.Random(self._next_seed())
        x = box["x"] + box["width"] * (0.35 + 0.3 * rng.random())
        y = box["y"] + box["height"] * (0.35 + 0.3 * rng.random())
        self.click_point(x, y)

    def type_text(self, selector: str, text: str) -> None:
        self.click(selector)
        for char in text:
            self.page.keyboard.type(char)
            time.sleep(0.03 + random.random() * 0.07)
