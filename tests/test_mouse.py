import time

from oby.mouse import Pointer


class _Mouse:
    def __init__(self):
        self.moves = []
        self.downs = 0
        self.ups = 0

    def move(self, x, y):
        self.moves.append((x, y))

    def down(self):
        self.downs += 1

    def up(self):
        self.ups += 1


class _Page:
    def __init__(self):
        self.mouse = _Mouse()


def test_move_lands_on_the_target(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    page = _Page()
    pointer = Pointer(page, seed=1)
    pointer.move(240, 180)
    last = page.mouse.moves[-1]
    assert abs(last[0] - 240) < 0.01
    assert abs(last[1] - 180) < 0.01
    assert len(page.mouse.moves) > 2


def test_two_moves_do_not_share_one_path(monkeypatch):
    monkeypatch.setattr(time, "sleep", lambda _seconds: None)
    page = _Page()
    pointer = Pointer(page, seed=3)
    pointer.move(80, 40)
    first = list(page.mouse.moves)
    pointer.move(80, 40)
    second = page.mouse.moves[len(first):]
    assert first != second
