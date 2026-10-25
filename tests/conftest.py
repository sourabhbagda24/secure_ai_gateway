import pytest

from secure_ai.demo_world import build_world


class FakeClock:
    def __init__(self, t=1_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


@pytest.fixture
def world():
    return build_world()


@pytest.fixture
def clock():
    return FakeClock()
