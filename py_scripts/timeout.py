import time

from angr import ExplorationTechnique


class TimeLimitedExecution(ExplorationTechnique):
    def __init__(self, time_limit):
        super(TimeLimitedExecution, self).__init__()
        self.time_limit = time_limit
        self.start_time = int(round(time.time() * 1000))

    def complete(self, simgr):
        current_time = int(round(time.time() * 1000))
        return (current_time - self.start_time) > self.time_limit