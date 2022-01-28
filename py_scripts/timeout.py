import time

from angr import ExplorationTechnique


class TimeLimitedExecution(ExplorationTechnique):
    """
    The TimeLimitedExecution technique limits the execution time for a single explore to time_limit milliseconds.
    """
    def __init__(self, time_limit):
        # call the constructor of the parent class
        super(TimeLimitedExecution, self).__init__()
        # set the time limit
        self.time_limit = time_limit
        # set the start time to the current time
        self.start_time = int(round(time.time() * 1000))

    def complete(self, simgr):
        """
        This method is called everytime the explore function explores a new state.
        Returns whether or not the simulation manager has reached a "completed" state -> execution should halt.
        """
        # get the current time
        current_time = int(round(time.time() * 1000))
        # check if execution exceeded the time limit
        return (current_time - self.start_time) > self.time_limit
