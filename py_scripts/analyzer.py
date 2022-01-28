from typing import List

import angr
import archinfo
from angr import SimState
from timeout import TimeLimitedExecution
import common

MAX_PATHS_COUNT = 100
TIME_LIMIT_MILLIS = 3000


class Analyzer:
    def __init__(self, options):
        # set options
        self.options = options
        main_opts = {}
        # when using the blob backend, set all the needed options
        if self.options["mainOptions"]["angrBackend"] == "blob":
            main_opts = {
                'backend': 'blob',
                'arch': self.options["mainOptions"]["arch"],
                'base_addr': int(self.options["mainOptions"]["baseAddress"], 16),
                'entry_point': int(self.options["mainOptions"]["entryPoint"], 16)
            }

        print(f"Running angr with main_opts={main_opts}")
        # load the binary into a new project
        self.proj = angr.Project(self.options["mainOptions"]["pathToBinary"], main_opts=main_opts)
        # print out some basic project information
        common.project_info(self.proj)
        # convert avoid addresses from string to integer
        self.avoid_addrs = [int(x, 16) for x in self.options["findOptions"]["avoidAddresses"]]

    def get_state(self):
        """
        get_state constructs a new state for the options given and applies state modifications
        """
        # Tell angr to fill unconstrained memory and registers. This is the default behaviour.
        # The options are set to suppress warnings relating unconstrained memory/registers
        opts = {angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}

        if self.options["mainOptions"]["useBlankState"]:
            # construct a blank state at the given address
            state = self.proj.factory.blank_state(addr=int(self.options["mainOptions"]["blankStateStartAt"], 16),
                                                  add_options=opts)
        else:
            # construct a state at the entrypoint of the binary
            state = self.proj.factory.entry_state(add_options=opts)

        # Apply memory modifications
        for mod in self.options["stateModificationOptions"]["memoryModifications"]:
            # check the endianness
            if mod["byteOrdering"] == "BE":
                endness = archinfo.Endness.BE
            else:
                endness = archinfo.Endness.LE
            # actually apply the modification
            state.memory.store(int(mod["address"], 16), int(mod["value"], 16), mod["length"], endness=endness)

        # return the newly created and modified state
        return state

    def glitch(self):
        """
        glitch iterates over the glitch_addresses an tries to find a working glitch
        """
        # initialise the empty glitches list
        working_glitches = []
        print("starting to find path without glitch")
        # try to find a path without a real glitch (glitch is inserted at 0xFFFFFFFF)
        found: List[SimState] = self.find_path_with_glitch({"address": "0xFFFFFFFF"})

        # check if there is a result
        if len(found) > 0:
            print(f"found {len(found)} path(s) without glitching")
            # add the paths to the working glitches (0x0 is needed since address resolution will break otherwise)
            working_glitches.append({"glitchAddress": "0x0", "paths": common.extract_paths(self.proj, found)})
            # return since no actual glitching is needed
            return working_glitches

        print("starting to find path with glitch")
        # get the instruction at which a glitch should be inserted
        instructions = self.options["glitchOptions"]["instructions"]
        # iterate over all instructions
        for inst in instructions:
            # try to glitch at the given instruction
            found: List[SimState] = self.find_path_with_glitch(inst)
            # check if the glitch was successful
            if len(found) > 0:
                print(f"found {len(found)} path(s) for glitch at: {inst['address']}")
                # add the glitch to the working glitches
                working_glitches.append({"glitchAddress": inst["address"], "paths": self.find_paths_to_glitch(inst)})

        return working_glitches

    def find_path_with_glitch(self, instruction):
        """
        find path with glitch actually glitches the binary for a given instruction
        """
        print(instruction)
        # convert the instruction address from string to int
        glitch_addr = int(instruction["address"], 16)

        # insert the glitch at glitch_addr
        self.proj.hook(glitch_addr, common.hook_nop, length=4)

        # get a fresh state
        state = self.get_state()

        # initialize the simulation manager
        simgr = self.proj.factory.simgr(state)

        # limit the execution time to TIME_LIMIT_MILLIS
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)

        # explore the state and check if the glitch is working / if a valid path can be found
        simgr.explore(find=self.options["find"], avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        # remove the glitch from the project
        self.proj.unhook(glitch_addr)

        return simgr.found

    def find_paths_to_glitch(self, instruction):
        """
        find a path to a given instruction without glitching
        """
        # convert the address from string to int
        glitch_addr = int(instruction["address"], 16)

        # get a fresh state
        state = self.get_state()

        # initialize the simulation manager
        simgr = self.proj.factory.simgr(state)

        # limit the execution time to TIME_LIMIT_MILLIS
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)

        # use simgr to find a path to glitchaddr
        simgr.explore(find=glitch_addr, avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        # extract the full path from all possible results
        return common.extract_paths(self.proj, simgr.found)
