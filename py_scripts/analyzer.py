from typing import List

import angr
import archinfo
from angr import SimState
from timeout import TimeLimitedExecution
import common



MAX_PATHS_COUNT = 100
TIME_LIMIT_MILLIS = 3000


class Analyzer():
    def __init__(self, options):
        self.options = options
        main_opts = {}
        if self.options["mainOptions"]["angrBackend"] == "blob":
            main_opts = {
                'backend': 'blob',
                'arch': self.options["mainOptions"]["arch"],
                'base_addr': int(self.options["mainOptions"]["baseAddress"], 16),
                'entry_point': int(self.options["mainOptions"]["entryPoint"], 16)
            }
        print(f"Running angr with main_opts={main_opts}")
        self.proj = angr.Project(self.options["mainOptions"]["pathToBinary"], main_opts=main_opts)
        common.project_info(self.proj)
        self.avoid_addrs = [int(x, 16) for x in self.options["findOptions"]["avoidAddresses"]]

    def get_state(self):
        if self.options["mainOptions"]["useBlankState"]:
            state = self.proj.factory.blank_state(addr=int(self.options["mainOptions"]["blankStateStartAt"], 16),
                                                  add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        else:
            state = self.proj.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                           angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

        for mod in self.options["stateModificationOptions"]["memoryModifications"]:
            if mod["byteOrdering"] == "BE":
                endness = archinfo.Endness.BE
            else:
                endness = archinfo.Endness.LE

            state.memory.store(int(mod["address"], 16), int(mod["value"], 16), mod["length"], endness=endness)
        return state

    def glitch(self):
        working_glitches = []
        print("starting to find path without glitch")
        found: List[SimState] = self.find_path_with_glitch({"address": "0xFFFFFFFF"})
        if len(found) > 0:
            print(f"found {len(found)} path(s) without glitching")
            working_glitches.append({"glitchAddress": "0x0", "paths": common.extract_paths(self.proj, found)})
            return working_glitches

        print("starting to find path with glitch")
        instructions = self.options["glitchOptions"]["instructions"]
        for inst in instructions:
            found: List[SimState] = self.find_path_with_glitch(inst)
            if len(found) > 0:
                print(f"found {len(found)} path(s) for glitch at: {inst['address']}")
                working_glitches.append({"glitchAddress": inst["address"], "paths": self.find_paths_to_glitch(inst)})

        return working_glitches

    def find_path_with_glitch(self, instruction):
        glitch_len = 4
        print(instruction)
        glitch_addr = int(instruction["address"], 16)

        self.proj.hook(glitch_addr, common.hook_nop, length=glitch_len)

        state = self.get_state()

        simgr = self.proj.factory.simgr(state)
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)
        simgr.explore(find=self.options["find"], avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        self.proj.unhook(glitch_addr)

        return simgr.found

    def find_paths_to_glitch(self, instruction):
        glitch_addr = int(instruction["address"], 16)

        state = self.get_state()

        simgr = self.proj.factory.simgr(state)
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)
        simgr.explore(find=glitch_addr, avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        return common.extract_paths(self.proj, simgr.found)
