from typing import List

import angr
from angr import SimState, Project
from angr.sim_state import SimStateHistory
from timeout import TimeLimitedExecution


def hook_nop(state: SimState):
    pass


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
        self.project_info()
        self.avoid_addrs = [int(x, 16) for x in self.options["findOptions"]["avoidAddresses"]]

    def glitch(self):
        working_glitches = []
        print("starting to find path without glitch")
        found: List[SimState] = self.find_path_with_glitch({"address": "0xFFFFFFFF", "thumb": False})
        if len(found) > 0:
            print(f"found {len(found)} path(s) without glitching")
            working_glitches.append({"glitchAddress": "0x0", "paths": self.extract_paths(found)})
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
        # TODO thumb modifications

        self.proj.hook(glitch_addr, hook_nop, length=glitch_len)

        if self.options["mainOptions"]["useBlankState"]:
            state = self.proj.factory.blank_state(addr=int(self.options["mainOptions"]["blankStateStartAt"], 16),
                                                  add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        else:
            state = self.proj.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

        for mod in self.options["stateModificationOptions"]["memoryModifications"]:
            state.memory.store(int(mod["address"], 16), int(mod["value"], 16), mod["length"])

        simgr = self.proj.factory.simgr(state)
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)
        simgr.explore(find=self.options["find"], avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        self.proj.unhook(glitch_addr)

        return simgr.found

    def backtrace(self, proj: Project, history: SimStateHistory):
        total_instructions = 0
        parent = history

        while parent.addr is not None:
            print("###################")
            print(f"addr: {hex(parent.addr)}")
            print(f"jumpkind: {parent.jumpkind}")
            print(f"jumpguard: {parent.jump_guard}")
            block = proj.factory.block(addr=parent.addr)
            print(f"#instructions: {block.instructions}")
            total_instructions += block.instructions
            print(f"Code:")
            block.pp()
            parent = parent.parent

        return total_instructions

    def project_info(self):
        print("############ project info ############")
        print(f"file: {self.proj.filename}")
        print(f"arch: {self.proj.arch}")
        print(f"entry: {hex(self.proj.entry)}")
        print(f"min_addr: {hex(self.proj.loader.min_addr)}")
        print(f"max_addr: {hex(self.proj.loader.max_addr)}")
        print("############ project info ############")

    def find_paths_to_glitch(self, instruction):
        glitch_addr = int(instruction["address"], 16)

        if self.options["mainOptions"]["useBlankState"]:
            state = self.proj.factory.blank_state(addr=int(self.options["mainOptions"]["blankStateStartAt"], 16),
                                                  add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})
        else:
            state = self.proj.factory.entry_state(add_options={angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                                                               angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS})

        for mod in self.options["stateModificationOptions"]["memoryModifications"]:
            state.memory.store(int(mod["address"], 16), int(mod["value"], 16), int(mod["length"]))

        simgr = self.proj.factory.simgr(state)
        tl = TimeLimitedExecution(time_limit=TIME_LIMIT_MILLIS)
        simgr.use_technique(tl)
        simgr.explore(find=glitch_addr, avoid=self.avoid_addrs, num_find=MAX_PATHS_COUNT)

        return self.extract_paths(simgr.found)

    def extract_paths(self, sim_states):
        paths = []
        for state in sim_states:
            history: SimStateHistory = state.history
            parent = history
            blocks = []
            instruction_count = 0
            while parent.addr is not None:
                block = self.proj.factory.block(addr=parent.addr)
                instruction_addrs = [hex(addr) for addr in block.instruction_addrs]
                instruction_count += block.instructions
                block = {"address": hex(parent.addr), "instructionAddrs": instruction_addrs}
                blocks.append(block)
                parent = parent.parent
            path = {"blocks": blocks, "instructionCount": instruction_count}
            paths.append(path)

        return paths

    def write_results(self, working_glitches):
        print(working_glitches)
