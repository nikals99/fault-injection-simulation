from angr import SimState, Project, SimState
from angr.sim_state import SimStateHistory


def project_info(proj: Project):
    print("############ project info ############")
    print(f"file: {proj.filename}")
    print(f"arch: {proj.arch}")
    print(f"entry: {hex(proj.entry)}")
    print(f"min_addr: {hex(proj.loader.min_addr)}")
    print(f"max_addr: {hex(proj.loader.max_addr)}")
    print("############ project info ############")


def backtrace(proj: Project, history: SimStateHistory):
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

    print(f"Total number of instructions: {total_instructions}")

    return total_instructions


def extract_paths(proj, sim_states):
    paths = []
    for state in sim_states:
        history: SimStateHistory = state.history
        parent = history
        blocks = []
        instruction_count = 0
        while parent.addr is not None:
            block = proj.factory.block(addr=parent.addr)
            instruction_addrs = [hex(addr) for addr in block.instruction_addrs]
            instruction_count += block.instructions
            block = {"address": hex(parent.addr), "instructionAddrs": instruction_addrs}
            blocks.append(block)
            parent = parent.parent
        path = {"blocks": blocks, "instructionCount": instruction_count}
        paths.append(path)

    return paths


def hook_nop(state: SimState):
    pass
