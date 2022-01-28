from angr import Project, SimState
from angr.sim_state import SimStateHistory

"""
Common contains multiple functions that are used by the plugin as well as in the jupyter notebooks 
"""


def project_info(proj: Project):
    """
    project_info prints basic information for a given project/binary
    """
    print("############ project info ############")
    print(f"file: {proj.filename}")
    print(f"arch: {proj.arch}")
    print(f"entry: {hex(proj.entry)}")
    print(f"min_addr: {hex(proj.loader.min_addr)}")
    print(f"max_addr: {hex(proj.loader.max_addr)}")
    print("############ project info ############")


def backtrace(proj: Project, history: SimStateHistory):
    """
    backtrace prints the history of a given state to the console. In addition to that the number of instructions is counted.
    """
    # setup an instruction counter
    total_instructions = 0
    # set the parent
    parent = history

    # when parent.addr = None the start of the history is reached
    while parent.addr is not None:
        # print some basic information
        print("###################")
        print(f"addr: {hex(parent.addr)}")
        print(f"jumpkind: {parent.jumpkind}")
        print(f"jumpguard: {parent.jump_guard}")
        block = proj.factory.block(addr=parent.addr)
        print(f"#instructions: {block.instructions}")

        # increase the instruction counter
        total_instructions += block.instructions
        print(f"Code:")
        # block.pp() prints all instructions/assembly of the current block
        block.pp()
        # set the new parent
        parent = parent.parent

    print(f"Total number of instructions: {total_instructions}")

    return total_instructions


def extract_paths(proj, sim_states):
    """
    extract_paths works similar to backtrace. It extracts all the paths of that lead to a list of states and returns them as a list
    """
    paths = []
    # iterate over all states
    for state in sim_states:
        # set the current parent
        parent = state.history
        # setup the block list
        blocks = []
        # initialize the instruction counter
        instruction_count = 0

        # iterate over all parents
        while parent.addr is not None:
            # get the block at the current address
            block = proj.factory.block(addr=parent.addr)
            # get all instruction addrs inside the block
            instruction_addrs = [hex(addr) for addr in block.instruction_addrs]
            # increase the instruction counter
            instruction_count += block.instructions
            # append the block to the list of blocks
            block = {"address": hex(parent.addr), "instructionAddrs": instruction_addrs}
            blocks.append(block)
            # set the new parent
            parent = parent.parent
        # add the found path to the list of paths
        path = {"blocks": blocks, "instructionCount": instruction_count}
        paths.append(path)

    return paths


def hook_nop(state: SimState):
    """
    Angr hooks a specified instruction and executes this function instead. This function is used to simulate the glitch.
    """
    pass
