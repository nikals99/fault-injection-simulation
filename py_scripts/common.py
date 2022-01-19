from angr import SimState, Project


def project_info(proj: Project):
    print("############ project info ############")
    print(f"file: {proj.filename}")
    print(f"arch: {proj.arch}")
    print(f"entry: {hex(proj.entry)}")
    print(f"min_addr: {hex(proj.loader.min_addr)}")
    print(f"max_addr: {hex(proj.loader.max_addr)}")
    print("############ project info ############")


def hook_nop(state: SimState):
    pass
