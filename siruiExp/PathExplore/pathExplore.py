import angr

def pathExplore(target):
    project = angr.Project(target,auto_load_libs=False)
    state = project.factory.entry_state(addr=0x08048A2A)
    simgr = project.factory.simulation_manager(state)
    simgr.explore(find=0x8048896)
    blocks = simgr.found[0].history.bbl_addrs.hardcopy
    for i in blocks:
        print(hex(i))
    print(simgr.active)
    print(simgr.found[0].posix.dumps(0).decode("utf-8"))

pathExplore("/home/yld/target_program/user_after_free/hitconTraining_uaf/hacknote")