import angr
from angr.exploration_techniques.tracer import TracingMode
from angr import sim_options as so

def tracerExcution(fileName):
   
    project = angr.Project(fileName,auto_load_libs=False)
    extras = {so.ZERO_FILL_UNCONSTRAINED_MEMORY}#https://docs.angr.io/en/latest/appendix/options.html
    state = project.factory.entry_state(add_options=extras)
    state.options.add(so.UNICORN)
    print(hex(state.project.entry))
    paths=[state.project.entry,0x8048530,0x8048a41,0x80484d0,0x810002c,0x8048a5b,0x80484d0,0x810002c,0x8048a72,
    0x8048970,0x8048530,0x804897c,0x8048490,0x810001c,0x8048991,0x8048490,0x810001c,0x80489a3,0x8048490,0x810001c,0x80489b5,
    0x8048490,0x810001c,0x80489c7,0x8048490,0x810001c,0x80489d9,0x8048490,0x810001c,0x80489eb,0x8048490,0x810001c,
    0x80489fd,0x8048490,0x810001c,0x8048a0f,0x8048450,
    0x810000c,0x8048a21,0x8048a7a,0x8048440,0x8100008,0x8048a8a,
    0x80484e0,0x8100030,0x8048a99,0x8048aa1,0x8048aad,0x8048ac7]
    simgr = project.factory.simulation_manager(state,save_unconstrained=True,save_unsat=True)
    target = angr.exploration_techniques.Tracer(trace=paths, resiliency=True, copy_states=True, mode=TracingMode.Permissive)
    '''
       """ https://docs.angr.io/en/latest/_modules/angr/exploration_techniques/tracer.html
    :ivar Strict:       Strict mode, the default mode, where an exception is raised immediately if tracer's path
                        deviates from the provided trace.
    :ivar Permissive:   Permissive mode, where tracer attempts to force the path back to the provided trace when a
                        deviation happens. This does not always work, especially when the cause of deviation is related
                        to input that will later be used in exploit generation. But, it might work magically sometimes.
    :ivar CatchDesync:  CatchDesync mode, catch desync because of sim_procedures. It might be a sign of something
                        interesting.
    """
    
    '''

    simgr.use_technique(target)
    # simgr.run()
    while simgr.active:
        print(simgr.active)
        simgr.step()
    print(simgr.traced[0].posix.dumps(0))
    simgr.remove_technique(target)
     # 由于在tracer中把UNICORN给删了，从而导致在进行下一个循环时，不能使用UNICORN，使用的引擎是/home/angr/angr-dev/angr/angr/engines/soot/engine.py
            # 使用的引擎不同时，得到的后继不一样；原本基本块是530->4f0->028; 当前状态是530，使用UNICORN得到的后继是028.而使用soot得到的后继死4f0，这就导致了angr.exploration_techniques.tracer | Trying to synchronize at %#x (%#x) but it does not appear in the trace?
            # 因此，在循环结束后，再把UNICORN给self.state.
            # extras = {so.REVERSE_MEMORY_NAME_MAP, so.TRACK_ACTION_HISTORY,so.ZERO_FILL_UNCONSTRAINED_MEMORY}
    



if __name__=="__main__":
    tracerExcution("/home/yld/target_program/user_after_free/hitconTraining_uaf/hacknote")