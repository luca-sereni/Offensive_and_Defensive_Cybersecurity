import angr
import claripy

proj = angr.Project("./prodkey")

stdin_var = claripy.BVS("pk", 30*8)
initial_state = proj.factory.entry_state(stdin=stdin_var)

simgr = proj.factory.simgr(initial_state)

simgr.explore(find=0x0400e4e, avoid=0x0400e6c)
if simgr.found:
    found = simgr.found[0]
    print(found.solver.eval(stdin_var).to_bytes(30, 'big'))