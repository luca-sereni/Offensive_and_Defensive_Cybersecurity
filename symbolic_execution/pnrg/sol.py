import z3

class State:
  def __init__(self):
    self.state = [0]*0x270
    self.index = 0

def m_seedRand(s, original_seed):
  s.state[0] = original_seed & 0xffffffff
  s.index = 1
  while (s.index < 0x270):
    s.state[s.index] = (s.state[s.index - 1] * 0x17b5) & 0xffffffff
    s.index = s.index + 1
  return s

def mag(i):
  return z3.If(i == 0, z3.BitVecVal(0x0, 32), z3.BitVecVal(0x9908b0df, 32))

def genRandLong(s):  
  if ((0x26f < s.index) or (s.index < 0)):
    if ((0x270 < s.index) or (s.index < 0)):
      m_seedRand(s,0x1105)

    for i in range(0xe3):
      uVar2 = s.state[i + 1]
      p1 = s.state[i + 0x18d]
      p2a = ((uVar2 & 0x7fffffff) | (s.state[i] & 0x80000000))
      p2 = z3.LShR(p2a, 1)
      p3 = mag(uVar2 & 1)
      s.state[i] = (p1 ^ p2 ^ p3) & 0xffffffff

    for i in range(0xe3,0x26f):
      uVar2 = s.state[i + 1]
      p1 = s.state[i - 0xe3]
      p2a = ((uVar2 & 0x7fffffff) | (s.state[i] & 0x80000000))
      p2 = z3.LShR(p2a, 1)
      p3 = mag((uVar2 & 1))
      s.state[i] = (p1 ^ p2 ^ p3) & 0xffffffff

    uVar2 = s.state[0]
    p1 = s.state[0x18c]
    p2a = ((uVar2 & 0x7fffffff) | (s.state[0x26f] & 0x80000000))
    p2 = z3.LShR(p2a, 1)
    p3 = mag((uVar2 & 1))
    s.state[0x26f] = (p1 ^ p2 ^ p3) & 0xffffffff
    s.index = 0
  uVar2 = s.index
  s.index = uVar2 + 1
  uVar1 = (s.state[uVar2] ^ z3.LShR(s.state[uVar2], 0xb)) & 0xffffffff
  uVar1 = (uVar1 ^ (uVar1 << 7) & 0x9d2c5680) & 0xffffffff
  uVar1 = (uVar1 ^ (uVar1 << 0xf) & 0xefc60000) & 0xffffffff
  rand_num = (uVar1 ^ z3.LShR(uVar1, 0x12)) & 0xffffffff
  return s, rand_num

s = State() #struct of state
seed = z3.BitVec('seed', 32)
solver = z3.Solver()
s = m_seedRand(s, seed)
for i in range(1000):
  s,n = genRandLong(s)
s,n = genRandLong(s)
solver.add(n == 0x9f392a2d)
solver.check()
print(solver.model())