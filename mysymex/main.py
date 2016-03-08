#!/usr/bin/env python
import collections
from numpy import int_

class CPU:
    def __init__(self):
        self.stack = Stack(self.mem, 0x1000000)
        self.mem = collections.defaultdict(lambda x:Symbol("mem_"+str(x)))
        self.registers = {}

class Register(Expr):
    def __init__(self, cpu, name):
        self.cpu = cpu
        self.name = name

    @property
    def value(self):
        return self.cpu.registers[self.name]

    @value.setter
    def value(self, val):
        self.cpu.registers[self.name] = val

class Stack:
    """
    A stack that grows from top to bottom and can be accessed relatively
    i.e. push => ptr-1
         pop  => ptr+1
    """
    def __init__(self, mem, ptr):
        self.mem = mem
        self.ptr = ptr

    def push(self, val):
        self.mem[self.ptr.value] = val
        self.ptr -= 1

    def pop(self):
        val = self.mem[self.ptr.value]
        self.ptr += 1
        return val

    def __getitem__(self, offset):
        return self.mem[self.ptr.value+offset]

class Symbol(Expr):
    def __init__(self, name):
        self.res = self
        self.name = name

    def eval(self):
        if not isinstance(self.res, Expr):
            return self.res,False
            

class Expr:
    OpArgs = collections.namedtuple("OpArgs", ["a", "b", "res"])
    def __init__(self, op, a, b):
        self.args = OpArgs(a,b,self)
        self.op = Op(op)

    def eval(self):
        """
        Fully evaluates all operands and result if possible
        returns True if Expr is fully evaluated afterwards
        returns False otherwise
        """
        self.args,evaled = self.op.eval(self.args)
        return evaled

    def simplify(self):
        if self.eval():
            return self.res
        else:
            return self

    @property
    def a(self):
        return self.args.a
    @property
    def b(self):
        return self.args.b
    @property
    def res(self):
        return self.args.res

class Op:
    T = True
    F = False
    ops = {
        "add": {(T,T,T):lambda a,b,r: OpArgs(a,b,r),
                (T,T,F):lambda a,b,r: OpArgs(a,b,a.res+b.res),
                (T,F,T):lambda a,b,r: OpArgs(a,r.res-b.res,r),
                (F,T,T):lambda a,b,r: OpArgs(r.res-a.res,b,r),
                },
        "sub": {(T,T,T):lambda a,b,r: OpArgs(a,b,r),
                (T,T,F):lambda a,b,r: OpArgs(a,b,a.res-b.res),
                (T,F,T):lambda a,b,r: OpArgs(a,r.res+b.res,r),
                (F,T,T):lambda a,b,r: OpArgs(a.res-r.res,b,r),
                },
    }
    def __init__(self, opearation):
        self.operation = operation

    def eval(self, args):
        """
        Fully evaluates all operands and result if possible
        returns True if Expr is fully evaluated afterwards
        returns False otherwise
        """
        unknowns = tuple(
            isinstance(v,Expr) and isinstance(v.res,Expr) 
            for v in args
        )
        try:
            return (ops[self.operation][unknowns](*args), True)
        except KeyError as e:
            return (key, False)

def main(self, *argv):
    pass

if __name__=='__main__':
    import sys
    main(*sys.argv)
