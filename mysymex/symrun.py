from pprint import pprint,pformat
import re
from numpy import int_, bool_
from collections import defaultdict,ChainMap
from functools import wraps
import json
import pickle
import yaml

def read_asm(f):
    """
    yields (label, op_name, [args])
    """
    for line in f:
        print(line)
        line = line.strip()
        if line.startswith("#"):
            continue
        if "<" in line:
            line, commentary = line.rsplit(" <", 1)
        lno, rest = line.split(":", 1)
        if re.match("^[0-9a-fA-F]+$", rest.strip()):
            continue
        op, args = rest.split()[-2:]
        argvs = [s.strip() for s in re.split(",(?![^(]*\))", args)]
        yield (lno.strip(), op.strip(), argvs)

class Expr:
    def __add__(self, other):
        if not isinstance(other, Expr) and other == 0:
            return self
        return OpExpr("add", self, other)

    def __radd__(self, other):
        if not isinstance(other, Expr) and other == 0:
            return self
        return OpExpr("add", other, self)

    def __sub__(self, other):
        if not isinstance(other, Expr) and other == 0:
            return self
        return OpExpr("sub", self, other)

    def __rsub__(self, other):
        if not isinstance(other, Expr) and other == 0:
            return self
        return OpExpr("sub", other, self)

    def __xor__(self, other):
        if self == other:
            return int_(0)
        else:
            return OpExpr("xor", self, other)

    def __mul__(self, other):
        if not isinstance(other, Expr) and other == 1:
            return self
        return OpExpr("mul", self, other)

    def __lshift__(self, other):
        return OpExpr("shl", self, other)
        
    def __rshift__(self, other):
        return OpExpr("shr", self, other)

    def __or__(self, other):
        return OpExpr("or", self, other)

    def __and__(self, other):
        try:
            if self.op == "and" and not isinstance(other, Expr) and other in self.args:
                return self
        except AttributeError as e:
            pass
        return OpExpr("and", self, other)

    def __eq__(self, other):
        return OpExpr("eq", self, other)
    
class CPUJump(Exception):
    pass
        
class CPUSymbolicJump(Exception):
    pass
        

def parse_int(i):
    try:
        return int_(int(i))
    except ValueError as e:
        return int_(int(i, 16))

class OpExpr(Expr):
    def __init__(self, op, *args):
        self.op = op
        self.args = args
        try:
            self.depth = max(a.depth for a in args if isinstance(a, Expr))+1
            self.nodes = sum(a.nodes for a in args if isinstance(a, Expr))+1
        except ValueError as e:
            self.depth = 1
            self.nodes = 1

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "({} -> {})".format(
            self.op,
            ",".join(str(s) for s in self.args)
        )

    def str_build(self):
        yield "("
        yield self.op
        yield " -> "
        for a in self.args:
            try:
                yield from a.str_build()
            except AttributeError:
                yield str(a)
        yield ")"

    def __iter__(self):
        yield self
        for a in self.args:
            try:
                yield from a
            except TypeError as e:
                yield a

    def __hash__(self):
        try:
            return self.hash
        except AttributeError:
            self.hash = hash(self.op) + sum(hash(a) for a in self.args)
            return self.hash

    def __eq__(self, other):
        if isinstance(other, OpExpr):
            if self.op == other.op and all(s==o for s,o in zip(self.args, other.args)):
                return True
        return super().__eq__(other)

    def __bool__(self):
        return False

class Symbol(Expr):
    table = set()
    def __init__(self, name):
        self.name = name
        self.depth = 1
        self.nodes = 1
        Symbol.table.add(self)

    def __repr__(self):
        return "<"+self.name+">"

    def __str__(self):
        return self.name

    def str_build(self):
        yield self.name

    def __iter__(self):
        yield self

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if isinstance(other, Symbol):
            if self.name == other.name:
                return True
        return super().__eq__(other)


class SymbolicDefaultDict(defaultdict):
    def __init__(self, prefix=""):
        self.prefix = str(prefix)
    def __missing__(self, key):
        val = Symbol(self.prefix+str(key))
        self[key] = val
        return val

class NameSpaceImmediate:
    def __getitem__(self, key):
        return key

class x86RegisterFile:
    def __init__(self, stackptr, magic=[]):
        self.regs = {}
        self.regs["zero"] = int_(0)
        self.regs["rsp"] = stackptr

        for r in ["rbp","rsi","rdi"]:
            self.regs[r] = Symbol("reg_"+r)

        for r in ["rax","rbx","rcx","rdx"]:
            self.regs[r] = Symbol("reg_"+r)

        for r in range(8,16):
            self.regs['r'+str(r)] = Symbol("reg_"+str(r))

        for m in magic:
            self.regs[m] = Symbol(m)

    def __getitem__(self, key):
        if key in self.regs:
            return self.regs[key]
        elif key.startswith("e"):
            key = 'r'+key[1:]
            return self.regs[key] & 0xFFFFFFFF
        elif key.endswith("d"):
            return self.regs[key[:-1]] & 0xFFFFFFFF
        else:
            raise KeyError("What register are you looking for!? "+str(key))

    def __setitem__(self, key, value):
        if key in self.regs:
            self.regs[key] = value
        elif key.startswith("e"):
            key = 'r'+key[1:]
            self.regs[key] = value & 0xFFFFFFFF
        elif key.endswith("d"):
            self.regs[key[:-1]] = value & 0xFFFFFFFF
        else:
            raise KeyError("What register are you looking for!? "+str(key))
            

    def __repr__(self):
        ret = "Register File:\n"
        ret += pformat(self.regs)
        return ret
        
class Operands:
    """
    This is a decorator for specifying operand types
    use like:

    @Operands(MemOp|RegOp|ImmOp, MemOp|RegOp)
    def op_mov(self, a, b):
        b.value = a.value

    the parameters will be passed as OperandWrapper
    """
    def __init__(self, *specs):
        self.specs = specs
    def __call__(self, f):
        @wraps(f)
        def wrapper(cpu, *operands):
            args = (spec.parse(arg, cpu)
                    for spec,arg in zip(self.specs, operands))
            return f(cpu, *args)
        return wrapper


class OperandSpec:
    def __init__(self, name="", order=None):
        self.name = name
        if order is None:
            self.eval_order = [self]
        else:
            self.eval_order = order

    def __or__(self, other):
        return OperandSpec(order=(self.eval_order + other.eval_order))

    def __str__(self):
        return "|".join(s.name for s in self.eval_order)

    def parse(self, operand, cpu):
        for spec in self.eval_order:
            try:
                return spec.evaluate(operand, cpu)
            except ValueError as e:
                continue

        msg = "Could not parse {} according to {}".format(operand, self)
        raise ValueError(msg)

class MemOpSpec(OperandSpec):
    def evaluate(self, operand, cpu):
        # disp(base,index,scale)  == [base+index*scale+disp]
        match = re.match(r"""(?P<disp>-?0x[0-9a-fA-F]+)?
                             \(
                                 (?P<base>%[a-z0-9]+)
                                 (?:,(?P<index>%[a-z0-9]+))?
                                 (?:,(?P<scale>(?:0x)?[0-9a-fA-F]+))?
                             \)""", operand, re.VERBOSE)
        if not match:
            raise ValueError("Not a valid memory adress: "+operand)

        defaults = {
            "disp" : "0x0",
            "base" : "%zero",
            "index": "%zero",
            "scale": "0x0"
        }

        fields = ChainMap(
            {k:v for k,v in match.groupdict().items() if v is not None},
            defaults
        )

        disp  = parse_int(fields["disp"])
        base  = RegOp.evaluate(fields["base"], cpu).value
        index = RegOp.evaluate(fields["index"], cpu).value
        scale = parse_int(fields["scale"])

        return OperandWrapper(cpu.memory, base+index*scale+disp)
MemOp = MemOpSpec("MemOp")

class ImmOpSpec(OperandSpec):
    def evaluate(self, operand, cpu):
        if operand.startswith("$"):
            return OperandWrapper(cpu.immediate, parse_int(operand[1:]), writable=False)
        try:
            return OperandWrapper(cpu.immediate, parse_int(operand), writable=False)
        except ValueError as e:
            raise ValueError("Not a valid immediate: "+operand)
ImmOp = ImmOpSpec("ImmOp")

class RegOpSpec(OperandSpec):
    def evaluate(self, operand, cpu):
        if operand.startswith("%"):
            return OperandWrapper(cpu.register, operand[1:])
        else:
            raise ValueError("Not a register: "+operand)
RegOp = RegOpSpec("RegOp")

class LabelOpSpec(OperandSpec):
    def evaluate(self, operand, cpu):
        return OperandWrapper(cpu.label_index, operand, writable=False)
LabelOp = LabelOpSpec("LabelOp")

class OperandWrapper:
    def __init__(self, namespace, key, writable=True):
        self.ns       = namespace
        self.key      = key
        self.writable = writable

    @property
    def value(self):
        return self.ns[self.key]

    @value.setter
    def value(self, newval):
        if not self.writable:
            raise TypeError("This operand is not writable: "+key)
        self.ns[self.key] = newval

class CPU:
    def __init__(self, code):
        magic_regs = ["magic"+str(i) for i in range(9)] + ["key0","key1","key2","key3"]

        self.code = list(code)
        self.label_index = {stmt[0]:i for i,stmt in enumerate(self.code)}
        self.memory    = SymbolicDefaultDict("mem_")
        self.register  = x86RegisterFile(0x1000000, magic_regs)
        self.immediate = NameSpaceImmediate()
        self.flags     = SymbolicDefaultDict("flag_")

        self.pc = 0
        
    def _show_syms(self):
        print("Symbol Table:")
        pprint(Symbol.table)
    def _show_regs(self):
        pprint(self.register)
    def _show_mem(self):
        pprint(self.memory)
    def _show_flags(self):
        pprint(self.flags)
    def _show_opcode(self):
        pprint(self.current_opcode())
    def _show_header(self):
        print("#"*70)
        print("######## pc={} cnt={} #######".format(self.pc, self.cycle_cnt))
        print("#"*70)

    def current_opcode(self):
        return self.code[self.pc]

    def run(self, ncycles=None, output="hso"):
        """
        output = sequence of characters, specifying output actions during each cycle
                 see below for the available actions:
        """
        output_specifier = {
            "o" : self._show_opcode,
            "h" : self._show_header,
            "s" : self._show_syms,
            "r" : self._show_regs,
            "m" : self._show_mem,
            "f" : self._show_flags,
            "S" : lambda : input("press enter for next step")
        }
        end = len(self.code)
        self.cycle_cnt = 0
        while self.pc < end:
            label, op, args = self.current_opcode()
            try:
                self.__getattribute__("op_"+op)(*args)
                for spec in output:
                    output_specifier[spec]()
            except CPUJump as e:
                self.pc = self.label_index[e.args[0]]
            except AttributeError as e:
                raise NotImplementedError(e)
            else:
                self.pc += 1
            self.cycle_cnt += 1
            if ncycles is not None and cnt >= ncycles:
                return
    
    @classmethod
    def yaml_init(cls):
        def bool_representer(dumper, data):
            return dumper.represent_scalar("!bool", str(bool(data)))
        def bool_constructor(loader, node):
            val = loader.construct_scalar(node)
            return bool_(val)
        def int_representer(dumper, data):
            return dumper.represent_scalar("!int64", str(int(data)))
        def int_constructor(loader, node):
            val = loader.construct_scalar(node)
            return int_(val)
        yaml.add_representer(bool_, bool_representer)
        yaml.add_constructor("!bool", bool_constructor)
        yaml.add_representer(int_, int_representer)
        yaml.add_constructor("!int64", int_constructor)
        
    def save_state(self, ofile):
        CPU.yaml_init()
        with open(ofile+".yaml", "w") as f:
            f.write(yaml.dump(self))
        with open(ofile+".pickle", "wb") as f:
            pickle.dump(self, f)

    @classmethod
    def load_state(cls, ifile):
        cls.yaml_init()
        if ifile.endswith("pickle"):
            with open(ifile, "rb") as f:
                return pickle.load(f)
        else:
            with open(ifile) as f:
                return yaml.load(f.read())



    def _eval_operand(self, op):
        if op.startswith("%"):
            return self.register[op[1:]]
        elif op.startswith("$"):
            return int_(int(op[1:], 16))
        elif op.startswith("0x"):
            return int_(int(op, 16))
        else:
            try:
                return int_(op)
            except ValueError as e:
                raise NotImplementedError("wtf operand? "+op)

    def _eval_reference(self, op):
        if op.startswith("%"):
            return (self.register, op[1:])
        elif op.startswith("$"):
            return (self.immediate, int_(int(op[1:], 16)))
        else:
            return (self.memory, self._parse_mem_ref(op))

    def _parse_mem_ref(self, ref):
        # disp(base,index,scale)  == [base+index*scale+disp]
        m = re.match(r"""(?P<disp>-?0x[0-9a-fA-F]+)?
                        \(
                        (?P<base>%[a-z0-9]+)
                        (?:,(?P<index>%[a-z0-9]+))?
                        (?:,(?P<scale>(?:0x)?[0-9a-fA-F]+))?
                        \)""", ref, re.VERBOSE)
        if m:
            fields = [("disp", "0x0"),
                        ("base", "%zero"),
                        ("index", "%zero"),
                        ("scale", "0x0")]
            vals = []
            for name,default in fields:
                match = m.groupdict()[name]
                if match is None:
                    print("defaulting: {} = {}".format(name,default))
                    match = default
                else:
                    print("given: {} = {}".format(name, match))
                vals.append(self._eval_operand(match))
            disp,base,index,scale = vals

            return base+index*scale+disp
        else:
            raise ValueError("Not a valid memory adress: "+ref)

    def op_movl(self, fro, to):
        """TODO: This might be invalid semantics, memory in fro allowed?
        """
        nsf,val = self._eval_reference(fro)
        nst,index = self._eval_reference(to)
        nst[index] = nsf[val]

    def op_xor(self, fro, to):
        f = self._eval_operand(fro)
        reg,t = self._eval_reference(to)
        reg[t] = reg[t]^f

    def op_mov(self, fro, to):
        nsf,f = self._eval_reference(fro)
        nst,t = self._eval_reference(to)
        nst[t] = nsf[f]
        
    def op_shl(self, a, b):
        a = self._eval_operand(a)
        nsb,b = self._eval_reference(b)
        nsb[b] = nsb[b]<<a

    def op_shr(self, a, b):
        a = self._eval_operand(a)
        nsb,b = self._eval_reference(b)
        nsb[b] = nsb[b]>>a

    def op_or(self, a, b):
        a = self._eval_operand(a)
        nsb,b = self._eval_reference(b)
        nsb[b] = nsb[b] | a

    def op_and(self, a, b):
        a = self._eval_operand(a)
        nsb,b = self._eval_reference(b)
        nsb[b] = nsb[b] & a

    def op_lea(self, a, b):
        mem,a = self._eval_reference(a)
        reg,b = self._eval_reference(b)
        reg[b] = a

    @Operands(RegOp|ImmOp, RegOp)
    def op_add(self, a, b):
        b.value = b.value + a.value
        
    def op_sub(self, a, b):
        a = self._eval_operand(a)
        nsb,b = self._eval_reference(b)
        nsb[b] = nsb[b] - a

    def op_cmp(self, a, b):
        a = self._eval_operand(a)
        b = self._eval_operand(b)
        
        self.flags["SF"] = None # MSB of a-b (sign flag)
        self.flags["ZF"] = ((a-b)==int_(0))      # (zero flag)
        self.flags["CF"] = int_(0)               # (carry flag)
        # flags OF                               # (overflow flag)
        # flags PF                               # (parity flag)

    def op_cmpl(self, a, b):
        """TODO: this might have different mem/reg reference semantics!"""
        a = self._eval_operand(a)
        nsp,b = self._eval_reference(b)
        b = nsp[b]
        
        self.flags["SF"] = None # MSB of a-b (sign flag)
        self.flags["ZF"] = ((a-b)==int_(0))      # (zero flag)
        self.flags["CF"] = int_(0)               # (carry flag)
        # flags OF                               # (overflow flag)
        # flags PF                               # (parity flag)


    def op_jne(self, label):
        if isinstance(self.flags["ZF"], Expr):
            raise CPUSymbolicJump(self.flags["ZF"])
        if not self.flags["ZF"]:
            raise CPUJump(label)
    
    def op_push(self, a):
        a = self._eval_operand(a)
        self.register["rsp"] = self.register["rsp"]-8
        self.memory[self.register["rsp"]] = a


def main(self, infile, resultprefix="state", display="hso", *argv):
    with open(infile) as f:
        cpu = CPU(read_asm(f))
            
    pprint(cpu.code)
    pprint(cpu.label_index)

    cpu.run(output=display)
    cpu.save_state(resultprefix)

if __name__=='__main__':
    import sys
    main(*sys.argv)
