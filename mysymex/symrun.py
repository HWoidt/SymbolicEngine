from pprint import pprint,pformat
import re
from numpy import int_, bool_
from collections import defaultdict,ChainMap,OrderedDict,deque
from functools import wraps
from itertools import count
import json
import pickle
import yaml
import hashlib

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

    def __rxor__(self, other):
        if self == other:
            return int_(0)
        else:
            return OpExpr("xor", other, self)

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
            if self.op == "and" and (not isinstance(other, Expr)) and other in self.args:
                return self
        except AttributeError as e:
            pass
        return OpExpr("and", self, other)

    def __eq__(self, other):
        return OpExpr("eq", self, other)

    def __iter__(self):
        """
        Traverse all unique child nodes in breadth-first order
        """
        visited = set()
        queue = deque()
        queue.append(e)
        try:
            for e in iter(queue.pop, None):
                if e not in visited:
                    yield e
                    visited.add(e)
                    if isinstance(e, OpExpr):
                        queue.extend(e.args)
        except IndexError as e:
            pass
    
class CPUJump(Exception):
    pass
        
class CPUSymbolicJump(Exception):
    pass
        

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

        self.symbols = set()
        for a in args:
            try:
                self.symbols = self.symbols.union(a.symbols)
            except AttributeError as e:
                pass

    def __repr__(self):
        return str(self)

    def __str__(self):
        return "(OpExpr {op} depth={depth} depends={sym}".format(
                    op    = self.op,
                    depth = self.depth,
                    nodes = self.nodes,
                    sym   = self.symbols,
        )

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
        self.symbols = set([self])
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


class SymbolicDefaultDict(OrderedDict):
    def __init__(self, prefix=""):
        super().__init__()
        self.prefix = str(prefix)

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError as e:
            s = Symbol(self.prefix+str(key))
            self[key] = s
            return s

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

    def __iter__(self):
        return iter(sorted(self.regs.items()))

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
        self.memo = {}
    def __call__(self, f):
        @wraps(f)
        def wrapper(cpu, *operands):
            operands = tuple(spec.parse(arg, cpu)
                             for spec,arg
                             in  zip(self.specs, operands))
            return f(cpu, *operands)
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

    def _parse_int(self, i):
        try:
            return int_(int(i))
        except ValueError as e:
            return int_(int(i, 16))


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

        disp  = self._parse_int(fields["disp"])
        base  = RegOp.evaluate(fields["base"], cpu).value
        index = RegOp.evaluate(fields["index"], cpu).value
        scale = self._parse_int(fields["scale"])

        return OperandWrapper(cpu.memory, base+index*scale+disp)
MemOp = MemOpSpec("MemOp")

class ImmOpSpec(OperandSpec):
    def evaluate(self, operand, cpu):
        if operand.startswith("$"):
            return OperandWrapper(cpu.immediate, self._parse_int(operand[1:]), writable=False)
        try:
            return OperandWrapper(cpu.immediate, self._parse_int(operand), writable=False)
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

        self.next_interactive = 0
        self.cycle_cnt = 0
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
        try:
            pprint(self.current_opcode())
        except IndexError as e:
            pprint(())
    def _show_header(self):
        print("#"*70)
        print("######## pc={} cnt={} #######".format(self.pc, self.cycle_cnt))
        print("#"*70)
    def _interactive(self):
        if self.next_interactive == self.cycle_cnt:
            i = input("> ")
            try:
                self.next_interactive = self.cycle_cnt + int(i)
            except ValueError as e:
                self.next_interactive = self.cycle_cnt + 1

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
            "S" : lambda : input("press enter for next step"),
            "I" : self._interactive,
        }
        end = len(self.code)
        self.cycle_cnt = 0
        while self.pc < end:
            for spec in output:
                output_specifier[spec]()
            label, op, args = self.current_opcode()
            try:
                self.__getattribute__("op_"+op)(*args)
            except CPUJump as e:
                self.pc = self.label_index[e.args[0]]
            except AttributeError as e:
                raise NotImplementedError(e)
            else:
                self.pc += 1
            self.cycle_cnt += 1
            if ncycles is not None and self.cycle_cnt >= ncycles:
                break
        for spec in output:
            output_specifier[spec]()
        print("-- sim paused --")
        print("State hash: ", self.hash_state())
    
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
        # clean self referential symbols:
        for s in Symbol.table:
            del s.symbols
        with open(ofile+".yaml", "w") as f:
            f.write(yaml.dump(self))
        with open(ofile+".pickle", "wb") as f:
            pickle.dump(self, f)

    def unique_exprs(self):
        """
        Traverses the whole machine state (reg,mem,flags) and returns a dict
        which assigns an id to every unique expression

        These ids are stable => same asm-program results in same AST and same ids
        This is because registers are sorted by name, while memory and flags keep
        their values in insertion order (OrderedDict).
        """
        exprs = OrderedDict()
        ids = count()

        def traverse(e):
            queue = deque()
            queue.append(e)
            try:
                for e in iter(queue.pop, None):
                    if e not in exprs:
                        exprs[e] = next(ids)
                        if isinstance(e, OpExpr):
                            queue.extend(e.args)
            except IndexError as e:
                pass

        for flag,expr in self.flags.items():
            traverse(expr)
        for reg,expr in self.register:
            traverse(expr)
        for addr,expr in self.memory.items():
            traverse(expr)

        return exprs

    def hash_state(self):
        """
        Computes a hash based on the state of the virtual cpu

        depends on the ordered semantics of self.unique_exprs() !
        """
        h = hashlib.sha1()
        exprs = self.unique_exprs() # type: OrderedDict
        for e,i in exprs.items():
            if isinstance(e, OpExpr):
                args = e.op + ",".join(str(exprs[a]) for a in e.args)
            elif isinstance(e, Symbol):
                args = e.name
            else:
                args = str(e)
            h.update("({}->{})".format(i, args).encode())
        return h.hexdigest()
            

    @classmethod
    def load_state(cls, ifile):
        cls.yaml_init()
        if ifile.endswith("pickle"):
            with open(ifile, "rb") as f:
                return pickle.load(f)
        else:
            with open(ifile) as f:
                return yaml.load(f.read())

    @Operands(RegOp|MemOp|ImmOp, RegOp|MemOp)
    def op_movl(self, a, b):
        "TODO: This might have different sizing semantics?"
        b.value = a.value

    @Operands(RegOp|ImmOp, RegOp)
    def op_xor(self, a, b):
        b.value = b.value^a.value

    @Operands(MemOp|RegOp|ImmOp, MemOp|RegOp)
    def op_mov(self, a, b):
        b.value = a.value
        
    @Operands(RegOp|ImmOp, RegOp)
    def op_shl(self, a, b):
        b.value = b.value<<a.value

    @Operands(RegOp|ImmOp, RegOp)
    def op_shr(self, a, b):
        b.value = b.value>>a.value

    @Operands(RegOp|ImmOp, RegOp)
    def op_or(self, a, b):
        b.value = a.value|b.value

    @Operands(RegOp|ImmOp, RegOp)
    def op_and(self, a, b):
        b.value = a.value&b.value

    @Operands(MemOp, RegOp)
    def op_lea(self, a, b):
        b.value = a.key

    @Operands(RegOp|ImmOp, RegOp)
    def op_add(self, a, b):
        b.value = b.value + a.value
        
    @Operands(RegOp|ImmOp, RegOp)
    def op_sub(self, a, b):
        b.value = b.value - a.value

    @Operands(RegOp|ImmOp, RegOp|ImmOp)
    def op_cmp(self, a, b):
        a = a.value
        b = b.value
        self.flags["SF"] = None # MSB of a-b (sign flag)
        self.flags["ZF"] = ((a-b)==int_(0))      # (zero flag)
        self.flags["CF"] = int_(0)               # (carry flag)
        # flags OF                               # (overflow flag)
        # flags PF                               # (parity flag)

    @Operands(MemOp|RegOp|ImmOp, MemOp|RegOp|ImmOp)
    def op_cmpl(self, a, b):
        "TODO: this might have different sizing semantics"
        a = a.value
        b = b.value
        
        self.flags["SF"] = None # MSB of a-b (sign flag)
        self.flags["ZF"] = ((a-b)==int_(0))      # (zero flag)
        self.flags["CF"] = int_(0)               # (carry flag)
        # flags OF                               # (overflow flag)
        # flags PF                               # (parity flag)


    @Operands(LabelOp)
    def op_jne(self, label):
        if isinstance(self.flags["ZF"], Expr):
            raise CPUSymbolicJump(self.flags["ZF"])
        if not self.flags["ZF"]:
            raise CPUJump(label.key)
    
    @Operands(RegOp|ImmOp)
    def op_push(self, a):
        self.register["rsp"] = self.register["rsp"]-8
        self.memory[self.register["rsp"]] = a.value


def main(self, infile, resultprefix="state", display="hso", *argv):
    with open(infile) as f:
        cpu = CPU(read_asm(f))
            
    pprint(cpu.code)
    pprint(cpu.label_index)

    cpu.run(output=display)
    cpu.save_state(resultprefix)
    return cpu

if __name__=='__main__':
    import sys
    main(*sys.argv)
