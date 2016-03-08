import collections
from pprint import pprint
from queue import Queue,Empty
from symrun import *

def _collect_stats(e, stats):
    if isinstance(e, OpExpr):
        stats[e.op] += 1
        stats["prim_args"] += sum(isinstance(a, Expr) for a in e.args)
        for a in e.args:
            explore(a, stats)
    elif isinstance(e, Symbol):
        stats["symbols"].add(e.name)
    else:
        stats["prims"].add(e)

def __collect_stats(e, stats):
    #queue = Queue()
    queue = collections.deque()
    queue.append(e)

    try:
        for e in iter(queue.pop, None):
            if isinstance(e, OpExpr):
                stats[e.op] += 1
                stats["prim_args"] += sum(isinstance(a, Expr) for a in e.args)
                for a in e.args:
                    queue.append(a)
            elif isinstance(e, Symbol):
                stats["symbols"].add(e.name)
            else:
                stats["prims"].add(e)
    except IndexError:
        pass

def unique_exprs(e):
    queue = collections.deque()
    queue.append(e)
    s = []
    prims = set()
    try:
        for e in iter(queue.pop, None):
            if not hasattr(e, "visited"):
                try:
                    e.visited = True
                    s.append(e)
                    if isinstance(e, OpExpr):
                        for a in e.args:
                            queue.append(a)
                except AttributeError as exc:
                    prims.add(e)
    except IndexError:
        return prims,s

class Solve:
    def __init__(self, expressions):
        self.exp = expressions
    

def collect_stats(e):
    stats = collections.defaultdict(lambda: 0, {
        "symbols":set(),
        "prims":set(),
        "prim_args":0,
    })

    __collect_stats(e, stats)
    return stats

if __name__=='__main__':
    cpu = CPU.load_state("state.pickle")
    print("cpu was loaded")
    e = cpu.memory[16772168]
    p,s = unique_exprs(e)
    pprint(sorted(p))
    cnt = collections.Counter(e.op for e in s if isinstance(e, OpExpr))
    print("depth: \t\t", e.depth)
    print("nodes: \t\t", e.nodes)
    print("unique nodes: \t", len(s))
    print(cnt)
    print(len(s))
