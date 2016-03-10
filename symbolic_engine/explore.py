import collections
from pprint import pprint
from queue import Queue,Empty
from itertools import count
from symrun import *
from graph_tool import Graph
from graph_tool.draw import *
from numpy import array,zeros

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
    expr_id = count()
    try:
        for e in iter(queue.pop, None):
            if not hasattr(e, "visited"):
                try:
                    e.visited = next(expr_id)
                    s.append(e)
                    if isinstance(e, OpExpr):
                        for a in e.args:
                            queue.append(a)
                except AttributeError as exc:
                    prims.add(e)
    except IndexError:
        return prims,s

def show_graph(e, ofile):
    prims,uexprs = unique_exprs(e)
    g = Graph()
    vertexes = g.add_vertex(len(uexprs))
    prim_vertexes = g.add_vertex(len(prims))
    pv_map = {p:v for p,v in zip(prims, prim_vertexes)}

    colors = g.new_vertex_property("vector<float>")
    typecolormap = defaultdict(lambda:[0.,0.,1.,1.],{
        OpExpr: [1.,0.,0.,1.],
        Symbol: [0.,1.,0.,1.],
    })

    shapes = g.new_vertex_property("int")
    shapemap = defaultdict(lambda:0, {
        "and":1, # triangle
        "xor":2, # square
        "shr":3, # pentagon
    })
    uexprs = list(uexprs)
    for expr,vertex in zip(uexprs, vertexes):
        expr.vertex = vertex
        colors[vertex] = typecolormap[type(expr)]
        if expr is e:
            colors[vertex] = [1.,1.,0.,1.]
    for prim,vertex in pv_map.items():
        colors[vertex] = typecolormap[type(prim)]
    for expr in uexprs:
        if isinstance(expr, OpExpr):
            shapes[expr.vertex] = shapemap[expr.op]
            for a in expr.args:
                if isinstance(a, Expr):
                    g.add_edge(expr.vertex, a.vertex)
                elif a not in [0xFFFFFFFF, 3,4,5]:
                    #g.add_edge(expr.vertex, pv_map[a])
                    pass
    interactive_window(g, 
                output_size=(2400,2400),
                output=ofile,
                #pos=arf_layout(g),
                vertex_shape=shapes,
                vertex_fill_color=colors,
    )
    


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
    #e = cpu.memory[16772168]
    #p,s = unique_exprs(e)
    #pprint(sorted(p))
    #cnt = collections.Counter(e.op for e in s if isinstance(e, OpExpr))
    #print("depth: \t\t", e.depth)
    #print("nodes: \t\t", e.nodes)
    #print("unique nodes: \t", len(s))
    #print(cnt)
    #print(len(s))

    e = cpu.memory[16772168]
    show_graph(e, "graph.png")
