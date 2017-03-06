#!/usr/bin/env python
# coding=utf-8
from pyparsing import nestedExpr, ParseException
from collections import namedtuple
from graphviz import Digraph

BvTyp = namedtuple("BvTyp", "size")
ArrTyp = namedtuple("ArrTyp", "index_size content_size")

Input = namedtuple('Input', "name type")
VarDef = namedtuple('VarDef', "name type value")
Assert = namedtuple('Assert', "value")
Raw = namedtuple('Raw', "raw")

Bv = namedtuple('Bv', 'value size')
Var = namedtuple('Var', 'name')
UnOp = namedtuple('UnOp', "op expr opt1 opt2")
BinOp = namedtuple('BinOp', 'op expr1 expr2')
Ite = namedtuple('Ite', 'cond expr1 expr2')
Select = namedtuple("Select", "array expr")
Select32 = namedtuple("Select32", "array expr")
Let = namedtuple("Let", "bindings expr")
Store = namedtuple('Store', "array addr expr")
Store32 = namedtuple("Store32", "array addr expr")


def group(lines):
    final = []
    i = 0
    while i < len(lines):
        line = lines[i]
        count = line.count("(")-line.count(")")
        if count == 0:
            final.append(line)
            i += 1
        else:
            s = line
            tmp_count = count
            while tmp_count != 0:
                i += 1
                line = lines[i]
                tmp_count += line.count("(")-line.count(")")
                s += " "+line
            i += 1
            final.append(s)
    return final


def parse_parentheses(line):
    try:
        return nestedExpr('(', ')').parseString(line).asList()
    except ParseException:
        print "Exception on line:", line


class SMTFormula:

    bvunary_op = ["bvneg", "bvnot", "extract", "zero_extend", "sign_extend", "rotate_left", "rotate_right"]
    binary_op = ["=", "and", "or"]
    unary_op = ["not"]

    bvbinary_op = ["bvadd", "bvsub", "bvmul", "bvudiv", "bvsdiv", "bvurem", "bvsrem", "bvsmod",
                   "bvor", "bvnor", "bvand", "bvnand", "bvxor", "bvxnor", "concat", "bvshl", "bvlshr", "bvashr",
                   "bvcomp", "bvule", "bvult", "bvuge", "bvugt", "bvsle", "bvslt", "bvsge", "bvsgt"]

    def __init__(self):
        self.inputs = set()
        self.formula = {-1: []}  # Map index by trace offset
        self.offset_instr = {}
        self.var_seen = set()
        self.asserts = []
        self.graph = Digraph(comment='Slice')
        self.graph.attr('node', shape='ellipse')
        self.optim_map = {}  # Access a variable definition more easily
        self.nb_defs = 0
        self.nb_store = 0
        self.nb_select = 0

    #============================= PARSING ==============================
    def parse(self, data):
        lines = [i.strip() for i in data.split("\n") if i != '']
        groups = group(lines)
        current_offset = -1
        for line in groups:
            if line.startswith(";"):
                current_offset = self.parse_comment(current_offset, line)
            else:
                item = parse_parentheses(line)[0]
                command = item[0]
                if command == "define-fun":
                    if not item[2]:
                        self.formula[current_offset].append(self.parse_define_fun(item[1:]))
                    else:
                        self.formula[current_offset].append(Raw(line))
                elif command == "assert":
                    self.asserts.append([current_offset, len(self.formula[current_offset])])
                    e = self.parse_bv_expr(item[1:][0])
                    self.formula[current_offset].append(Assert(e))
                elif command == "declare-fun":
                    self.formula[current_offset].append(self.parse_declare_fun(item[1:]))
                else:
                    self.formula[current_offset].append(Raw(line))

    def parse_comment(self, current_offset, line):
        if line.startswith("; ---"):  # We are on a new instruction
            try:
                splitted = [x for x in line.split()][2:-1]
                addr = int(splitted[0], 16)
                off = int(splitted[1][1:])
                opcode = ' '.join(splitted[2:])
                self.offset_instr[off] = (addr, opcode)
                self.formula[off] = []
                return off
            except Exception:
                print "Unexcepected comment:", line
                return current_offset
        else:
            return current_offset

    def parse_define_fun(self, elts):
        name = elts[0]
        self.nb_defs += 1
        typ = ArrTyp(32, 8) if elts[2][0] == 'Array' else BvTyp(elts[2][2])
        e = self.parse_bv_expr(elts[3])
        self.optim_map[name] = e
        return VarDef(name, typ, e)

    def parse_declare_fun(self, elts):
        name = elts[0]
        typ = ArrTyp(32, 8) if elts[2][0] == 'Array' else BvTyp(elts[2][2])
        self.inputs.add(name)
        return Input(name, typ)

    def parse_bv_expr(self, e):
        if isinstance(e, list):
            s = e[0]
            if s == "_":
                return Bv(int(e[1][2:]), e[2])
            elif s in self.bvunary_op:
                return UnOp(s, self.parse_bv_expr(e[1]), None, None)
            elif s in self.bvbinary_op:
                return BinOp(s, self.parse_bv_expr(e[1]), self.parse_bv_expr(e[2]))
            elif s in self.binary_op:
                return BinOp(s, self.parse_bv_expr(e[1]), self.parse_bv_expr(e[2]))
            elif s in self.unary_op:
                return UnOp(s, self.parse_bv_expr(e[1]), None, None)
            elif s == 'ite':
                return Ite(self.parse_bv_expr(e[1]), self.parse_bv_expr(e[2]), self.parse_bv_expr(e[3]))
            elif s == 'select':
                self.nb_select += 1
                return Select(Var(e[1]), self.parse_bv_expr(e[2]))
            elif s == 'load32_at':
                self.nb_select += 1
                return Select32(Var(e[1]), self.parse_bv_expr(e[2]))
            elif s == 'store':
                self.nb_store += 1
                if isinstance(e[1], list):
                    memory = self.parse_bv_expr(e[1])
                else:
                    memory = Var(e[1])
                return Store(memory, self.parse_bv_expr(e[2]), self.parse_bv_expr(e[3]))
            elif s == 'store32_at':
                self.nb_store += 1
                return Store32(Var(e[1]), self.parse_bv_expr(e[2]), self.parse_bv_expr(e[3]))
            elif s == 'let':
                return Let([(x[0], self.parse_bv_expr(x[1])) for x in e[1]], self.parse_bv_expr(e[2]))
            elif s == "false":
                return False
            elif s == 'true':
                return True
            elif isinstance(s, list):
                if s[0] == "_" and s[1] in self.bvunary_op:
                    if s[1] == "extract":
                        return UnOp(s[1], self.parse_bv_expr(e[1]), s[2], s[3])
                    else:
                        return UnOp(s[1], self.parse_bv_expr(e[1]), s[2], None)
                else:
                    print "Unknown list in bvexpr", s[0]
            else:
                print "Uknown bv token:", s
                sys.exit(1)
        elif isinstance(e, str) or isinstance(e, unicode):
            if e.startswith("#b"):
                return Bv(int(e[2:], 16), len(e[2:]))
            elif e.startswith("#x"):
                return Bv(int(e[2:], 16), len(e[2:])*4)
            else:
                return Var(e)
        elif isinstance(e, bool):
            return e
        else:
            print "Is going to return none! %s  Type:%s" % (repr(e), str(type(e)))
    # ===============================================================

    # ========================== SLICING ============================
    def slice(self, output, offset=None, nth=None):
        if offset is None and nth is None:
            offset = max(self.formula.keys())
            nth = [i for i, x in zip(range(len(self.formula[offset])), self.formula[offset])
                   if isinstance(x, Assert)][-1]
        i = offset
        while i >= -1:
            if i in self.formula:
                items = self.formula[i]
                indexes = range(nth+1) if i == offset else range(len(items))
                for j in reversed(indexes):
                    item = items[j]
                    tokeep = (i == offset and j == nth)
                    if self.visit_command(item, tokeep, loc=(i, j)):
                        pass  # ok cool we keep :p
            i -= 1

        print "Rendering.."
        self.graph.render(filename=output)
        self.var_seen = set()

    def visit_command(self, com, keep=False, loc=(0, 0)):
        if isinstance(com, VarDef):
            return self.visit_vardef(com.name, com.type, com.value, keep=keep)
        elif isinstance(com, Assert):
            return self.visit_assert(com.value, keep=keep, loc=loc)
        elif isinstance(com, Input):
            return self.visit_input(com.name, com.type)

    def visit_vardef(self, name, type, value, keep=False):
        if self.var_seen.issuperset({name}) or keep:
            seen = self.get_var_bv_expr(value)
            self.var_seen = self.var_seen.union(seen)
            self.graph.node(name, name+" := "+(self.expr_to_string(value)))
            for var in seen:
                self.graph.edge(name, var)
            return True
        else:
            return False

    def visit_assert(self, constraint, keep=False, loc=(0, 0)):
        name = str(loc)
        seen = self.get_var_bv_expr(constraint)
        if self.var_seen.isdisjoint(seen) and not keep:
            return False
        else:
            self.var_seen = self.var_seen.union(seen)
            self.graph.attr('node', shape="box")
            self.graph.node(name, "Constraint:"+(self.expr_to_string(constraint)))
            self.graph.attr("node", shape="ellipse")
            for var in seen:
                self.graph.edge(name, var)
            return True

    def visit_input(self, name, type):
        return self.var_seen.issuperset({name})

    def get_var_bv_expr(self, e):
        if isinstance(e, Bv):
            return set()
        elif isinstance(e, Var):
            return {e.name}
        elif isinstance(e, UnOp):
            return self.get_var_bv_expr(e.expr)
        elif isinstance(e, BinOp):
            return self.get_var_bv_expr(e.expr1).union(self.get_var_bv_expr(e.expr2))
        elif isinstance(e, Ite):
            return self.get_var_bv_expr(e.cond).union(self.get_var_bv_expr(e.expr1).union(self.get_var_bv_expr(e.expr2)))
        elif isinstance(e, Select):
            return self.get_var_bv_expr(e.expr)  # Here does not gather memory name
        elif isinstance(e, Select32):
            return self.get_var_bv_expr(e.expr)  # Does not gather memory name
        elif isinstance(e, Let):
            vars = reduce(set.union, [self.get_var_bv_expr(x) for (x, y) in e.bindings])
            return self.get_var_bv_expr(e.expr).union(vars)
        elif isinstance(e, Store):
            return self.get_var_bv_expr(e.addr).union(self.get_var_bv_expr(e.expr))
        elif isinstance(e, Store32):
            return self.get_var_bv_expr(e.addr).union(self.get_var_bv_expr(e.expr))
        else:
            print "Unknown type", type(e)
            return set()
    # ===============================================================

    # ====================== REPLACEMENTS ===========================
    def replace_var_bv_expr(self, name, sub, e):
        if isinstance(e, Bv):
            return e
        elif isinstance(e, Var):
            return sub if e.name == name else e
        elif isinstance(e, UnOp):
            return UnOp(e.op, self.replace_var_bv_expr(name, sub, e.expr), e.opt1, e.opt2)
        elif isinstance(e, BinOp):
            return BinOp(e.op, self.replace_var_bv_expr(name, sub, e.expr1), self.replace_var_bv_expr(name, sub, e.expr2))
        elif isinstance(e, Ite):
            return Ite(self.replace_var_bv_expr(name, sub, e.cond), self.replace_var_bv_expr(name, sub, e.expr1),
                       self.replace_var_bv_expr(name, sub, e.expr2))
        elif isinstance(e, Select):
            return Select(e.array, self.replace_var_bv_expr(name, sub, e.expr))
        elif isinstance(e, Select32):
            return Select32(e.array, self.replace_var_bv_expr(name, sub, e.expr))
        elif isinstance(e, Store):
            return Store(e.array, self.replace_var_bv_expr(name, sub, e.addr), self.replace_var_bv_expr(name, sub, e.expr))
        elif isinstance(e, Store32):
            return Store32(e.array, self.replace_var_bv_expr(name, sub, e.addr), self.replace_var_bv_expr(name, sub, e.expr))
        else:
            print "Unknown type", type(e)
            return e
    # ===============================================================

    # =========================== PRINTING ==========================
    def formula_to_string(self):
        for k in sorted(self.formula.keys()):
            l = self.formula[k]
            yield "\n; ----- %d -----" % k  # TODO: use mapping offset instr to regenerate same thing
            for i in range(len(l)):
                item = l[i]
                yield self.command_to_string(item)

    def command_to_string(self, item):
        if isinstance(item, VarDef):
            return "(define-fun %s () %s %s)" % (item.name, self.type_to_string(item.type), self.expr_to_string(item.value))
        elif isinstance(item, Input):
            return "(declare-fun %s () %s)" % (item.name, self.type_to_string(item.type))
        elif isinstance(item, Assert):
            return "(assert %s)" % self.expr_to_string(item.value)
        elif isinstance(item, Raw):
            return item.raw

    def print_formula(self, output=None):
        for s in self.formula_to_string():
            output.write(s+"\n")

    @staticmethod
    def type_to_string(typ):
        if isinstance(typ, BvTyp):
            return "(_ BitVec %s)" % typ.size
        else:
            return "(Array (_ BitVec %d) (_ BitVec %d))" % (typ.index_size, typ.content_size)

    def expr_to_string(self, e):
        if isinstance(e, Bv):
            if e.size < 8:
                return "#"+bin(e.value)[1:]
            else:
                return "#x"+hex(e.value)[2:].zfill(e.size/4)
        elif isinstance(e, Var):
            return e.name
        elif isinstance(e, UnOp):
            if e.op == "extract":
                return "((_ %s %s %s)  %s)" % (e.op, e.opt1, e.opt2, self.expr_to_string(e.expr))
            if e.op in ["zero_extend", "sign_extend", "rotate_left", "rotate_right"]:
                return "((_ %s %s) %s)" % (e.op, e.opt1, self.expr_to_string(e.expr))
            else:
                return "(%s %s)" % (e.op, self.expr_to_string(e.expr))
        elif isinstance(e, BinOp):
            return "(%s %s %s)" % (e.op, self.expr_to_string(e.expr1), self.expr_to_string(e.expr2))
        elif isinstance(e, Ite):
            return "(ite %s %s %s)" % (self.expr_to_string(e.cond), self.expr_to_string(e.expr1), self.expr_to_string(e.expr2))
        elif isinstance(e, Select):
            return "(select %s %s)" % (e.array.name, self.expr_to_string(e.expr))
        elif isinstance(e, Select32):
            return "(load32_at %s %s)" % (e.array.name, self.expr_to_string(e.expr))
        elif isinstance(e, Let):
            s = "(let \n("
            for x, y in e.bindings:
                s += "(%s %s)\n" % (x, self.expr_to_string(y))
            s += ")\n %s)" % (self.expr_to_string(e.expr))
            return s
        elif isinstance(e, Store):
            return "(store %s %s %s)" % (self.expr_to_string(e.array), self.expr_to_string(e.addr), self.expr_to_string(e.expr))
        elif isinstance(e, Store32):
            return "(store32_at %s %s %s)" % (e.array.name, self.expr_to_string(e.addr), self.expr_to_string(e.expr))
        elif isinstance(e, bool):
            return str(e).lower()
        else:
            return "UNKNOWN"

    @staticmethod
    def bop_to_pp_string(op):
        return {"bvadd": "+", "bvsub": "-", "bvmul": "*", "bvudiv": "/", "bvsdiv": "/",
                "bvurem": "rem", "bvsrem": "rem", "bvsmod": "%", "bvor": "||", "bvnor": "!||",
                "bvand": "&&", "bvnand": "!&&", "bvxor": "⨁", "bvxnor": "!⨁", "concat": "::",
                "bvshl": "≪", "bvlshr": "≫", "bvashr": "≫", "bvcomp": "=", "bvule": "≤",
                "bvult": "<", "bvuge": "≥", "bvugt": ">", "bvsle": "≤", "bvslt": "<", "bvsge": "≥",
                "bvsgt": ">", "=": "="}[op]
    # =================================================================

    # ======================= UTILITIES FUNCTIONS =====================
    def get_addresses(self):
        return {x[0] for x in self.offset_instr.values()}


if __name__ == "__main__":
    import sys
    import subprocess
    f = SMTFormula()
    f.parse(open(sys.argv[1], 'r').read())
    for line in f.formula_to_string():
        print line
    output = "/tmp/slice_test"
    f.slice(output)
    res = subprocess.call(["dot", "-Tpdf", output, "-o", output+".pdf"])
    if res != 0:
        print "Something went wrong with dot"
    else:
        subprocess.Popen(["xdg-open", output+".pdf"])
