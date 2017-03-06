#!/usr/bin/env python
# -*- coding: utf-8 -*-

from idasec.dba_io import *

def to_indice_str(s):
    matrix = ["₀", "₁", "₂", "₃", "₄", "₅", "₆", "₇", "₈", "₉"]
    ret = ""
    for c in s:
        val = int(c)
        ret += matrix[val] if 0 <= val <= 9 else "X"
    return ret


def bitvector_to_string(bv):
    val = to_indice_str(str(bv.size))
    return hex(bv.value)+"₍"+val+"₎"


def dbacodeaddress_to_string(addr):
    return "("+bitvector_to_string(addr.addr)+","+str(addr.offset)+")"


def codeaddress_to_string(addr):
    if addr.loc == Near:
        return str(addr.addr)
    elif addr.loc == Far:
        return dbacodeaddress_to_string(addr.addr)


def binaryop_to_string(bop):
    return {Plus: " + ", Minus: " - ", MulU: " *𝒖 ", MulS: " *𝒔 ", DivU: " / ", DivS: " /𝒔 ", ModU: " mod𝒖 ",
            ModS: " mod𝒔 ", Or: " || ", And: " && ", Xor: " ⨁ ", Concat: " :: ", Lshift: " ≪ ", RshiftU: " ≫𝒖 ",
            RshiftS: " ≫𝒔 ", Lrotate: " lrotate ", Rrotate: " rrotate ", Equal: " = ", Diff: " ≠ ", LeqU: " ≤𝒖 ",
            LtU: " <𝒖 ", GeqU: " ≥𝒖 ", GtU: " >𝒖 ", LeqS:  " ≤𝒔 ", LtS: " <𝒔 ", GeqS: " ≥𝒔 ", GtS: " >𝒔 ",
            ExtU: " ext𝒖 ", ExtS: " ext𝒔 "}[bop]


def unaryop_to_string(op):
    return {UMinus: "-", Not: "¬"}[op]


def endianess_to_string(en):
    return {Little: "𝐿", Big: "𝐵"}[en]


def dbaexpr_to_string(e, toplevel=True):
    op = "" if toplevel else "("
    oc = "" if toplevel else ")"
    if isinstance(e, Bv):
        return bitvector_to_string(e)
    elif isinstance(e, Var):
        return e.name
    elif isinstance(e, Load):
        return "@["+dbaexpr_to_string(e.expr, True)+"]"+endianess_to_string(e.endian)+to_indice_str(str(e.size))
    elif isinstance(e, UnOp):
        return op+unaryop_to_string(e.uop)+dbaexpr_to_string(e.expr, False)+oc
    elif isinstance(e, BinOp):
        se1 = dbaexpr_to_string(e.left, False)
        se2 = dbaexpr_to_string(e.right, False)
        return op+se1+binaryop_to_string(e.bop)+se2+oc
    elif isinstance(e, Restrict):
        return op+dbaexpr_to_string(e.expr, False)+"{"+("" if e.low == e.high else str(e.low)+",")+str(e.high)+"}"+oc
    elif isinstance(e, Ite):
        return '%sif %s %s else %s%s' % (op, dbacond_to_string(e.cond), dbaexpr_to_string(e.expr1, False),
                                         dbaexpr_to_string(e.expr2, False), oc)
    elif isinstance(e, int):
        return str(e)
    else:
        return "INVALID"


def dbacond_to_string(c):
    if isinstance(c, bool):
        return str(c)
    elif is_expression(c):
        return dbaexpr_to_string(c, True)
    elif isinstance(c, UnCond):
        if c.uop == Not:
            return "¬"+dbacond_to_string(c.cond)
        else:
            return "INVALID"
    elif isinstance(c, BinCond):
        if c.bop in [Or, And]:
            return dbacond_to_string(c.cond1)+" "+binaryop_to_string(c.bop)+" "+dbacond_to_string(c.cond2)
        else:
            return "INVALID"
    else:
        return "INVALID"


def lhs_to_string(lhs):
    if isinstance(lhs, Var):
        return lhs.name
    elif isinstance(lhs, Store):
        return "@["+dbaexpr_to_string(lhs.expr, True)+"]"+endianess_to_string(lhs.endian)+to_indice_str(str(lhs.size))
    else:
        return "INVALID"


def instr_to_string(inst):
    if isinstance(inst.instr, Assign):
        if isinstance(inst.instr.expr, Undef):
            return lhs_to_string(inst.instr.lhs) + " := \undef"
        else:
            return lhs_to_string(inst.instr.lhs) + " := "+dbaexpr_to_string(inst.instr.expr, True)
    elif isinstance(inst.instr, Jump):
        if isinstance(inst.instr.target, JmpAddr):
            return "goto "+codeaddress_to_string(inst.instr.target)
        elif is_expression(inst.instr.target):
            return "goto "+dbaexpr_to_string(inst.instr.target)
        else:
            return "INVALID"
    elif isinstance(inst.instr, If):
        c1 = dbacond_to_string(inst.instr.cond)
        t1 = codeaddress_to_string(inst.instr.target1)
        t2 = str(inst.instr.target2)
        return "if (%s) goto %s else %s" % (c1, t1, t2)
    else:
        return "INVALID"


if __name__ == "__main__":
    data = open("out2.dba", "rb").read()
    from proto import dba_pb2
    mylist = dba_pb2.dba_list()
    mylist.ParseFromString(data)
    l = parse_dbalist(mylist)
    for inst in l:
        print instr_to_string(inst)
