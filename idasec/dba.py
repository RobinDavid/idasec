from collections import namedtuple

# Unary ops
UMinus = 100
Not = 101

Little = 200
Big = 201

Near = 300
Far = 301

Call = 400
Return = 401

# Binary ops
Plus = 500
Minus = 501
MulU = 502
MulS = 503
DivU = 504
DivS = 505
ModU = 506
ModS = 507
Or = 508
And = 509
Xor = 510
Concat = 511
Lshift = 512
RshiftU = 513
RshiftS = 514
Lrotate = 515
Rrotate = 516
Equal = 517
Diff = 518
LeqU = 519
LtU = 520
GeqU = 521
GtU = 522
LeqS = 523
LtS = 524
GeqS = 525
GtS = 526
ExtU = 527
ExtS = 528

# bitvector are simply tuple
Bv = namedtuple("Bitvector", "value size")
Addr = namedtuple("DbaAddr", "addr offset")
JmpAddr = namedtuple("DbaJmpAddr", "loc addr")  # addr either offset or Addr

# Expression
Var = namedtuple("DbaExprVar", "name size")
Load = namedtuple("DbaExprLoad", "expr size endian")
UnOp = namedtuple("DbaExprUnary", "uop expr")
BinOp = namedtuple("DbaExprBinary", "left bop right")
Restrict = namedtuple("DbaExprRestrict", "expr low high")
Ite = namedtuple("DbaExprIte", "cond expr1 expr2")
Undef = namedtuple("DbaExprUndef", "")

# Cond
UnCond = namedtuple("DbaUnaryCond", "uop cond")
BinCond = namedtuple("DbaBinaryCond", "cond1 bop cond2")

# Lhs
Store = namedtuple("DbaStore", "expr size endian")

# Instr
Assign = namedtuple("DbaIkAssign", "lhs expr")
Jump = namedtuple("DbaJump", "target")
If = namedtuple("DbaIf", "cond target1 target2")

# Unusually used
Stop = namedtuple("DbaStop", "")
Assert = namedtuple("DbaAssert", "cond")
Assume = namedtuple("DbaAssume", "cond")
NonDet = namedtuple("DbaNonDet", "lhs")
# Undef  = namedtuple("DbaUndef", "lhs")
Malloc = namedtuple("DbaMalloc", "lhs expr")
Free = namedtuple("DbaFree", "expr")

Instr = namedtuple("DbaInstr", "addr instr offset")


class DbaException(Exception):
    pass


def is_expression(e):
    return type(e) in [Bv, Var, Load, UnOp, BinOp, Restrict, Ite]


def is_strict_condition(c):
    return type(c) in [bool, UnCond, BinCond]


def dbaexpr_size(e):
    if type(e) in [Bv, Var, Load]:
        return e.size
    elif isinstance(e, UnOp):
        return dbaexpr_size(e.expr)
    elif isinstance(e, BinOp):
        return dbaexpr_size(e.left)
    elif isinstance(e, Restrict):
        return e.high - e.low+1
    elif isinstance(e, Ite):
        return dbaexpr_size(e.expr1)
    else:
        raise DbaException("Unknown expression type:", type(e))
