from dba import *
from proto import dba_pb2
from proto.dba_pb2 import dbaexpr


class GenerationError(Exception):
    pass


class ParsingError(Exception):
    pass


def generate_bitvector(in_bv):
    bv = dba_pb2.bitvector()
    bv.bv = in_bv.value
    bv.size = in_bv.size
    return bv


def parse_bitvector(proto_bv):
    return Bv(proto_bv.bv, proto_bv.size)


def generate_dbacodeaddress(in_addr):
    addr = dba_pb2.dbacodeaddress()
    addr.bitvector.CopyFrom(generate_bitvector(in_addr.addr))
    addr.dbaoffset = in_addr.offset
    return addr


def parse_dbacodeaddress(pb_addr):
    bv = parse_bitvector(pb_addr.bitvector)
    return Addr(bv, pb_addr.dbaoffset)


def generate_codeaddress(addr):
    pbaddr = dba_pb2.codeaddress()
    if addr.loc == Near:
        pbaddr.typeid = pbaddr.Local
        pbaddr.offset = addr.addr
    elif addr.loc == Far:
        pbaddr.typeid = pbaddr.NonLocal
        pbaddr.address.CopyFrom(generate_dbacodeaddress(addr.addr))
    else:
        raise GenerationError()
    return pbaddr


def parse_codeaddres(pb_addr):
    if pb_addr.typeid == dba_pb2.codeaddress.Local:
        return JmpAddr(Near, pb_addr.offset)
    elif pb_addr.typeid == dba_pb2.codeaddress.NonLocal:
        return JmpAddr(Far, parse_dbacodeaddress(pb_addr.address))
    else:
        raise GenerationError()


# generate_dbatags (ignored)
# parse_dbatags (ignored)

# generate_dbastate (ignored)
# parse_dbastate (ignored)

def generate_binary_op(op):
    return {Plus: dbaexpr.DbaPlus, Minus: dbaexpr.DbaMinus, MulU: dbaexpr.DbaMultU,
            MulS: dbaexpr.DbaMultS, DivU: dbaexpr.DbaDivU, DivS: dbaexpr.DbaDivS, ModU: dbaexpr.DbaModU,
            ModS: dbaexpr.DbaModS, Or: dbaexpr.DbaOr, And: dbaexpr.DbaAnd, Xor: dbaexpr.DbaXor,
            Concat: dbaexpr.DbaConcat, Lshift: dbaexpr.DbaLShiftU, RshiftU: dbaexpr.DbaRShiftU,
            RshiftS: dbaexpr.DbaRShiftS, Lrotate: dbaexpr.DbaLeftRotate, Rrotate: dbaexpr.DbaRightRotate,
            Equal: dbaexpr.DbaEq, Diff: dbaexpr.DbaDiff, LeqU: dbaexpr.DbaLeqU, LtU: dbaexpr.DbaLtU,
            GeqU: dbaexpr.DbaGeqU, GtU: dbaexpr.DbaGtU, LeqS: dbaexpr.DbaLeqS, LtS: dbaexpr.DbaLtS,
            GeqS: dbaexpr.DbaGeqS, GtS: dbaexpr.DbaGtS}[op]


def parse_binary_op(pb_op):
    return {dbaexpr.DbaPlus: Plus, dbaexpr.DbaMinus: Minus, dbaexpr.DbaMultU: MulU,
            dbaexpr.DbaMultS: MulS, dbaexpr.DbaDivU: DivU, dbaexpr.DbaDivS: DivS, dbaexpr.DbaModU: ModU,
            dbaexpr.DbaModS: ModS, dbaexpr.DbaOr: Or, dbaexpr.DbaAnd: And, dbaexpr.DbaXor: Xor,
            dbaexpr.DbaConcat: Concat, dbaexpr.DbaLShiftU: Lshift, dbaexpr.DbaRShiftU: RshiftU,
            dbaexpr.DbaRShiftS: RshiftS, dbaexpr.DbaLeftRotate: Lrotate, dbaexpr.DbaRightRotate: Rrotate,
            dbaexpr.DbaEq: Equal, dbaexpr.DbaDiff: Diff, dbaexpr.DbaLeqU: LeqU, dbaexpr.DbaLtU: LtU,
            dbaexpr.DbaGeqU: GeqU, dbaexpr.DbaGtU: GtU, dbaexpr.DbaLeqS: LeqS, dbaexpr.DbaLtS: LtS,
            dbaexpr.DbaGeqS: GeqS, dbaexpr.DbaGtS: GtS}[pb_op]


def generate_unaryop(op):
    return {UMinus: dbaexpr.DbaUnaryMinus, Not: dbaexpr.DbaUnaryNot}[op]


def parse_unaryop(pb_op):
    return {dbaexpr.DbaUnaryMinus: UMinus, dbaexpr.DbaUnaryNot: Not}[pb_op]


def generate_endianess(en):
    return {Little: dba_pb2.Little, Big: dba_pb2.Big}[en]


def parse_endianess(pb_en):
    return {dba_pb2.Little: Little, dba_pb2.Big: Big}[pb_en]


def generate_dbaexpr(e):
    dba_e = dba_pb2.dbaexpr()
    if isinstance(e, Bv):
        dba_e.typeid = dba_e.DbaExprCst
        dba_e.bitvector.CopyFrom(generate_bitvector(e))
    elif isinstance(e, Var):
        dba_e.typeid = dba_e.DbaExprVar
        dba_e.name = e.name
        dba_e.size = e.size
    elif isinstance(e, Load):
        dba_e.typeid = dba_e.DbaLoad
        dba_e.endian = generate_endianess(e.endian)
        dba_e.size = e.size
        dba_e.expr1.CopyFrom(generate_dbaexpr(e.expr))
    elif isinstance(e, UnOp):
        dba_e.typeid = dba_e.DbaExprUnary
        dba_e.unaryop = generate_unaryop(e.uop)
        dba_e.expr1.CopyFrom(generate_dbaexpr(e.expr))
    elif isinstance(e, BinOp):
        if e.bop in [ExtU, ExtS]:
            dba_e.typeid = {ExtU: dba_e.DbaExprExtU, ExtS: dba_e.DbaExprExtS}[e.bop]
            dba_e.expr1.CopyFrom(generate_dbaexpr(e.left))
            if isinstance(e.right, int):
                dba_e.size = e.right
            else:
                raise GenerationError("Right operand of Extend should be int")
        else:
            dba_e.typeid = dba_e.DbaExprBinary
            dba_e.binaryop = generate_binary_op(e.bop)
            dba_e.expr1.CopyFrom(generate_dbaexpr(e.left))
            dba_e.expr2.CopyFrom(generate_dbaexpr(e.right))
    elif isinstance(e, Restrict):
        dba_e.typeid = dba_e.DbaExprRestrict
        dba_e.expr1.CopyFrom(generate_dbaexpr(e.expr))
        dba_e.low = e.low
        dba_e.high = e.high
    elif isinstance(e, Ite):
        dba_e.typeid = dba_e.DbaExprIte
        dba_e.cond.CopyFrom(generate_dbacond(e.cond))
        dba_e.expr1.CopyFrom(generate_dbaexpr(e.expr1))
        dba_e.expr2.CopyFrom(generate_dbaexpr(e.expr2))
    else:
        raise GenerationError("Unknown expression type:", type(e))
    return dba_e


def parse_dbaexpr(pb_e):
    if pb_e.typeid == pb_e.DbaExprVar:
        return Var(pb_e.name, pb_e.size)
    elif pb_e.typeid == pb_e.DbaLoad:
        return Load(parse_dbaexpr(pb_e.expr1), pb_e.size, parse_endianess(pb_e.endian))
    elif pb_e.typeid == pb_e.DbaExprCst:
        return parse_bitvector(pb_e.bitvector)
    elif pb_e.typeid == pb_e.DbaExprUnary:
        return UnOp(parse_unaryop(pb_e.unaryop), parse_dbaexpr(pb_e.expr1))
    elif pb_e.typeid == pb_e.DbaExprBinary:
        return BinOp(parse_dbaexpr(pb_e.expr1), parse_binary_op(pb_e.binaryop), parse_dbaexpr(pb_e.expr2))
    elif pb_e.typeid == pb_e.DbaExprRestrict:
        return Restrict(parse_dbaexpr(pb_e.expr1), pb_e.low, pb_e.high)
    elif pb_e.typeid == pb_e.DbaExprExtU:
        return BinOp(parse_dbaexpr(pb_e.expr1), ExtU, pb_e.size)
    elif pb_e.typeid == pb_e.DbaExprExtS:
        return BinOp(parse_dbaexpr(pb_e.expr1), ExtS, pb_e.size)
    elif pb_e.typeid == pb_e.DbaExprIte:
        return Ite(parse_dbacond(pb_e.cond), parse_dbaexpr(pb_e.expr1), parse_dbaexpr(pb_e.expr2))
    elif pb_e.typeid == pb_e.DbaExprAlternative:
        raise ParsingError("Alternatives not implemented")
    else:
        raise ParsingError("woot ?")


def generate_dbacond(c):
    dba_c = dba_pb2.dbacond()
    if isinstance(c, bool):
        dba_c.typeid = dba_c.DbaTrue if c else dba_c.DbaFalse
    elif is_expression(c):
        dba_c.typeid = dba_c.DbaCondReif
        dba_c.expr.CopyFrom(generate_dbaexpr(c))
    elif isinstance(c, UnCond):
        if c.uop == Not:
            dba_c.typeid = dba_c.DbaCondNot
            dba_c.cond1.CopyFrom(generate_dbacond(c.cond))
        else:
            raise GenerationError("Unknown unary operator for condition:", type(c.uop))
    elif isinstance(c, BinCond):
        if c.bop in [Or, And]:
            dba_c.typeid = dba_c.DbaCondAnd if c.bop == And else dba_c.DbaCondOr
            dba_c.cond1.CopyFrom(generate_dbacond(c.cond1))
            dba_c.cond2.CopyFrom(generate_dbacond(c.cond2))
        else:
            raise GenerationError("Unknown binary operator for condition", type(c.bop))
    else:
        raise GenerationError("Unknown condition type:", type(c))
    return dba_c


def parse_dbacond(pb_c):
    if pb_c.typeid == pb_c.DbaTrue:
        return True
    elif pb_c.typeid == pb_c.DbaFalse:
        return False
    elif pb_c.typeid == pb_c.DbaCondReif:
        return parse_dbaexpr(pb_c.expr)
    elif pb_c.typeid == pb_c.DbaCondAnd:
        return BinCond(parse_dbacond(pb_c.cond1), And, parse_dbacond(pb_c.cond2))
    elif pb_c.typeid == pb_c.DbaCondOr:
        return BinCond(parse_dbacond(pb_c.cond1), Or, parse_dbacond(pb_c.cond2))
    elif pb_c.typeid == pb_c.DbaCondNot:
        return UnCond(Not, parse_dbacond(pb_c.cond1))
    else:
        raise ParsingError("Woot ?")


def generate_lhs(lhs):
    pb_lhs = dba_pb2.dbaLhs()
    if isinstance(lhs, Var):
        res = reg_to_extract(Var.name)
        pb_lhs.name = lhs.name
        if res is None:
            pb_lhs.typeid = pb_lhs.DbaLhsVar
            pb_lhs.size = lhs.size
        else:
            newname, low, high = res
            pb_lhs.typeid = pb_lhs.DbaLhsVarRestrict
            pb_lhs.size = 32  # Wowow
            pb_lhs.low = low
            pb_lhs.high = high
    elif isinstance(lhs, Store):
        pb_lhs.typeid = pb_lhs.DbaStore
        pb_lhs.size = lhs.size
        pb_lhs.endian = generate_endianess(lhs.endian)
        pb_lhs.expr.CopyFrom(generate_dbaexpr(lhs.expr))
    else:
        raise GenerationError("Unknown lhs type:", type(lhs))
    return pb_lhs


def reg_to_extract(name):
    try:
        return {# "eax": ("eax", 0, 31),
                "ax": ("eax", 15, 31),
                "al": ("eax", 0, 7),
                "ah": ("eax", 8, 15),
                # "ebx": ("ebx", 0, 31),
                "bx": ("ebx", 15, 31),
                "bl": ("ebx", 0, 7),
                "bh": ("ebx", 8, 15),
                # "ecx": ("ecx", 0, 31),
                "cx": ("ecx", 15, 31),
                "cl": ("ecx", 0, 7),
                "ch": ("ecx", 8, 15),
                # "edx": ("edx", 0, 31),
                "dx": ("edx", 15, 31),
                "dl": ("edx", 0, 7),
                "dh": ("edx", 8, 15),
                # "ebp": ("ebp", 0, 31),
                "bp": ("ebp", 0, 15),
                "bpl": ("ebx", 0, 7),
                # "esi": ("esi", 0, 31),
                "si": ("esi", 0, 15),
                "sil": ("esi", 0, 7),
                # "esp": ("esp", 0, 31),
                "sp": ("esp", 0, 15),
                "spl": ("esp", 0, 8)}[name]
    except KeyError:
        return None


def parse_lhs(pb_lhs):
    if pb_lhs.typeid == pb_lhs.DbaLhsVar:
        return Var(pb_lhs.name, pb_lhs.size)
    elif pb_lhs.typeid == pb_lhs.DbaLhsVarRestrict:
        res = extract_to_reg(pb_lhs.name)
        if res is None:
            return Restrict(Var(pb_lhs.name, pb_lhs.size), pb_lhs.low, pb_lhs.high)
        else:
            return Var(res, pb_lhs.high-pb_lhs.low+1)
    elif pb_lhs.typeid == pb_lhs.DbaStore:
        return Store(parse_dbaexpr(pb_lhs.expr), pb_lhs.size, parse_endianess(pb_lhs.endian))
    else:
        raise ParsingError("woot ?")


def extract_to_reg(name):
    try:
        return {#"eax": ("eax", 0, 31),
                ("eax", 15, 31): "ax",
                ("eax", 0, 7): "al",
                ("eax", 8, 15): "ah",
                # "ebx": ("ebx", 0, 31),
                ("ebx", 15, 31): "bx",
                ("ebx", 0, 7): "bl",
                ("ebx", 8, 15): "bh",
                # "ecx": ("ecx", 0, 31),
                ("ecx", 15, 31): "cx",
                ("ecx", 0, 7): "cl",
                ("ecx", 8, 15): "ch",
                # "edx": ("edx", 0, 31),
                ("edx", 15, 31): "dx",
                ("edx", 0, 7): "dl",
                ("edx", 8, 15): "dh",
                # "ebp": ("ebp", 0, 31),
                ("ebp", 0, 15): "bp",
                ("ebx", 0, 7): "bpl",
                # "esi": ("esi", 0, 31),
                ("esi", 0, 15): "si",
                ("esi", 0, 7): "sil",
                # "esp": ("esp", 0, 31),
                ("esp", 0, 15): "sp",
                ("esp", 0, 8): "spl"}[name]
    except KeyError:
        return None


def generate_instr(inst):
    pb_inst = dba_pb2.dbainstr()
    pb_inst.location.CopyFrom(generate_dbacodeaddress(inst.addr))
    pb_inst.offset = inst.offset
    if isinstance(inst.instr, Assign):
        pb_inst.typeid = pb_inst.DbaIkAssign
        pb_inst.lhs.CopyFrom(generate_lhs(inst.instr.lhs))
        pb_inst.expr.CopyFrom(generate_dbaexpr(inst.instr.expr))
        # TODO: Deal with undef expr
    elif isinstance(inst.instr, Jump):
        if isinstance(inst.instr.target, JmpAddr):
            pb_inst.typeid = pb_inst.DbaIkSJump
            pb_inst.address.CopyFrom(generate_codeaddress(inst.instr.target))
        elif is_expression(inst.instr.target):
            pb_inst.typeid = pb_inst.DbaIkDJump
            pb_inst.expr.CopyFrom(generate_dbaexpr(inst.instr.target))
        else:
            raise GenerationError("Jump target type unknown", type(inst.instr.target))
    elif isinstance(inst.instr, If):
        pb_inst.typeid = pb_inst.DbaIkIf
        pb_inst.cond.CopyFrom(generate_dbacond(inst.instr.cond))
        pb_inst.address.CopyFrom(generate_codeaddress(inst.instr.target1))
        pb_inst.offset = inst.instr.target2
    else:
        raise GenerationError("Instruction not implemented")
    return pb_inst


def parse_instr(pb_instr):
    addr = parse_dbacodeaddress(pb_instr.location)
    offset = pb_instr.offset
    if pb_instr.typeid == pb_instr.DbaIkAssign:
        inst = Assign(parse_lhs(pb_instr.lhs), parse_dbaexpr(pb_instr.expr))
    elif pb_instr.typeid == pb_instr.DbaIkSJump:
        inst = Jump(parse_codeaddres(pb_instr.address))
    elif pb_instr.typeid == pb_instr.DbaIkDJump:
        inst = Jump(parse_dbaexpr(pb_instr.expr))
    elif pb_instr.typeid == pb_instr.DbaIkIf:
        inst = If(parse_dbacond(pb_instr.cond), parse_codeaddres(pb_instr.address), pb_instr.offset)
    elif pb_instr.typeid == pb_instr.DbaIkUndef:
        inst = Assign(parse_lhs(pb_instr.lhs), Undef())
    else:
        raise ParsingError("Dba instruction not decoded")
    return Instr(addr, inst, offset)


def generate_dbalist(l):
    dbalist = dba_pb2.dba_list()
    for i in l:
        x = dbalist.instrs.add()
        x.CopyFrom(generate_instr(i))
    return dbalist


def parse_dbalist(pb_l):
    res = []
    for i in pb_l.instrs:
        res.append(parse_instr(i))
    return res


if __name__ == "__main__":
    i1 = Assign(Var("ebx", 32), BinOp(Var("eax", 32), Plus, Bv(401023, 32)))
    i2 = Assign(Var("ah", 8), Ite(True, Restrict(Var("eax", 32), 0, 7), Var("al", 8)))
    i3 = Jump(JmpAddr(Far, Addr(Bv(401022, 32), 0)))
    i4 = If(BinCond(Bv(1, 1), And, True), JmpAddr(Far, Addr(Bv(401020, 32), 0)), 4)
    addr = Addr(Bv(7780052, 32), 0)
    l = [Instr(addr, i1, 0), Instr(addr, i2, 0), Instr(addr, i3, 0), Instr(addr, i4, 0)]
    pb = generate_dbalist(l)
    data = pb.SerializeToString()
    f = open("out2.dba", "wb")
    f.write(data)
    f.close()
