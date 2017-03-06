#!/usr/bin/env python
import struct

from capstone import Cs, CS_ARCH_X86, CS_MODE_32

from idasec.proto.trace_pb2 import *
from idasec.proto.common_pb2 import *
from idasec.exception import assert_ida_available


md = Cs(CS_ARCH_X86, CS_MODE_32)


def proto_size_t_to_int(a):
    return {INVALID_SIZE: -1,
            BIT8: 8,
            BIT16: 16,
            BIT32: 32,
            BIT64: 64,
            BIT80: 80,
            BIT128: 128,
            BIT256: 256}[a]


class Instruction:
    def __init__(self):
        self.thread = None
        self.address = None
        self.opcode = ""
        self.opc_bytes = None
        self.decoded = False
        self.dbainstrs = []

        # Concrete infos
        self.nextaddr = None
        self.registers = []
        self.memories = []
        self.comment = None
        self.wave = None
        self.syscall = None
        self.libcall = None
        self.not_retrieved = False

    def parse(self, pb_inst):
        self.thread = pb_inst.thread_id
        self.address = pb_inst.address
        self.opc_bytes = pb_inst.opcode
        for i in md.disasm(self.opc_bytes, self.address):
            self.opcode += i.mnemonic + " "+i.op_str
        if len(pb_inst.dba_instrs.instrs) != 0:
            self.decoded = True
            # TODO: Add the decoding of DBA instructions
        else:
            pass
        for info in pb_inst.concrete_infos:
            if info.typeid == ins_con_info_t.REGREAD:
                self.add_register(info.read_register, "R")
            elif info.typeid == ins_con_info_t.REGWRITE:
                self.add_register(info.write_register, "W")
            elif info.typeid == ins_con_info_t.MEMLOAD:
                self.memories.append(("R", info.load_memory.addr, info.load_memory.value))
            elif info.typeid == ins_con_info_t.MEMSTORE:
                self.memories.append(("W", info.store_memory.addr, info.store_memory.value))
            elif info.typeid == ins_con_info_t.CALL:
                self.libcall = info.call
            elif info.typeid == ins_con_info_t.SYSCALL:
                self.syscall = info.system_call
            elif info.typeid == ins_con_info_t.NEXT_ADDRESS:
                self.nextaddr = info.next_address
            elif info.typeid == ins_con_info_t.COMMENT:
                self.comment = info.reserved_comment
            elif info.typeid == ins_con_info_t.WAVE:
                self.wave = info.wave

    def add_register(self, reg, r_or_w):
        value = {BIT8: reg.value.value_8,
                 BIT16: reg.value.value_16,
                 BIT32: reg.value.value_32,
                 BIT64: reg.value.value_64,
                 BIT80: reg.value.value_80,
                 BIT128: reg.value.value_128,
                 BIT256: reg.value.value_256}[reg.value.typeid]
        if reg != "ss":
            self.registers.append((r_or_w, reg.name, value))

    def to_string(self):
        address = hex(self.address)[:-1]
        raw_opc = to_hex_spaced(self.opc_bytes)
        concs = ""
        concs += "" if self.libcall is None else " Call:"+self.libcall.func_name
        concs += "" if self.syscall is None else " "+str(self.syscall.id)
        concs += "" if self.comment is None else " Comment:"+self.comment
        for r_w, reg, value in self.registers:
            val = hex(value) if isinstance(value, int) else to_hex(value)
            concs += " "+r_w+"["+reg+"]="+val
        for r_w, addr, value in self.memories:
            concs += " "+r_w+"@["+hex(addr)+"]="+to_hex(value)
        concs += " Next:"+hex(self.nextaddr) if self.nextaddr is not None else ""
        padding1 = " " * (25 - len(raw_opc))
        padding2 = " " * (16 - len(self.opcode) + len(padding1) + len(raw_opc))
        th = self.thread
        return "%s t[%d] %s%s%s%s %s" % (address, th, raw_opc, padding1, self.opcode, padding2, concs)


class Trace:

    def __init__(self, fname):
        self.filename = fname
        self.addr_size = 32
        self.architecture = None
        self.instrs = {}
        self.metas = {}
        self.trace_index = 0
        self.length = lambda: self.trace_index - 1
        self.addr_covered = set()
        self.address_hit_count = {}

    def parse_file_generator(self, filename):
        self.filename = filename
        f = open(filename, "rb")
        size, = struct.unpack("I", f.read(4))
        header = header_t()
        header.ParseFromString(f.read(size))
        self.architecture = header.architecture
        self.addr_size = proto_size_t_to_int(header.address_size)
        chunk_nb = 0
        chunk = chunk_t()
        while True:
            tmp = f.read(4)
            if tmp == "":
                break
            else:
                chunk_nb += 1
                old_index = self.trace_index
                size, = struct.unpack("I", tmp)
                chunk.ParseFromString(f.read(size))
                self.add_body(chunk.body)
                yield chunk_nb, len(chunk.body), old_index, self.trace_index, size
        f.close()

    def parse_file(self, filename):
        for _, _, _, _, _ in self.parse_file_generator(filename):
            pass

    def add_body(self, body):
        for elem in body:
            if elem.typeid == body_t.METADATA:
                m = {metadata_t.INVALID_METADATA: ("invalid", None, None),
                     metadata_t.EXCEPTION_TYPE: ('exception', elem.metadata.exception_metadata.type_exception,
                                                 elem.metadata.exception_metadata.handler),
                     metadata_t.MODULE_TYPE: ('module', elem.metadata.module_metadata, None),
                     metadata_t.WAVE_TYPE: ("wave", elem.metadata.wave_metadata, None)}[elem.metadata.typeid]
                if self.trace_index in self.metas:
                    self.metas[self.trace_index].append(m)
                else:
                    self.metas[self.trace_index] = [m]
            elif elem.typeid == body_t.INSTRUCTION:
                inst = Instruction()
                inst.parse(elem.instruction)
                self.instrs[self.trace_index] = inst
                self.addr_covered.add(inst.address)
                if inst.address in self.address_hit_count:
                    self.address_hit_count[inst.address] += 1
                else:
                    self.address_hit_count[inst.address] = 1
                self.trace_index += 1

    def to_string_generator(self):
        for i in xrange(self.trace_index):
            if i in self.metas:
                for m in self.metas[i]:
                    name_id, arg1, arg2 = m
                    if name_id == "invalid":
                        print name_id
                    elif name_id == "exception":
                        print "Exception, type:"+str(arg1)+" handler:"+to_hex(arg2)
                    elif name_id == "wave":
                        print "====================== Wave "+str(arg1) + "======================"
            yield "%d %s" % (i, self.instrs[i].to_string())

    def print_trace(self):
        for line in self.to_string_generator():
            print line


def make_header():
    header = header_t()
    header.architecture = header.X86
    header.address_size = BIT32
    return header


def chunk_from_path(path):
    assert_ida_available()
    import idc
    chunk = chunk_t()
    for i in xrange(len(path)):
        body = chunk.body.add()
        body.typeid = body.INSTRUCTION
        inst = body.instruction
        inst.thread_id = 0
        addr = path[i]
        inst.address = addr
        inst.opcode = idc.GetManyBytes(addr, idc.NextHead(addr)-addr)
        try:
            next_a = path[i+1]
            inf1 = inst.concrete_infos.add()
            inf1.next_address = next_a
            inf1.typeid = inf1.NEXT_ADDRESS
        except IndexError:
            pass
        inf2 = inst.concrete_infos.add()
        inf2.typeid = inf2.NOT_RETRIEVED
    return chunk


def raw_parse_trace(filename):
    f = open(filename, "rb")
    size, = struct.unpack("I", f.read(4))
    raw_header = f.read(size)
    yield "TRACE_HEADER", raw_header
    while True:
        tmp = f.read(4)
        if tmp == "":
            break
        else:
            size, = struct.unpack("I", tmp)
            raw = f.read(size)
            yield "TRACE_CHUNK", raw
    f.close()


if __name__ == "__main__":
    from utils import to_hex_spaced, to_hex
    if len(sys.argv) < 2:
        print "Please provide a trace in parameter"
        sys.exit(1)

    name = sys.argv[1]

    trace = Trace(name)
    trace.parse_file(name)
    trace.print_trace()
