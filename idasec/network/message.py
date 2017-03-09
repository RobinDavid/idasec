from idasec.proto.message_pb2 import *
from idasec.proto.common_pb2 import *
from idasec.dba_io import parse_dbalist


class AbstractMessage:
    def __init__(self):
        pass

    def parse(self, raw):
        pass

    def serialize(self):
        pass


lookup_irkind = {"DBA": DBA, "BAP": BAP, "MIASM": MIASM}
reverse_lookup_irkind = {DBA: "DBA", BAP: "BAP", MIASM: "MIASM"}


class MessageDecodeInstr(AbstractMessage):

    lookup_kind = {"hexa": message_decode_instr.HEXA, "bin": message_decode_instr.BIN}
    reverse_lookup = {message_decode_instr.HEXA: "hexa", message_decode_instr.BIN: "bin"}

    def __init__(self, irkind="DBA", kind="bin", instrs=[], base_addrs=[]):
        AbstractMessage.__init__(self)
        self.message = message_decode_instr()
        self.kind = kind
        self.irkind = irkind
        self.instrs = instrs
        self.base_addrs = base_addrs

    def serialize(self):
        self.message.kind = self.lookup_kind[self.kind]
        self.message.irkind = lookup_irkind[self.irkind]
        if isinstance(self.instrs, str):
            elt = self.message.instrs.add()
            elt.instr = self.instrs
            elt.base_addr = self.base_addrs
        elif isinstance(self.instrs, list):
            for i in xrange(len(self.instrs)):
                print("Loop instrs"+str(i))
                elt = self.message.instrs.add()
                elt.instr = self.instrs[i]
                if len(self.base_addrs) > i:
                    elt.base_addr = self.base_addrs[i]
                else:
                    elt.base_addr = 0
        return self.message.SerializeToString()

    def parse(self, raw):
        self.message.ParseFromString(raw)
        self.kind = self.reverse_lookup[self.message.kind]
        self.irkind = reverse_lookup_irkind[self.message.irkind]
        self.instrs = self.message.instrs
        self.base_addrs = self.message.base_addrs


class MessageDecodeInstrReply(AbstractMessage):

    def __init__(self, kind="DBA", instrs=[]):
        self.message = message_decode_instr_reply()
        self.instrs = instrs
        self.irkind = kind

    def serialize(self):
        # TODO: Writing a real serialization module
        return self.message.SerializeToString()

    def parse(self, raw):
        if type(raw) == unicode:
            data = bytearray(raw, "utf-8")
            raw = bytes(data)
        self.message.ParseFromString(raw)
        for entry in self.message.instrs:
            opcode = entry.opcode
            self.irkind = reverse_lookup_irkind[entry.irkind]
            if self.irkind == "DBA":
                self.instrs.append((opcode, parse_dbalist(entry.dba_instrs)))
            else:
                print "IR kind not supported"
        # else: Take them in the other field


class MessageInfos(AbstractMessage):
    def __init__(self):
        self.message = message_infos()

    def serialize(self):
        # TODO: Writing a real serialization module
        return self.message.SerializeToString()

    def parse(self, raw):
        self.message.ParseFromString(raw)

    def get_infos(self):
        return self.message.nb_workers, self.message.analyses, self.message.solvers
