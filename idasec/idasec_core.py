from idasec.broker import Broker
from idasec.proto.config_pb2 import configuration

import idc
import idaapi
import idautils

PE = "\x4d\x5a"
ELF = "\x7fE"


class IDASecCore:
    def __init__(self):
        self.broker = Broker()
        self.trace_id = 0
        self.traces = {}
        self.configuration = configuration()
        self.solvers = []
        self.analyses = []
        self.nb_cpus = 1
        self.binsec_connected = False
        self.pinsec_connected = False
        self.seg_mapping = None
        self.fun_mapping = None
        self.update_mapping()
        self.nb_instr = self.compute_nb_instr()
        self.ftype = "ELF" if open(idaapi.get_input_file_path()).read(2) == ELF else "PE"
        self.imports = self.compute_imports()

    def update_mapping(self):
        pass
        self.fun_mapping = {idc.GetFunctionName(x): (idaapi.get_func(x).startEA, idaapi.get_func(x).endEA-1) for x in
                            idautils.Functions()}
        self.seg_mapping = {idc.SegName(x): (idc.SegStart(x), idc.SegEnd(x)) for x in idautils.Segments()}

    def add_trace(self, t):
        self.traces[self.trace_id] = t
        self.trace_id += 1
        return self.trace_id - 1

    def remove_trace(self, tr_id):
        t = self.traces.pop(tr_id)
        del t

    def compute_nb_instr(self):
        return 0  # FIXME: by iterating all segments
        count = 0
        start, stop = self.seg_mapping[".text"]  # TODO: Iterate all executable segs
        current = start
        while current <= stop:
            if idc.isCode(idc.GetFlags(current)):
                count += 1
            current = idc.NextHead(current, stop)
        return count

    @staticmethod
    def compute_imports():
        imports = {}
        current = ""

        def callback(ea, name, ordinal):
            imports[current].append((ea, name, ordinal))
            return True

        nimps = idaapi.get_import_module_qty()
        for i in xrange(0, nimps):
            current = idaapi.get_import_module_name(i)
            imports[current] = []
            idaapi.enum_import_names(i, callback)
        return imports
