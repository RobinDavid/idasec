"""
Author: Robin David (robin.david@cea.fr)

Binsec is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version http://www.gnu.org/licenses/.
"""

import json

from protobuf_json import json2pb, pb2json
from proto.config_pb2 import configuration
from idasec.exception import assert_ida_available


PE = "\x4d\x5a"
ELF = "\x7fE"


class Configuration:
    def __init__(self):
        self.config = configuration()

    def set_start_stop(self, ftype):
        assert_ida_available()
        import idc
        import idaapi
        import idautils
        fun_mapping = {idc.GetFunctionName(x): (idaapi.get_func(x).startEA, idaapi.get_func(x).endEA-1)
                       for x in idautils.Functions()}
        start = idc.BeginEA()
        stop = 0
        if ftype == PE:
            start, stop = fun_mapping["start"]
        else:
            if not idc.isCode(idc.GetFlags(start)):
                if idc.MakeCode(start) == 0:
                    print "Fail to decode instr !"
                idaapi.autoWait()
            if idc.GetFunctionName(start) == "":
                if idc.MakeFunction(start) == 0:
                    print "Fail to create function !"
                idaapi.autoWait()
                fun_mapping = {idc.GetFunctionName(x): (idaapi.get_func(x).startEA, idaapi.get_func(x).endEA-1)
                               for x in idautils.Functions()}

            if "main" in fun_mapping:
                start, stop = fun_mapping["main"]
            elif "start" in fun_mapping:
                if "__libc_start_main" in fun_mapping:
                    instrs = list(idautils.FuncItems(fun_mapping["start"][0]))
                    instrs.reverse()
                    for inst in instrs:
                        arg1 = idc.GetOperandValue(inst, 0)
                        if idc.GetMnem(inst) == "push":
                            start, stop = arg1, fun_mapping["start"][1]
                            break
                else:
                    start, stop = fun_mapping["start"]
        self.config.start, self.config.stop = start, stop

    def create_call_map(self, ftype):
        assert_ida_available()
        import idc
        import idautils
        seg_mapping = {idc.SegName(x): (idc.SegStart(x), idc.SegEnd(x)) for x in idautils.Segments()}
        imports = seg_mapping[".idata"] if ftype == PE else seg_mapping['.plt']
        start, stop = seg_mapping[".text"]
        current = start
        while current <= stop:
            inst = current
            if idc.GetMnem(inst) in ["call", "jmp"]:
                value = idc.GetOperandValue(inst, 0)
                name = idc.GetOpnd(inst, 0)
                if imports[0] <= value <= imports[1]:
                    entry = self.config.call_map.add()
                    entry.address = inst
                    entry.name = name
            current = idc.NextHead(current, stop)

    def from_file(self, filename):
        data = open(filename, "r").read()
        return self.from_string(data)

    def from_string(self, s):
        return json2pb(self.config, json.loads(s))

    def to_json(self):
        return pb2json(self.config)

    def to_str(self):
        return json.dumps(self.to_json(), indent=2)

    def to_file(self, filename):
        f = open(filename, "w")
        f.write(self.to_str())
        f.close()

    def __str__(self):
        return self.to_str()


if __name__ == "__main__":
    import idaapi
    import idc
    idaapi.autoWait()
    FT = open(idaapi.get_input_file_path()).read(2)
    import os
    print os.getcwd()
    conf = Configuration()
    conf.set_start_stop(FT)
    conf.create_call_map(FT)
    if len(idc.ARGV) < 2:
        print conf.to_str()
    else:
        conf.to_file(idc.ARGV[1])
        idc.Exit(0)
