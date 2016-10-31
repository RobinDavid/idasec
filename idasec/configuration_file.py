"""
Author: Robin David (robin.david@cea.fr)

Binsec is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version http://www.gnu.org/licenses/.
"""
from idc import *
from idautils import *
from idaapi import *

import json

from protobuf_json import json2pb, pb2json
from proto.config_pb2 import configuration

PE = "\x4d\x5a"
ELF = "\x7fE"

def compute_fun_mapping():
    return {GetFunctionName(x): (get_func(x).startEA, get_func(x).endEA-1) for x in Functions()}

class Configuration:
    def __init__(self):
        self.seg_mapping = {SegName(x): (SegStart(x), SegEnd(x)) for x in Segments()}
        self.fun_mapping = compute_fun_mapping()
        self.eip = BeginEA()
        self.config = configuration()

    def set_start_stop(self, ftype):
        stop = 0
        if ftype == PE:
            start, stop = self.fun_mapping["start"]
        else:
            if not isCode(GetFlags(self.eip)):
                if MakeCode(self.eip) == 0:
                    print "Fail to decode instr !"
                idaapi.autoWait()
            if GetFunctionName(self.eip) == "":
                if MakeFunction(self.eip) == 0:
                    print "Fail to create function !"
                idaapi.autoWait()
                self.fun_mapping = compute_fun_mapping()

            if self.fun_mapping.has_key("main"):
                start, stop = self.fun_mapping["main"]
            elif self.fun_mapping.has_key("start"):
                if self.fun_mapping.has_key("__libc_start_main"):
                    instrs = list(FuncItems(self.fun_mapping["start"][0]))
                    instrs.reverse()
                    for inst in instrs:
                        arg1 = GetOperandValue(inst, 0)
                        fname = GetFunctionName(arg1)
                        if GetMnem(inst) == "push":
                            start, stop = arg1, self.fun_mapping["start"][1]
                            break
                else:
                    start, stop = self.fun_mapping["start"]
            else:
                start, stop = self.eip, 0
        self.config.start, self.config.stop = start, stop

    def create_call_map(self, ftype):
        imports = self.seg_mapping[".idata"] if ftype == PE else self.seg_mapping['.plt']
        start, stop = self.seg_mapping[".text"]
        current = start
        while current <= stop:
        #for fun in Functions():
        #    for inst in list(FuncItems(fun)):
            inst = current
            if GetMnem(inst) in ["call", "jmp"]:
                is_dynamic = GetOpType(inst, 0) in [o_mem, o_reg]
                value = GetOperandValue(inst, 0)
                name = GetOpnd(inst, 0)
                if value >= imports[0] and value <= imports[1]:
                    entry = self.config.call_map.add()
                    entry.address = inst
                    entry.name = name
            current = NextHead(current, stop)

    def from_file(self,filename):
        data = open(filename, "r").read()
        json2pb(self.config, data)

    def from_string(self, s):
        json2pb(self.config, s)

    def to_json(self):
        return pb2json(self.config)

    def to_str(self):
        return json.dumps(self.to_json(), indent=2)

    def to_file(self, filename):
        f = open(filename, "w")
        f.write(self.to_str())
        f.close()


if __name__ == "__main__":
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
