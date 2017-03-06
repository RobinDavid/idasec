# coding=utf-8

from enum import Enum
from heapq import heappop, heappush

import idautils
import idaapi
import idc


def get_succs(ea):
    return [x for x in idautils.CodeRefsFrom(ea, True)]


class BasicBlockNotFound(Exception):
    pass

Status = Enum("DEAD", "ALIVE", "UNKNOWN")


class MyBasicBlock:
    def __init__(self, basicb):
        self._bb = basicb
        self.instrs = []
        self.instrs_status = {}
        self._preds = []
        self._succs = []
        self.startEA = self._bb.startEA
        self.endEA = self._bb.endEA
        self.id = self._bb.id
        self._fill_instrs()
        self.status = Status.UNKNOWN

    def concat(self, bb):
        print "concat %d :: %d" % (self.id, bb.id)
        print "  before instr:%d::%d status:%d::%d" % \
              (len(self.instrs), len(bb.instrs), len(self.instrs_status), len(bb.instrs_status))
        self.instrs.extend(bb.instrs)
        self.instrs_status.update(bb.instrs_status)
        print "  before instr:%d::%d status:%d::%d" % \
              (len(self.instrs), len(bb.instrs), len(self.instrs_status), len(bb.instrs_status))
        self._succs = list(bb.succs())
        self.endEA = bb.endEA
        for succ in bb.succs():  # Relocate
            succ.remove_pred(bb)
            succ.add_pred(self)
        if self.status != bb.status:
            print "Concat basic blocs with two different states"

    def reset_links(self):
        self._preds = []
        self._succs = []
        self._succs = []

    def add_pred(self, bb):
        self._preds.append(bb)

    def add_succ(self, bb):
        self._succs.append(bb)

    def remove_pred(self, bb):
        self._preds.remove(bb)

    def remove_succ(self, bb):
        self._succs.remove(bb)

    def old_succs(self):
        return self._bb.succs()

    def succs(self):
        for s in self._succs:
            yield s

    def nb_succs(self):
        return len(self._succs)

    def preds(self):
        for p in self._preds:
            yield p

    def nb_preds(self):
        return len(self._preds)

    def __iter__(self):
        return iter(self.instrs)

    def iter_alive(self):
        return iter([x for x in self.instrs if self.instrs_status[x] == Status.ALIVE])

    def _fill_instrs(self):
        cur_addr = self.startEA
        while cur_addr != idc.BADADDR:
            self.instrs.append(cur_addr)
            cur_addr = idc.NextHead(cur_addr, self.endEA)

    def size(self):
        return len(self.instrs)

    def last(self):
        return self.instrs[-1]

    def is_alive(self):
        return self.status == Status.ALIVE

    def is_dead(self):
        return self.status == Status.DEAD

    def is_unknown(self):
        return self.status == Status.UNKNOWN

    def is_full_spurious(self):
        return sum([self.instrs_status[x] != Status.DEAD for x in self.instrs]) == 0

    def set_instr_status(self, i, status):
        self.instrs_status[i] = status

    def dump(self):
        return '\n'.join([idc.GetDisasm(x) for x in self.instrs])

    def dump_alive(self):
        return '\n'.join([idc.GetDisasm(x) for x in self.instrs if self.instrs_status[x] == Status.ALIVE])


class MyFlowGraph(dict):
    def __init__(self, fun_addr):
        super(MyFlowGraph, self).__init__()
        self.fun = idaapi.get_func(fun_addr)
        self.startEA = self.fun.startEA
        self.endEA = self.fun.endEA
        for bb in idaapi.FlowChart(self.fun):
            self.__setitem__(bb.id, MyBasicBlock(bb))
        self._compute_links()
        self.edge_map = self.make_graph()
        self.shortest_path_map = self.dijkstra(self.edge_map)
        self.size = sum([x.size() for x in self.values()])
        self.viewer = MyFlowGraphViewer(self, "Extract(%s)" % idc.GetFunctionName(self.startEA))

    def reset(self):
        self._compute_links()

    def _compute_links(self):
        for bb in self.values():
            bb.reset_links()
        for bb in self.values():
            succs = [x.id for x in bb.old_succs()]
            for idx in succs:
                bb.add_succ(self.__getitem__(idx))
                succ_bb = self.__getitem__(idx)
                succ_bb.add_pred(bb)

    def make_graph(self):
        graph = {k: [] for k in self.keys()}
        for bb in self.values():
            size = bb.size()
            for succ in bb.succs():
                graph[bb.id].append((size, succ.id))
        return graph

    @staticmethod
    def dijkstra(graph):
        seen = set()            # élément traités
        d = {0: 0}           # distance map
        p = {}               # path map
        worklist = [(0, 0)]  # worklist d'éléments à traiter (distance, id)

        while worklist:  # tant qu'il reste des éléments dans la worklist à traiter

            dx, x_id = heappop(worklist)  # distance, and id
            if x_id in seen:                 # si l'élément est déjà traité on continue
                continue

            seen.add(x_id)                  # l'ajoute aux éléments traités

            for w, y in graph[x_id]:     # itère successeurs du noeud traité
                if y in seen:               # si le succ à déjà été traité continue
                    continue
                dy = dx + w                      # pondération du succ
                if y not in d or d[y] > dy:      # si succ n'est pas encore referencé ou new distance < alors update
                    d[y] = dy                    # met à jour la distance pour succ dans la distance map
                    heappush(worklist, (dy, y))  # met le succ dans la worklist (avec sa pondération)
                    p[y] = x_id                  # met à jour le prédecesseur le plus court pour succ
        # TODO: Do something with orphan BB
        return p

    def bb_id_path_to(self, x):
        path = [x]
        tmp = x
        if tmp not in self.shortest_path_map:  # In case of orphan BB
            return path
        while tmp != 0:
            tmp = self.shortest_path_map[tmp]
            path.insert(0, tmp)
        return path

    def get_basic_block(self, addr):
        if self.endEA < addr < self.startEA:
            raise BasicBlockNotFound()
        bb_addrs = {v.startEA: k for k, v in self.items() if v.startEA < addr}
        b_id = bb_addrs[max(bb_addrs.keys())]
        if addr in self.__getitem__(b_id).instrs:
            return b_id
        else:
            for b_id, bb in self.items():
                if addr in bb.instrs:
                    return b_id
        raise BasicBlockNotFound()

    def bb_path_to(self, addr):
        bb_id = self.get_basic_block(addr)
        return [x for x in self.__getitem__(bb_id) if x <= addr]

    def full_path_to(self, addr):
        bb_id = self.get_basic_block(addr)
        path = []
        bb_path = self.bb_id_path_to(bb_id)
        for bb_id in bb_path[:-1]:
            path += self.__getitem__(bb_id).instrs
        path += self.bb_path_to(addr)
        return path

    def safe_path_to(self, addr):
        path = self.full_path_to(addr)
        i = -1
        for ea, k in zip(path, range(len(path))):
            nb_preds = len([x for x in idautils.CodeRefsTo(ea, True)])
            if nb_preds > 1:
                i = k
            elif idc.GetDisasm(ea).startswith("call"):
                i = k+1
        print i
        if i == -1:
            return path
        else:
            return path[i:]

    def remove_dead_bb(self):
        for idx, bb in self.items():
            if bb.status == Status.DEAD:
                for pred in bb.preds():
                    pred.remove_succ(bb)
                for succ in bb.succs():
                    succ.remove_pred(bb)
                self.pop(idx)

    def OnRefresh(self):
        self.viewer.OnRefresh()

    def OnGetText(self, node_id):
        self.viewer.OnGetText(node_id)

    def Show(self):
        self.viewer.Show()


class MyFlowGraphViewer(idaapi.GraphViewer):

    def __init__(self, flow_graph, title):
        idaapi.GraphViewer.__init__(self, title)
        self.flow_graph = flow_graph
        self.result = None
        self.names = {}

    def OnRefresh(self):
        print 'refresh'
        self.Clear()
        self.make_cfg()
        return True

    def make_cfg(self):
        addr_id = {}
        for idx, bb in self.flow_graph.items():
            addr_id[idx] = self.AddNode(bb.dump_alive())

        for idx, bb in self.flow_graph.items():
            for succ in bb.succs():
                try:
                    self.AddEdge(addr_id[idx], addr_id[succ.id])
                except KeyError as e:
                    print "Edge %d->%d (%d) not found" % (idx, succ.id, e.args[0])

    def OnGetText(self, node_id):
        b = self[node_id]
        return str(b).lower()

    def OnSelect(self, node_id):
        return True

    def OnClick(self, node_id):
        return True

    def OnCommand(self, cmd_id):
        if self.cmd_test == cmd_id:
            print 'TEST!'
            return
        print "command:", cmd_id

    def Show(self):
        if not idaapi.GraphViewer.Show(self):
            return False
        self.cmd_test = self.AddCommand("Test", "F2")
        if self.cmd_test == 0:
            print "Failed to add popup menu item!"
        return True
