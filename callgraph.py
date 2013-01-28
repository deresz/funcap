'''
Created on Jan 22, 2013

@author: deresz@gmail.com
@version: 0.3

A module to draw real function call graphs based on stack capture. A part of FunCap.

'''

# This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
# Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

from idc import *
from idaapi import *
from idautils import *
from funcap import *

class CallGraph(GraphViewer):
    def __init__(self, title, calls, exact_offsets):
        GraphViewer.__init__(self, title, calls)
        self.calls = calls
        self.nodes = {}
        self.exact_offsets = exact_offsets

    def OnRefresh(self):
        self.Clear()
        node_callers = {}
        for hit in self.calls.keys():
            name = GetFunctionName(hit)
            #print "adding primary node %x" % hit 
            self.nodes[hit] = self.AddNode((hit, name))
            if not node_callers.has_key(hit):
                node_callers[hit] = []
            for caller in self.calls[hit].keys():
                if self.exact_offsets == True:
                    caller_name = FormatOffset(caller)
                    graph_caller = caller
                else:
                    caller_name = GetFunctionName(caller)
                    if not caller_name:
                        caller_name = "0x%x" % caller
                        graph_caller = caller
                    else:
                        graph_caller = LocByName(caller_name)
                if not node_callers.has_key(graph_caller):
                    #print "adding node %x" % caller
                    self.nodes[graph_caller] = self.AddNode((graph_caller, caller_name))
                    node_callers[graph_caller] = []
                if not graph_caller in node_callers[hit]:
                    #print "adding edge for %x --> %x" % (caller, hit)
                    self.AddEdge(self.nodes[graph_caller], self.nodes[hit])
        return True

    def OnGetText(self, node_id):
        ea, label = self[node_id]
        return label

    def OnDblClick(self, node_id):
        ea, label = self[node_id]
        Jump(ea)
        return True
    
    def OnHint(self, node_id):
        ea, label = self[node_id]
        disasm = GetDisasm(ea-1)
        return "0x%x %s" % (ea, disasm)


