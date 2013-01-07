'''c v
Created on Nov 21, 2012

@author: deresz@gmail.com
@version: 0.1
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
import sys, re
import os

def Caller(ret):
    # later on we could think about analyzing area if we want the calls from DLLs
    offset = GetFuncOffset(ret)    
    if offset == "" or offset == None:
        offset = "0x%x" % ret
    return offset
    
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
                    caller_name = Caller(caller)
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

class FunCapHook(DBG_Hooks):
    '''
    Main class to inherit from DBG_Hooks
    '''  

    # some static constants
    STRING_EXPLORATION_MIN_LENGTH = 2
    STRING_EXPLORATION_BUF_SIZE = 128
    FUNC_COLOR = 0xF7CBEA
    ITEM_COLOR = 0x70E01B
    BB_COLOR = 0xF3FA39
  
    def __init__(self, outfile=None, delete_breakpoints = False, hexdump = False, comments = True, resume = False, depth = 0, \
                 nofunc_comments = True, func_colors = True, nofunc_colors = True, output_console = True):
        '''        
        @param outfile: log file where the output dump will be written (None = no logging)
        @param delete_breakpoints: do we delete a breakpoint after first pass ?
        @param hexdump: do we include hexdump in dump and in IDA comments ?
        @param comments: do we add IDA comments on top of each function ?
        @param resume: resume program after hitting a breakpoint ?
        @param depth: current stack depth capture for non-function hits"
        @param nofunc_comments: do we add IDA comments on breakpoints that are not on function start ?
        @param func_colors: do we fill all the function blocks with colors when the breakpoint hits?
        @param nofunc_colors: do we mark breakpoints hits which are not on function start ? 
        '''
        self.outfile = outfile
        self.delete_breakpoints = delete_breakpoints
        self.hexdump = hexdump
        self.comments = comments
        self.resume = resume
        self.depth = depth
        self.nofunc_comments = nofunc_comments
        self.func_colors = func_colors
        self.nofunc_colors = nofunc_colors
        self.output_console = output_console
        
        # FIXME: rneed to find better way do determine architecture ...
        (self.arch, self.bits) = self.getArch()
        
        self.calls = {}
        self.commented = {}
        DBG_Hooks.__init__(self)
        
        self.out = None

    #This is public interface
    #Switches are to be set manually - too lazy to implement setters and getters
    #I started to implement GUI as well but it did not work as expected so I g

    def on(self):
        if self.outfile:
            self.out = open(outfile, 'w')
        self.hook()
        print "FunCap is ON"
        
    def off(self):
        if self.out != None:
            self.out.close()
        self.unhook()
        print "FunCap is OFF"
        
    def addAllBreakpoints(self):
        '''
        Put breakpoints on all functions
        '''
        for f in list(Functions()):
            AddBpt(f)

    def delAllBreakpoints(self):
        '''
        Remove all function breakpoints
        '''
        for f in list(Functions()):
            DelBpt(f)
            
    def graph(self, exact_offsets = True):
        '''
        Draw the graph
        
        @param exact_offsets: if enabled each function call with offset(e.g. function+0x12) will be treated as graph node
            if disabled, only function name will be presented as node (more regular graph but less precise information)
        '''
        CallGraph("FunCap: function calls", self.calls, exact_offsets).Show()

    #End of public interface    

    def getArch(self):
        (arch, bits) = (None, None) 
        # currently only Intel architectures
        for x in idaapi.dbg_get_registers():
            name = x[0]
            if name == 'RAX':
                arch = 'amd64'
                bits = 64
                break
            elif name == 'EAX':
                arch = 'x86'
                bits = 32
                break
            elif name == 'R0':
                arch = 'arm'
                bits = 32
                break
        if not arch:
            raise "Architecture currently not supported"
        return (arch, bits)
  
    def getNumArgsStack(self, addr):        
        argFrameSize = GetStrucSize(GetFrame(addr)) - GetFrameSize(addr) + GetFrameArgsSize(addr)
        return argFrameSize / (self.bits/8)
  
    def getContext(self, general_only=True, ea=None, depth=None):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack
        
        @param general_only: only general registers (names start from E or R) - only Intel arch currently
        @param ea: if not None, stack will be examined for arguments
        @depth: stack depth - if none then number of arguments is determined automatically
        '''
        # currently only Intel architectures
        l = []        
        if self.arch == 'x86':
            for x in idaapi.dbg_get_registers():
                name = x[0]
                if not general_only or (re.match("E", name) and name != 'ES'):
                    value = idc.GetRegValue(name)
                    l.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
            if ea != None:
                stack = idc.GetRegValue('ESP')
                if depth == None: depth = self.getNumArgsStack(ea)+1
                for arg in range(1, depth):
                # FIXME - try-catch for non readable stack
                    value = DbgDword(stack+arg*4)
                    l.append({'name': "+%02x" % (arg*4), 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
        elif self.arch == 'amd64':
            for x in idaapi.dbg_get_registers():
                name = x[0]
                if not general_only or (re.match("R", name) and name != 'RS'):
                    value = idc.GetRegValue(name)
                    l.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
            if ea != None:
                stack = idc.GetRegValue('RSP')
                if depth == None: depth = self.getNumArgsStack(ea)+1
                for arg in range(1, depth):
                    value = DbgQword(stack+arg*8)
                    l.append({'name': "+%02x" % (arg*8), 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
        elif self.arch == 'arm':
            for x in idaapi.dbg_get_registers():
                name = x[0]
                value = idc.GetRegValue(name)
                l.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
                # IDA doesn't seem to show the stack argument frame size so we don't show stack-passed arguments here
                # Still, we have first four arguments in registers R0-R4
        else:
            raise "Unknown arch"
    
        return l 
    
    def dbg_bpt(self, tid, ea):
        if ea not in Functions():
            header = "Address: 0x%x" % ea
            # no argument dumping if not function
            # TODO: we can maybe dump local variables instead in the future ?
            context = self.getContext(ea=ea, depth=self.depth)
            if self.nofunc_colors:
                SetColor(ea, CIC_ITEM, self.ITEM_COLOR)
        else:
            header = "Function: %s (0x%x) " % (GetFunctionName(ea),ea) + "called by " + self.getCaller()
            context = self.getContext(ea=ea)
            # this is maybe not needed as we can colorize via trace function in IDA
            SetColor(ea, CIC_FUNC, self.FUNC_COLOR)
            if not self.calls.has_key(ea):
                self.calls[ea] = {}
            self.calls[ea][self.return_address()] = True
        lines = self.format_reg_output(context)
        if self.delete_breakpoints:
            DelBpt(ea)
        if self.comments and not self.commented.has_key(ea):
            self.add_comments(ea, lines)
            self.commented[ea] = True
        if self.output_console:
            print header
            self.dump_regs(lines)        
            print
        if self.outfile:
            self.out.write(header + "\n")
            self.dump_regs(lines, self.out)
            self.out.write("\n")
            self.out.flush()
        # disabled now for testing but will be enabled finally
        if self.resume: ResumeProcess()
        return 0
        
    def return_address(self):
        if self.arch == 'x86':
        # FIXME need to account for when stack is not callable
            return DbgDword(GetRegValue('ESP'))
        elif self.arch == 'amd64':
            return DbgQword(GetRegValue('RSP'))
        elif self.arch == 'arm':
            return GetRegValue('LR')
        else:
            raise 'Unknown arch'
        
    def getCaller(self):
        ret = self.return_address()
        return Caller(ret) + " (0x%x)" % ret
    
    def add_comments(self, ea, lines):
        idx = 0
        for line in lines:
            # workaround with Eval() - ExtLinA() doesn't work well in idapython
            line_sanitized = line.replace('"', '\\"')
            ret = idc.Eval('ExtLinA(%d, %d, "%s");' % (ea, idx, line_sanitized))
            if ret:
                print "idc.Eval() returned an error: %s" % ret
            idx += 1
    
    def format_reg_output(self, regs):
        lines = []
        if self.bits == 32:
            for reg in regs:
                lines.append("%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        else:
            for reg in regs:
                lines.append("%3s: 0x%016x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        return lines
    
    def dump_regs(self, lines, file=None):
        for line in lines:
            if file != None:
                file.write(line + "\n")
            else:
                print line

    # the following few functions are adopted from PaiMei by Pedram Amini
    def get_ascii_string (self, data):
        '''
        Retrieve the ASCII string, if any, from data. Ensure that the string is valid by checking against the minimum
        length requirement defined in self.STRING_EXPLORATION_MIN_LENGTH.

        @type  data: Raw
        @param data: Data to explore for printable ascii string

        @rtype:  String
        @return: False on failure, ascii string on discovered string.
        '''

        discovered = ""

        for char in data:
            # if we've hit a non printable char, break
            if ord(char) < 32 or ord(char) > 126:
                break

            discovered += char

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered  
 
    def get_printable_string (self, data, print_dots=True):
        '''
        description

        @type  data:       Raw
        @param data:       Data to explore for printable ascii string
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: False on failure, discovered printable chars in string otherwise.
        '''

        discovered = ""

        for char in data:
            if ord(char) >= 32 and ord(char) <= 126:
                discovered += char
            elif print_dots:
                discovered += "."

        return discovered
 
    def get_unicode_string (self, data):
        '''
        description

        @type  data: Raw
        @param data: Data to explore for printable unicode string

        @rtype:  String
        @return: False on failure, ascii-converted unicode string on discovered string.
        '''

        discovered  = ""
        every_other = True

        for char in data:
            if every_other:
                # if we've hit a non printable char, break
                if ord(char) < 32 or ord(char) > 126:
                    break

                discovered += char

            every_other = not every_other

        if len(discovered) < self.STRING_EXPLORATION_MIN_LENGTH:
            return False

        return discovered 
 
    def hex_dump (self, data, addr=0, prefix=""):
        '''
        Utility function that converts data into hex dump format.

        @type  data:   Raw Bytes
        @param data:   Raw bytes to view in hex dump
        @type  addr:   DWORD
        @param addr:   (Optional, def=0) Address to start hex offset display from
        @type  prefix: String (Optional, def="")
        @param prefix: String to prefix each line of hex dump with.

        @rtype:  String
        @return: Hex dump of data.
        '''

        dump  = prefix
        slice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%s%04x: " % (prefix, addr)
                slice = ""

            dump  += "%02x " % ord(byte)
            slice += byte
            addr  += 1

        remainder = addr % 16

        if remainder != 0:
            dump += "   " * (16 - remainder) + " "

        for char in slice:
            if ord(char) >= 32 and ord(char) <= 126:
                dump += char
            else:
                dump += "."

        return dump + "\n"
 
    def smart_dereference (self, address, print_dots=True, hex_dump=False):
        '''
        "Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
        or Unicode string. In the absense of a string the printable characters are returned with non-printables
        represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
        the name of the module it lies in (global data).

        @type  address:    DWORD
        @param address:    Address to smart dereference
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable
        @type  hex_dump:   Bool
        @param hex_dump:   (Optional, def=False) Return a hex dump in the absense of string detection

        @rtype:  String
        @return: String of data discovered behind dereference.
        '''

        explored = GetManyBytes(address, self.STRING_EXPLORATION_BUF_SIZE, use_dbg=True)
        if not explored:
            return 'N/A'
        explored_string = self.get_ascii_string(explored)

        if not explored_string:
            explored_string = self.get_unicode_string(explored)

        if not explored_string and hex_dump:
            explored_string = self.hex_dump(explored)

        if not explored_string:
            explored_string = self.get_printable_string(explored, print_dots)

        return explored_string
    
# main()
outfile = os.path.expanduser('~') + "/funcap.txt"
d = FunCapHook(outfile=outfile)
d.on()