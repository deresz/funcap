'''
Created on Nov 21, 2012

@author: deresz@gmail.com
@contributors: Bartol0 @ github
@version: 0.91

FunCap. A script to capture function calls during a debug session in IDA.
It is created to help quickly importing some runtime data into static IDA database to boost static analysis.
Was meant to be multi-modular but seems IDA does not like scripts broken in several files/modules.
So we got one fat script file atm.

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

## BUGS:
#  - need to cancel "Analyze Area" if it takes too long - code analysis problem in IDA ?
#
## TODO LIST:
# - better call and ret association: build a call tree for each thread instead of current stack pointer-based hashing (this turns out not reliable).
# - function call capture using tracing (thinking here about PIN as only this one is fast enough).
#   We will probably have to calculate the destination jump address instead of using single stepping - it will be much more stable
# - instead of simple arg frame size calculation (get_num_args_stack()) + argument primitive type guessing (string, int),
#   we need to read in function prototypes guessed by IDA (or even HexRays decompiler plugin...) and match arguments to them
#   maybe it could be possible by getting some info from underlying debugger symbols via WinDbg/GDB, IDA pro static arg list analysis
# - some database interface for collected data + UI plugin in IDA - so that right click on a function call in IDA will show
#   the table with links to different captures for that particular call. This would be really cool.
# - amd64 stack-based arguments are not always well captured

# IDA imports

import sys
import pickle
from idaapi import *
from idautils import *
from idc import *

# utility functions

def format_name(ea):
    name = GetFunctionName(ea)
    if name == "" or name == None:
        name = "0x%x" % ea
    return name

def format_offset(ea):
    offset = GetFuncOffset(ea)
    if offset == "" or offset == None:
        offset = "0x%x" % ea
    return offset

def get_arch():
    '''
    Get the target architecture.
    Supported archs: x86 32-bit, x86 64-bit, ARM 32-bit
    '''
    (arch, bits) = (None, None)
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

    return (arch, bits)

class FunCapHook(DBG_Hooks):
    '''
    Main class to implementing DBG_Hooks
    '''

    ## CONSTANTS
    # minimum length requirement to be ascii
    STRING_EXPLORATION_MIN_LENGTH = 4
    # length of discovered strings outputted to file and console
    STRING_LENGTH = 164
    # length of the same strings inserted in IDA code
    STRING_LENGTH_IN_COMMENTS = 82
    # length of single-line hexdumps in hexdump mode outputted to file and console
    HEXMODE_LENGTH = 164
    # length of the same hexdumps inserted in IDA code
    HEXMODE_LENGTH_IN_COMMENTS = 82
    # visited functions will be tagged as follows
    FUNC_COLOR = 0xF7CBEA
    #FUNC_COLOR = 0xF7A0A0
    # visited items (except call instructions) will be tagged as follows
    ITEM_COLOR = 0x70E01B
    # calls will be tagged as follows
    CALL_COLOR = 0x99CCCC
    #CALL_COLOR = 0xB1A0F7
    # maximum comment lines inserted after/before call instructions
    CMT_MAX = 5

    def __init__(self, **kwargs):
        '''

        @param outfile: log file where the output dump will be written (default: %USERPROFILE%\funcap.txt)
        @param delete_breakpoints: delete a breakpoint after first pass ? (default: yes)
        @param hexdump: include hexdump instead of ascii in outfile and IDA comments ? (default: no)
        @param comments: add IDA comments ? (default: yes)
        @param resume: resume program after hitting a breakpoint ? (default: yes)
        @param depth: current stack depth capture for non-function hits (default: 0)
        @param colors: mark the passage with colors ? (default: yes)
        @param output_console: print everything to the console ? (default: yes)
        @param overwrite_existing: overwrite existing capture comment in IDA when the same function is called ? (default: no)
        @param recursive: when breaking on a call - are we recursively hooking all call instructions in the new function ? (default: no)
        @param code_discovery: enable discovery of a dynamically created code - for obfuscators and stuff like that (default: no)
        @param code_discovery_nojmp: don't hook jumps in code_discovery mode (default: no)
        @param code_discovery_stop: stop if new code section is discovered (default: no)
        @param no_dll: disable API calls capturing (default: no)
        @param strings_file: file containing strings dump on captured function arguments (default: %USERPROFILE%\funcap_strings.txt)
        @param multiple_dereferences: dereference each pointer resursively ? (default: 3 levels, 0 - off)

        '''
        self.outfile = kwargs.get('outfile', os.path.expanduser('~') + "/funcap.txt")
        self.delete_breakpoints = kwargs.get('delete_breakpoints', True)
        self.hexdump = kwargs.get('hexdump', False)
        self.comments = kwargs.get('comments', True)
        self.resume = kwargs.get('resume', True)
        self.depth = kwargs.get('depth', 0)
        self.colors = kwargs.get('colors', True)
        self.output_console = kwargs.get('output_console', True)
        self.overwrite_existing = kwargs.get('overwrite_existing', False)
        self.recursive = kwargs.get('recursive', False)
        self.code_discovery = kwargs.get('code_discovery', False) # for obfuscators
        self.code_discovery_nojmp = kwargs.get('code_discovery_nojmp', False)
        self.code_discovery_stop = kwargs.get('code_discovery_stop', False)
        self.no_dll = kwargs.get('no_dll', False)
        self.strings_file = kwargs.get('strings', os.path.expanduser('~') + "/funcap_strings.txt")
        self.multiple_dereferences = kwargs.get('multiple_dereferences', 3)

        self.visited = [] # functions visited already
        self.saved_contexts = {} # saved stack contexts - to re-dereference arguments when the function exits
        self.function_calls = {} # recorded function calls - used for several purposes
        self.stop_points = [] # brekpoints where FunCap will pause the process to let user start the analysis
        self.calls_graph = {} # graph nodes prepared for call graphs
        self.hooked = [] # functions that were already hooked
        self.stub_steps = 0
        self.stub_name = None
        self.current_caller = None # for single step - before-call context
        self.delayed_caller = None # needed in case where single step lands on breakpoint (brekpoint fires first - which is bad...)
        DBG_Hooks.__init__(self)

        self.out = None
        self.strings_out = None

    ###
    # This a is public interface
    # Switches are to be set manually - too lazy to implement setters and getters
    # I started to implement GUI as well but it did not work as expected so it won't be implemented...
    ###

    def on(self):
        '''
        Turn the script on
        '''
        if self.outfile:
            self.out = open(self.outfile, 'w')
        if self.strings_file:
            self.strings_out = open(self.strings_file, 'w')
        self.hook()
        print "FunCap is ON"

    def off(self):
        '''
        Turn the script off
        '''
        if self.out != None:
            self.out.close()
        self.unhook()

        print "FunCap is OFF"

    def addFuncStart(self):
        '''
        Add breakpoints on all function starts
        '''
        for f in list(Functions()):
            AddBpt(f)

    def addFuncRet(self):
        '''
        Add breakpoints on all return from subroutine instructions
        '''
        for seg_ea in Segments():
        # For each of the defined elements
            for head in Heads(seg_ea, SegEnd(seg_ea)):

                # If it's an instruction
                if isCode(GetFlags(head)):

                    if self.is_ret(head):
                        AddBpt(head)

    def addCallee(self):
        '''
        Add breakpoints on both function starts and return instructions
        '''
        self.addFuncStart()
        self.addFuncRet()

    def hookFunc(self, jump = False, func = ""):
        '''
        Add breakpoints on call instructions within a function

        @param jump: if True, jump instructions will also be hooked in addition to calls - used in code discovery mode
        @param func: this should be a function name. If null, the function that UI cursor points to will be processed

        '''

        if func:
            ea = LocByName(func)
        else:
            ea = ScreenEA()
            func = GetFunctionName(ea)

        self.output("hooking function: %s()" % func)

        chunks = Chunks(ea)
        for (start_ea, end_ea) in chunks:
            if jump:
                self.add_call_and_jump_bp(start_ea, end_ea)
            else:
                self.add_call_bp(start_ea, end_ea)
        self.hooked.append(func)

    def hookSeg(self, seg = "", jump = False):
        '''
        Add breakpoints on call instructions within a given segment

        @param jump: if True, jump instructions will also be hooked in addition to calls - used in code discovery mode
        @param seg: this should be a segment name. If null, the segment that UI cursor points to will be processed
        '''

        if seg:
            ea = None
            for s in Segments():
                if seg == SegName(s):
                    ea = s
                    break

            if ea == None:
                self.output("WARNING: cannot hook segment %s" % seg)
                return
        else:
            ea = ScreenEA()
            seg = SegName(ea)
        self.output("hooking segment: %s" % seg)
        start_ea = SegStart(ea)
        end_ea = SegEnd(ea)
        if jump:
            self.add_call_and_jump_bp(start_ea, end_ea)
        else:
            self.add_call_bp(start_ea, end_ea)

    def addCJ(self, func = ""):
        '''
        Hook all call and jump instructions

        @param func: name of the function to hook

        '''
        self.hookFunc(jump = True, func = func)

    def delAll(self):
        '''
        Delete all breakpoints
        '''

        for bp in range(GetBptQty(), 0, -1):
            DelBpt(GetBptEA(bp))

    def graph(self, exact_offsets = False):
        '''
        Draw the graph

        @param exact_offsets: if enabled each function call with offset(e.g. function+0x12) will be treated as graph node
                              if disabled, only function name will be presented as node (more regular graph but less precise information)
        '''

        CallGraph("FunCap: function calls", self.calls_graph, exact_offsets).Show()

    def saveGraph(self, path = os.path.expanduser('~') + "/funcap.graph"):
        pickle.dump(d.calls_graph, open(path, "w"))

    def loadGraph(self, path = os.path.expanduser('~') + "/funcap.graph"):
        d.calls_graph = pickle.load(open(path, "r"))

    def addStop(self, ea):
        '''
        Add a stop point - the script will pause the process when this is reached

        @param ea: address of the new stop point to add
        '''

        self.stop_points.append(ea)
        AddBpt(ea)

    ###
    # END of public interface
    ###

    def add_call_bp(self, start_ea, end_ea):
        '''
        Add breakpoints on every subrountine call instruction within the given scope (start_ea, end_ea)

        @param start_ea:
        @param end_ea:
        '''

        for head in Heads(start_ea, end_ea):

            # If it's an instruction
            if isCode(GetFlags(head)):

                if self.is_call(head):
                    AddBpt(head)

    def add_call_and_jump_bp(self, start_ea, end_ea):
        '''
        Add breakpoints on every subrountine call instruction and jump instruction within the given scope (start_ea, end_ea)

        @param start_ea:
        @param end_ea:

        '''

        for head in Heads(start_ea, end_ea):

            # If it's an instruction
            if isCode(GetFlags(head)):

                if (self.is_call(head) or self.is_jump(head)):
                    AddBpt(head)


    def get_num_args_stack(self, addr):
        '''
        Get the size of arguments frame

        @param addr: address belonging to a function

        '''

        argFrameSize = GetStrucSize(GetFrame(addr)) - GetFrameSize(addr) + GetFrameArgsSize(addr)
        return argFrameSize / (self.bits/8)

    def get_caller(self):

        return self.prev_ins(self.return_address())

    def format_caller(self, ret):

        return format_offset(ret) + " (0x%x)" % ret

    def getRegValueFromCtx(self, name, context):
        '''
        Extract the value of a single register from the saved context

        @param name: name of the register to extract
        @param context: saved execution context
        '''

        for reg in context:
            if reg['name'] == name:
                return reg['value']

    def add_comments(self, ea, lines, every = False):
        '''
        Insert lines (posterior and anterior lines which are referred to as "comments" in this code) into IDA assembly listing

        @param ea: address where to insert the comments
        @param lines: array of strings to be inserted as multiple lines using ExtLinA()
        @param every: if set to True, the maximum number of lines per address (self.CMT_MAX) will not be respected

        '''

        idx = 0
        for line in lines:
            # workaround with Eval() - ExtLinA() doesn't work well in idapython
            line_sanitized = line.replace('"', '\\"')
            ret = idc.Eval('ExtLinA(%d, %d, "%s");' % (ea, idx, line_sanitized))
            if ret:
                self.output("idc.Eval() returned an error: %s" % ret)
            idx += 1
            if every == False and idx > self.CMT_MAX: break

    def format_normal(self, regs):
        '''
        Returns two lists of formatted values and derefs of registers, one for console/file dump, and another for IDA comments (tha latter is less complete)
        Used for everything besides calling and returning from function.

        @param regs: dictionary returned by get_context()
        '''

        full_ctx = []
        cmt_ctx = []

        if self.bits == 32:
            format_string = "%3s: 0x%08x"
            format_string_append =  " -> 0x%08x"
            getword = DbgDword
        else:
            format_string = "%3s: 0x%016x"
            format_string_append =  " -> 0x%016x"
            getword = DbgQword

        memval = None
        next_memval = None
        prev_memval = None
        valchain_full = ""
        valchain_cmt = ""

        for reg in regs:
            valchain_full = format_string % (reg['name'], reg['value'])
            valchain_cmt = format_string % (reg['name'], reg['value'])
            prev_memval = reg['value']
            memval=getword(reg['value'])
            next_memval = getword(memval)

            if (self.multiple_dereferences):
                maxdepth = self.multiple_dereferences
                while (next_memval): #memval is a proper pointer
                    if (maxdepth == 0):
                        break
                    maxdepth-=1
                    if (prev_memval == memval):#points at itself
                        break
                    valchain_full += format_string_append % memval
                    valchain_cmt += format_string_append % memval

                    prev_memval = memval
                    memval = next_memval
                    next_memval = getword(memval)

            function_name=GetFuncOffset(prev_memval)#no more dereferencing. is this a function ?
            if (function_name):
                valchain_full += " (%s)" % function_name
                valchain_cmt += " (%s)" % function_name
            else: #no, dump data
                if (self.hexdump):
                    valchain_full_left = (self.HEXMODE_LENGTH - len(valchain_full) - 1) / 4
                    valchain_cmt_left = (self.HEXMODE_LENGTH_IN_COMMENTS - len(valchain_cmt) - 1) / 4
                    format_string_dump = " (%s)"
                else:
                    valchain_full_left = self.STRING_LENGTH - len(valchain_full)
                    valchain_cmt_left = self.STRING_LENGTH_IN_COMMENTS - len(valchain_cmt)
                    format_string_dump = " (\"%s\")"

                if (valchain_full_left <4): valchain_full_left = 4 #allways dump at least 4 bytes
                if (valchain_cmt_left <4): valchain_cmt_left = 4 #allways dump at least 4 bytes

                valchain_full += format_string_dump % self.smart_format(self.dereference(prev_memval,2 * valchain_full_left), valchain_full_left)
                valchain_cmt += format_string_dump % self.smart_format_cmt(self.dereference(prev_memval,2 * valchain_cmt_left),valchain_cmt_left)

            full_ctx.append(valchain_full)
            cmt_ctx.append(valchain_cmt)

        return (full_ctx, cmt_ctx)

    def format_call(self, regs):
        '''
        Returns two lists of formatted values and derefs of registers, one for console/file dump, and another for IDA comments
        Used when calling a function.

        @param regs: dictionary returned by get_context()
        '''

        full_ctx = []
        cmt_ctx = []

        if self.bits == 32:
            format_string_full = "%3s: 0x%08x"
            format_string_cmt = "   %3s: 0x%08x"
            format_string_append =  " -> 0x%08x"
            getword = DbgDword
        else:
            format_string_full = "%3s: 0x%016x"
            format_string_cmt = "   %3s: 0x%016x"
            format_string_append =  " -> 0x%016x"
            getword = DbgQword

        memval = None
        next_memval = None
        prev_memval = None
        valchain_full = ""
        valchain_cmt = ""

        for reg in regs:
            valchain_full = format_string_full % (reg['name'], reg['value'])
            valchain_cmt = format_string_cmt % (reg['name'], reg['value'])
            prev_memval = reg['value']
            memval=getword(reg['value'])
            next_memval = getword(memval)

            if (self.multiple_dereferences):
                maxdepth = self.multiple_dereferences
                while (next_memval): #memval is a proper pointer
                    if (maxdepth == 0):
                        break
                    maxdepth-=1
                    if (prev_memval == memval):#points at itself
                        break
                    valchain_full += format_string_append % memval
                    valchain_cmt += format_string_append % memval

                    prev_memval = memval
                    memval = next_memval
                    next_memval = getword(memval)

            function_name=GetFuncOffset(prev_memval)#no more dereferencing. is this a function ?
            if (function_name):
                valchain_full += " (%s)" % function_name
                valchain_cmt += " (%s)" %  function_name
            else: #no, dump data
                if (self.hexdump):
                    valchain_full_left = (self.HEXMODE_LENGTH - len(valchain_full) - 1) / 4
                    valchain_cmt_left = (self.HEXMODE_LENGTH_IN_COMMENTS - len(valchain_cmt) - 1) / 4
                    format_string_dump = " (%s)"
                else:
                    valchain_full_left = self.STRING_LENGTH - len(valchain_full)
                    valchain_cmt_left = self.STRING_LENGTH_IN_COMMENTS - len(valchain_cmt)
                    format_string_dump = " (\"%s\")"

                if (valchain_full_left <4): valchain_full_left = 4 #allways dump at least 4 bytes
                if (valchain_cmt_left <4): valchain_cmt_left = 4 #allways dump at least 4 bytes

                valchain_full += format_string_dump % self.smart_format(self.dereference(prev_memval,2 * valchain_full_left), valchain_full_left)
                valchain_cmt += format_string_dump % self.smart_format_cmt(self.dereference(prev_memval,2 * valchain_cmt_left),valchain_cmt_left)

            full_ctx.append(valchain_full)
            if any(regex.match(reg['name']) for regex in self.CMT_CALL_CTX):
                cmt_ctx.append(valchain_cmt)

        return (full_ctx, cmt_ctx)

    def format_return(self, regs, saved_regs):
        '''
        Returns two lists of formatted values and derefs of registers, one for console/file dump, and another for IDA comments
        Used when returning from function.

        @param regs: dictionary returned by get_context()
        @param saved_regs: dictionary in the format returned by get_context()
        '''

        full_ctx = []
        cmt_ctx = []

        if self.bits == 32:
            format_string_append =  " -> 0x%08x"
            format_string_full = "%3s: 0x%08x"
            format_string_cmt = "   %3s: 0x%08x"
            format_string_full_s = "s_%3s: 0x%08x"
            format_string_cmt_s = "   s_%3s: 0x%08x"
            getword = DbgDword
        else:
            format_string_full = "%3s: 0x%016x"
            format_string_cmt = "   %3s: 0x%016x"
            format_string_full_s = "s_%3s: 0x%016x"
            format_string_cmt_s = "   s_%3s: 0x%016x"
            format_string_append =  " -> 0x%016x"
            getword = DbgQword

        memval = None
        next_memval = None
        prev_memval = None
        valchain_full = ""
        valchain_cmt = ""

        for reg in regs:
            valchain_full = format_string_full % (reg['name'], reg['value'])
            valchain_cmt = format_string_cmt % (reg['name'], reg['value'])
            prev_memval = reg['value']
            memval=getword(reg['value'])
            next_memval = getword(memval)

            if (self.multiple_dereferences):
                maxdepth = self.multiple_dereferences
                while (next_memval): #memval is a proper pointer
                    if (maxdepth == 0):
                        break
                    maxdepth-=1
                    if (prev_memval == memval):#points at itself
                        break
                    valchain_full += format_string_append % memval
                    valchain_cmt += format_string_append % memval

                    prev_memval = memval
                    memval = next_memval
                    next_memval = getword(memval)

            function_name=GetFuncOffset(prev_memval)#no more dereferencing. is this a function ?
            if (function_name):
                valchain_full += " (%s)" % function_name
                valchain_cmt += " (%s)" %  function_name
            else: #no, dump data
                if (self.hexdump):
                    valchain_full_left = (self.HEXMODE_LENGTH - len(valchain_full) - 1) / 4
                    valchain_cmt_left = (self.HEXMODE_LENGTH_IN_COMMENTS - len(valchain_cmt) - 1) / 4
                    format_string_dump = " (%s)"
                else:
                    valchain_full_left = self.STRING_LENGTH - len(valchain_full)
                    valchain_cmt_left = self.STRING_LENGTH_IN_COMMENTS - len(valchain_cmt)
                    format_string_dump = " (\"%s\")"

                if (valchain_full_left <4): valchain_full_left = 4 #allways dump at least 4 bytes
                if (valchain_cmt_left <4): valchain_cmt_left = 4 #allways dump at least 4 bytes

                valchain_full += format_string_dump % self.smart_format(self.dereference(prev_memval,2 * valchain_full_left), valchain_full_left)
                valchain_cmt += format_string_dump % self.smart_format_cmt(self.dereference(prev_memval,2 * valchain_cmt_left),valchain_cmt_left)

            full_ctx.append(valchain_full)
            if any(regex.match(reg['name']) for regex in self.CMT_RET_CTX):
                cmt_ctx.append(valchain_cmt)

        if saved_regs:
            for reg in saved_regs:
                if any(regex.match(reg['name']) for regex in self.CMT_RET_SAVED_CTX):
                    valchain_full =  format_string_full_s % (reg['name'], reg['value'])
                    valchain_cmt = format_string_cmt_s % (reg['name'], reg['value'])
                    prev_memval = reg['value']
                    memval=getword(reg['value'])
                    next_memval = getword(memval)

                    if (self.multiple_dereferences):
                        maxdepth = self.multiple_dereferences
                        while (next_memval): #memval is a proper pointer
                            if (maxdepth == 0):
                                break
                            if (prev_memval == memval):#points at itself
                                break
                            maxdepth-=1
                            valchain_full += format_string_append % memval
                            valchain_cmt += format_string_append % memval

                            prev_memval = memval
                            memval = next_memval
                            next_memval = getword(memval)

                    function_name=GetFuncOffset(prev_memval)#no more dereferencing. is this a function ?
                    if (function_name):
                        valchain_full += " (%s)" % function_name
                        valchain_cmt += " (%s)" %  function_name
                    else: #no, dump data
                        if (self.hexdump):
                            valchain_full_left = (self.HEXMODE_LENGTH - len(valchain_full) - 1) / 4
                            valchain_cmt_left = (self.HEXMODE_LENGTH_IN_COMMENTS - len(valchain_cmt) - 1) / 4
                            format_string_dump = " (%s)"
                        else:
                            valchain_full_left = self.STRING_LENGTH - len(valchain_full)
                            valchain_cmt_left = self.STRING_LENGTH_IN_COMMENTS - len(valchain_cmt)
                            format_string_dump = " (\"%s\")"

                        if (valchain_full_left <4): valchain_full_left = 4 #allways dump at least 4 bytes
                        if (valchain_cmt_left <4): valchain_cmt_left = 4 #allways dump at least 4 bytes

                        valchain_full += format_string_dump % self.smart_format(self.dereference(prev_memval,2 * valchain_full_left), valchain_full_left)
                        valchain_cmt += format_string_dump % self.smart_format_cmt(self.dereference(prev_memval,2 * valchain_cmt_left),valchain_cmt_left)

                    full_ctx.append(valchain_full)
                    cmt_ctx.append(valchain_cmt)

        return (full_ctx, cmt_ctx)

    def output(self, line):
        '''
        Standard "print" function used across the whole script

        @param line: line to print
        '''

        if self.outfile:
            self.out.write(line + "\n")
        if self.output_console:
            print line
        if self.outfile:
            self.out.flush()

    def output_lines(self, lines):
        '''
        This prints a list, line by line

        @param lines: lines to print
        '''

        for line in lines:
            if self.outfile:
                self.out.write(line + "\n")
            if self.output_console:
                print line
        if self.outfile:
            self.out.flush()

    # the following few functions are adopted from PaiMei by Pedram Amini
    # they are here to format and present data in a nice way

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

    def hex_dump(self, data):
        '''
        Utility function that converts data into one-line hex dump format.

        @type  data:   Raw Bytes
        @param data:   Raw bytes to view in hex dump

        @rtype:  String
        @return: Hex dump of data.
        '''

        dump = ""

        for byte in data:
            dump  += "%02x " % ord(byte)

        for byte in data:
            if ord(byte) >= 32 and ord(byte) <= 126:
                dump += byte
            else:
                dump += "."

        return dump


    def dereference(self, address, size):
        return GetManyBytes(address, size, use_dbg=True)

    def smart_format(self, raw_data, maxlen, print_dots=True):
        '''
        "Intelligently" discover data behind an address. The address is dereferenced and explored in search of an ASCII
        or Unicode string. In the absense of a string the printable characters are returned with non-printables
        represented as dots (.). The location of the discovered data is returned as well as either "heap", "stack" or
        the name of the module it lies in (global data).

        @param raw_data:    Binary data to format
        @type  print_dots: Bool
        @param print_dots: (Optional, def:True) Controls suppression of dot in place of non-printable

        @rtype:  String
        @return: String of data discovered behind dereference.
        '''

        if not raw_data:
            return 'N/A'

        try_unicode = raw_data[:maxlen * 2]
        try_ascii = raw_data[:maxlen]

        data = raw_data[:maxlen]

        data_string = self.get_ascii_string(try_ascii)

        if not data_string:
            data_string = self.get_unicode_string(try_unicode)

        if not data_string and self.hexdump:
            data_string = self.hex_dump(data)

        if not data_string:
            data_string = self.get_printable_string(data, print_dots)

        # shouldn't have been here but the idea of string dumping came out to me later on
        # TODO: re-implement. We could also take much longer strings
        if self.strings_file:
            self.strings_out.write(self.get_printable_string(raw_data, False) + "\n")
            self.strings_out.flush()

        return data_string

    def smart_format_cmt(self, raw_data, maxlen,  print_dots=True):
        '''
        Same as smart_format() but for IDA comments
        '''

        if not raw_data:
            return 'N/A'

        try_unicode = raw_data[:maxlen * 2]
        try_ascii = raw_data[:maxlen]

        data = raw_data[:maxlen]

        data_string = self.get_ascii_string(try_ascii)

        if not data_string:
            data_string = self.get_unicode_string(try_unicode)

        if not data_string and self.hexdump:
            data_string = self.hex_dump(data)

        if not data_string:
            data_string = self.get_printable_string(data, print_dots)

        return repr(data_string).strip("'")

    def next_ins(self, ea):
        '''
        Return next instruction to ea
        '''
        end = idaapi.cvar.inf.maxEA
        return idaapi.next_head(ea, end)

    def prev_ins(self, ea):
        '''
        Return previous instruction to ea
        '''
        start = idaapi.cvar.inf.minEA
        return idaapi.prev_head(ea, start)

    # handlers called from within debug hooks

    def handle_function_end(self, ea):
        '''
        Called when breakpoint hit on ret instruction
        '''

        function_name = GetFunctionName(ea)
        caller = self.format_caller(self.get_caller())
        if function_name:
            header = "At function end: %s (0x%x) " % (function_name,ea) + "to " + caller
            raw_context = self.get_context(ea=ea)
        else:
            header = "At function end - unknown function (0x%x) " % ea + "to " + caller
            raw_context = self.get_context(ea=ea, depth=0)
        if self.colors:
            SetColor(ea, CIC_ITEM, self.ITEM_COLOR)
        (context_full, context_comments) = self.format_normal(raw_context)
        if self.delete_breakpoints:
            DelBpt(ea)

        if self.comments and (self.overwrite_existing or ea not in self.visited):
            self.add_comments(ea, context_comments, every = True)

        self.visited.append(ea)
        self.output_lines([ header ] + context_full + [ "" ])

    def handle_return(self, ea):
        '''
        Called when breakpoint hit on next-to-call instruction
        '''

        # need to get context from within a called function
        function_call = self.function_calls[ea]
        ret_shift = function_call['ret_shift']
        raw_context = self.get_context()
        #raw_context = self.get_context(stack_offset = 0 - ret_shift, depth=function_call['num_args'] - ret_shift) # no stack here ?

        sp = self.get_sp()
        sp = sp - ret_shift
        if self.saved_contexts.has_key(sp):
            saved_context = self.saved_contexts[sp]['ctx']
            func_name = self.saved_contexts[sp]['func_name']
            del self.saved_contexts[sp]
        else:
            func_name = function_call['func_name']
            self.output("WARNING: saved context not found for stack pointer 0x%x, assuming function %s" % (sp, function_call['func_name']))
            saved_context = None

        header = "Returning from call to %s(), execution resumed at %s (0x%x)" % (func_name, format_offset(ea), ea)
        (context_full, context_comments) = self.format_return(raw_context, saved_context)

        if self.comments and (self.overwrite_existing or ea not in self.visited):
            self.add_comments(ea, context_comments)
        self.visited.append(ea)
        self.output_lines([ header ] + context_full + [ "" ])

    def handle_function_start(self, ea):
        '''
        Called when breakpoint hit on the beginning of a function
        '''

        name = GetFunctionName(ea)

        caller_ea = self.get_caller()
        caller_offset = self.format_caller(caller_ea)
        caller_name = format_name(caller_ea)

        header = "At function start: %s (0x%x) " % (name,ea) + "called by %s" % caller_offset

        raw_context= self.get_context(ea=ea)
        if self.colors:
            SetColor(ea, CIC_FUNC, self.FUNC_COLOR)

        # update data for graph
        if not self.calls_graph.has_key(ea):
            self.calls_graph[ea] = {}
            self.calls_graph[ea]['callers'] = []
        self.calls_graph[ea]['callers'].append({ 'name' : caller_name, 'ea' : caller_ea, 'offset' : caller_offset })
        self.calls_graph[ea]['name'] = name

        (context_full, context_comments) = self.format_normal(raw_context)

        if self.comments and (self.overwrite_existing or ea not in self.visited):
            self.add_comments(ea, context_comments, every = True)

        self.visited.append(ea)

        self.visited.append(ea)
        self.output_lines([ header ] + context_full + [ "" ])


    def handle_generic(self, ea):
        '''
        Called when breakpoint hit on anything else besides the above and below
        '''

        header = "Address: 0x%x" % ea
        # no argument dumping if not function
        raw_context = self.get_context(ea=ea, depth=self.depth)
        (context_full, context_comments) = self.format_normal(raw_context)
        if self.colors:
            SetColor(ea, CIC_ITEM, self.ITEM_COLOR)

        if self.comments and (self.overwrite_existing or ea not in self.visited):
            self.add_comments(ea, context_comments)

        self.visited.append(ea)
        self.output_lines([ header ] + context_full + [ "" ])

    def handle_call(self, ea):
        '''
        Called when breakpoint hit on a call instruction.
        '''
        if self.current_caller: # delayed_caller: needed if breakpoint hits after signle step request
            self.delayed_caller = { 'type': 'call', 'addr' : ea, 'ctx' : self.get_context(ea=ea, depth=0) }
        else:
            self.current_caller = { 'type': 'call', 'addr' : ea, 'ctx' : self.get_context(ea=ea, depth=0) }

        #print "handle_call: 0x%x" % ea
        if self.colors:
            SetColor(ea, CIC_ITEM, self.CALL_COLOR)

    def handle_jump(self, ea):
        '''
        Called when breakpoint hits on a jump instruction when code_discovery mode enabled
        '''

        if self.current_caller:
            self.delayed_caller = { 'type': 'jump', 'addr' : ea }
        else:
            self.current_caller = { 'type': 'jump', 'addr' : ea } # don't need ctx here

    def handle_after_jump(self, ea):
        '''
        Called when single stepping into a jmp instruction
        '''

        if self.comments:
            MakeComm(self.current_caller['addr'], "0x%x" % ea)
        seg_name = SegName(ea)
        if self.code_discovery and (not isCode(GetFlags(ea)) or not self.isCode) and not self.is_system_lib(seg_name):
            self.output("New code segment discovered: %s (0x%x => 0x%x)" % (seg_name, self.current_caller['addr'], ea))
            start_ea = SegStart(ea)
            end_ea = SegEnd(ea)
            refresh_debugger_memory()
            if not MakeCode(ea):
                ins = DecodeInstruction(ea)
                if ins.size:
                    MakeUnknown(ea, ins.size, DOUNK_EXPAND)
                    if not MakeCode(ea):
                        self.output("handle_after_jump(): unable to make code at 0x%x" % ea)

            AnalyzeArea(start_ea, end_ea)
            self.add_call_and_jump_bp(start_ea, end_ea)

        self.current_caller = self.delayed_caller
        self.delayed_caller = None

    def discover_function(self, ea):
        '''
        Try to get a name of a function. If function does not exists at ea, tries to create/discover it.
        '''

        name = GetFunctionName(ea)
        symbol_name = Name(ea)

        if symbol_name and name and symbol_name != name and not re.match("loc_", symbol_name):
            self.output("WARNING: IDA has probably wrongly analyzed the following function: %s and " \
                        "it is overlapping with another symbol: %s. Funcap will undefine it. " % (name, symbol_name))
            DelFunction(LocByName(name))
            name = None

        if name: return name

        need_hooking = False
        #refresh_debugger_memory() # SegName didn't seem to work sometimes
        seg_name = SegName(ea)
        if self.code_discovery and not self.is_system_lib(seg_name) and (not isCode(GetFlags(ea)) or not self.isCode):
            #print "need_hooking :: ea: %x, seg_name: %s" % (ea, seg_name)
            need_hooking = True

        refresh_debugger_memory() # need to call this here (thx IlfakG)
        # this should normally work for dynamic libraries

        r = MakeFunction(ea)
        if not r:
            # this might be dynamically created code (such as obfuscation etc.)
            if MakeCode(ea):
                # fine, we try again
                r = MakeFunction(ea)
                if not r:
                    self.output("WARNING: unable to create function at 0x%x" % ea)
            else:
                # undefining also helps. Last try (thx IgorS)
                ins = DecodeInstruction(ea)
                if ins.size:
                    MakeUnknown(ea, ins.size, DOUNK_EXPAND)
                    if MakeCode(ea):
                        # weird but worked on my example ... calling the same twice
                        refresh_debugger_memory()
                        r = MakeFunction(ea)
                        refresh_debugger_memory()
                        r = MakeFunction(ea)
                        if not r:
                            self.output("WARNING: unable to create function at 0x%x" % ea)

        if need_hooking:
            start_ea = SegStart(ea)
            end_ea = SegEnd(ea)
            refresh_debugger_memory()
            self.output("0x%x: new code section detected: [0x%x, 0x%x]" % (ea, start_ea, end_ea))
            AnalyzeArea(start_ea, end_ea)
            if self.code_discovery_stop:
                self.resume = False
            if self.code_discovery_nojmp:
                self.add_call_bp(start_ea, end_ea)
            else:
                self.add_call_and_jump_bp(start_ea, end_ea)

        if r:
            name = GetFunctionName(ea)
            func_end = GetFunctionAttr(ea, FUNCATTR_END)
            AnalyzeArea(ea, func_end)
            return name
        else:
            return None

    def handle_after_call(self, ret_addr, stub_name):
        '''
        Called when single stepping into a call instruction (lands at the beginning of a function)
        '''

        ea = self.get_ip()

        if self.is_fake_call(ea):
            MakeComm(self.current_caller['addr'], "fake function call to 0x%x" % ea)
            self.output("0x%X: fake function call to 0x%x" % (self.current_caller['addr'],ea))
            self.current_caller = self.delayed_caller
            self.delayed_caller = None
            return 0

        #print "handle_after_call(): 0x%x" % ea

        seg_name = SegName(ea)

        if self.no_dll and self.is_system_lib(seg_name):
            # skipping API calls
            self.current_caller = self.delayed_caller
            self.delayed_caller = None
            return 0

        caller_ea = self.current_caller['addr']
        caller = format_offset(caller_ea)
        caller_name = format_name(caller_ea)

        arguments = []
        num_args = 0

        name = self.discover_function(ea)

        # if it's a real function (should be), capture stack-based arguments

        if name:
            num_args = self.get_num_args_stack(ea)
            arguments = self.get_stack_args(ea=ea, depth=num_args+1)
            # if recursive or code_discover mode, hook the new functions with breakpoints on all calls (or jumps)
            if (self.recursive or self.code_discovery) and not self.is_system_lib(seg_name) and name not in self.hooked:
                self.hookFunc(func = name)
        else:
            name = Name(ea) # maybe there is a symbol (happens sometimes when the IDA analysis goes wrong)
            if not name: name = "0x%x" % ea
            # this probably is not a real function then - handle it in a generic way
            self.output("Call to unknown function: 0x%x to %s" % (caller_ea,name))
            self.handle_generic(ea)
            self.current_caller = self.delayed_caller
            self.delayed_caller = None
            return 0

        # if we were going through a stub, display the name that was called directly (e.g. not kernelbase but kernel32)
        if self.stub_name:
            header = "Function call: %s to %s (0x%x)" % (caller, stub_name, ea) +\
                    "\nReal function called: %s" % name
        else:
            header = "Function call: %s to %s (0x%x)" % (caller, name, ea)

        # link previously captured register context with stack-based arguments

        raw_context = self.current_caller['ctx'] + arguments
        self.current_caller = self.delayed_caller
        self.delayed_caller = None

        # update data for graph
        if not self.calls_graph.has_key(ea):
            self.calls_graph[ea] = {}
            self.calls_graph[ea]['callers'] = []
        self.calls_graph[ea]['callers'].append({ 'name' : caller_name, 'ea' : caller_ea, 'offset' : caller })
        self.calls_graph[ea]['name'] = name

        if CheckBpt(ret_addr) > 0:
            user_bp = True
        else:
            user_bp = False
            AddBpt(ret_addr) # catch return from the function if not user-added breakpoint

        # fetch the operand for "ret" - will be needed when we will capture the return from the function
        ret_shift = self.calc_ret_shift(ea)

        # this is to be able to reference to this call instance when we are returning from this function
        # try to do it via the satck
        call_info = { 'ctx' : raw_context, 'calling_addr' : caller_ea, 'func_name' : name, \
                    'func_addr' : ea, 'num_args' : num_args, 'ret_shift' : ret_shift, 'user_bp' : user_bp}

        self.saved_contexts[self.get_saved_sp(raw_context)] = call_info

        # if no stack pointer matches while returning (which sometimes happends, unfortunately), try to match it via a fallback method
        # this gives a right guess most of the time, unless some circumstances arise with multiple threads
        self.function_calls[ret_addr] = call_info

        # output to the console and/or file
        (context_full, context_comments) = self.format_call(raw_context)
        self.output_lines([ header ] + context_full + [ "" ])

        # we prefer kernel32 than kernelbase etc. - this is to bypass stubs
        #if self.stub_name:
        #    name = self.stub_name

        # insert IDA's comments
        if self.comments and (self.overwrite_existing or caller_ea not in self.visited):
            self.add_comments(caller_ea, context_comments)
            MakeComm(caller_ea, "%s()" % name)

        # next time we don't need to insert comments (unles overwrite_existing is set)
        self.visited.append(caller_ea)

        if self.colors:
            SetColor(ea, CIC_FUNC, self.FUNC_COLOR)

    def is_system_lib(self, name):
        '''
        Returns true if a segment belongs to a system library, in which case we don't want to recursively hook calls.
        Covers Windows, Linux, Mac, Android, iOS

        @param name: segment name
        '''

        # the below is for Windows kernel debugging
        if name == 'nt':
            return True

        sysfolders = [re.compile("\\\\windows\\\\", re.I), re.compile("\\\\Program Files ", re.I), re.compile("/usr/", re.I), \
                      re.compile("/system/", re.I), re.compile("/lib/", re.I)]
        m = GetFirstModule()
        while m:
            path = GetModuleName(m)
            if re.search(name, path):
                if any(regex.search(path) for regex in sysfolders):
                    return True
                else:
                    return False
            m = GetNextModule(m)
        return False

    ###
    # debugging hooks
    ###

    def dbg_bpt(self, tid, ea):
        '''
        Callback routine called each time the breakpoint is hit
        '''

        #print "dbg_bpt(): 0x%x" % ea

        refresh_debugger_memory()
        is_func_start = False

        if ea in self.stop_points:
            print "FunCap: reached a stop point"
            return 0

        if ea in self.function_calls.keys(): # coming back from a call we previously stopped on
            self.handle_return(ea)
            if self.function_calls[ea]['user_bp'] == False:
                DelBpt(ea)
                if self.resume:
                    request_continue_process()
                    run_requests()
                return 0

        if ea in Functions(): # start of a function
            self.handle_function_start(ea)
            is_func_start = True

        if self.is_ret(ea): # stopped on a ret instruction
            self.handle_function_end(ea)

        elif self.is_jump(ea) and self.code_discovery: #
            self.handle_jump(ea)
            request_step_into()
            run_requests()
            # we don't want ResumeProcess() to be called so we end it up here
            if self.delete_breakpoints:
                DelBpt(ea)
            return 0

        elif self.is_call(ea): # stopped on a call to a function
            # we need to register context before step in
            self.handle_call(ea)
            # requesting step_into on call instruction: don't know if this is the proper way but it works like that
            request_step_into()
            run_requests()
            if self.delete_breakpoints:
                DelBpt(ea)
            return 0

        else: # not call, not ret, and not start of any function
            if not is_func_start:
                self.handle_generic(ea)

        if self.delete_breakpoints:
            DelBpt(ea)
        if self.resume:
            request_continue_process()
            run_requests()

        return 0

    def dbg_step_into(self):
        '''
        Standard callback routine for stepping into.
        '''
        # if we are currently bouncing off a stub, bounce one step further
        ea = self.get_ip()

        refresh_debugger_memory()
        #print "dbg_step_into(): 0x%x" % ea

        if self.stub_steps > 0:
            self.stub_steps = self.stub_steps - 1
            request_step_into()
            run_requests()
            return 0

        # check if need to bounce a new stub
        self.stub_steps = self.check_stub(ea)
        # print "check_stub(): %x : %d" % (ea, self.stub_steps)
        if self.stub_steps > 0:
            self.stub_name = Name(ea)
            #print "in self.stub_steps > 0: Name: %s" % self.stub_name
            self.stub_steps = self.stub_steps - 1
            request_step_into()
            run_requests()
            return 0

        if hasattr(self, 'current_caller') and self.current_caller and self.current_caller['type'] == 'jump':
            self.handle_after_jump(ea)
        else:
            # type must be call
            ret_addr = self.return_address()

            if hasattr(self, 'current_caller') and self.current_caller and ret_addr == self.next_ins(self.current_caller['addr']):
                self.handle_after_call(ret_addr, self.stub_name)
                self.stub_name = None
            else:
                # that's not us - return to IDA
                self.current_caller = None
                self.delayed_caller = None
                if self.resume: "FunCap: unexpected single step" # happens sometimes - due to a BUG in IDA. Hope one day it will be corrected
        if self.resume:
            request_continue_process()
            run_requests()
        return 0

# architecture-dependent classes that inherit from funcap core class

class X86CapHook(FunCapHook):
    '''
    X86 32-bit architecture
    '''
    def __init__(self, **kwargs):
        self.arch = 'x86'
        self.bits = 32
        self.CMT_CALL_CTX = [re.compile('^arg')]
        self.CMT_RET_CTX = [re.compile('^EAX')]
        self.CMT_RET_SAVED_CTX = [re.compile('^arg')]
        self.CMT_MAX = 4
        FunCapHook.__init__(self, **kwargs)

    def is_ret(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        mnem = GetMnem(ea)
        return re.match('ret', mnem)

    def is_call(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetDisasm(ea)
        if re.match('call\s+far ptr', mnem): return None # when IDA badly identifies data as code it throws false positives - zbot example
        return re.match('call', mnem)

    def is_jump(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetMnem(ea)
        return re.match('jmp', mnem)

    def get_context(self, general_only=True, ea=None, depth=None, stack_offset = 1):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack

        @param general_only: only general registers (names start from E)
        @param ea: Address belonging to a function. If not None, stack will be examined for arguments
        @param depth: stack depth to capture - if None then number of it is determined automatically based on number of arguments in the function frame
        '''
        regs = []
        for x in idaapi.dbg_get_registers():
            name = x[0]
            if not general_only or (re.match("E", name) and name != 'ES'):
                value = idc.GetRegValue(name)
                regs.append({'name': name, 'value': value, 'deref': self.dereference(value, 2 * self.STRING_LENGTH)})
        if ea != None or depth != None:
            regs = regs + self.get_stack_args(ea, depth=depth, stack_offset=stack_offset)
        return regs

    def get_stack_args(self, ea, depth = None, stack_offset = 1):
        '''
        Captures args from memory. If not depth given, number of args is dynamically created from IDA's analysis
        '''
        l = []
        stack = idc.GetRegValue('ESP')
        if depth == None: depth = self.get_num_args_stack(ea)+1
        argno = 0
        for arg in range(stack_offset, depth):
            value = DbgDword(stack+arg*4)
            l.append({'name': "arg_%02x" % argno, 'value': value, 'deref': self.dereference(value, 2 * self.STRING_LENGTH)})
            argno = argno + 4
        return l

    def get_ip(self):
        return GetRegValue('EIP')

    def get_sp(self):
        return GetRegValue('ESP')

    def get_saved_sp(self, context):
        return self.getRegValueFromCtx('ESP', context)

    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return DbgDword(GetRegValue('ESP'))

    def calc_ret_shift(self, ea):
        '''
        Calculates additional stack shift when returning from a function e.g. for 'ret 5h' it will return 5

        @param ea: address belonging to a function
        '''

        first_head = GetFunctionAttr(ea, FUNCATTR_START)
        curr_head = PrevHead(GetFunctionAttr(ea, FUNCATTR_END))
        while curr_head >= first_head:
            mnem = GetMnem(curr_head)
            ret_match = re.match('ret', mnem)
            if ret_match:
                break
            curr_head = PrevHead(curr_head)
        if curr_head >= first_head:
            op = GetOpnd(curr_head, 0)
            if op:
                ret_shift = int(re.sub('h$', '', op), 16)
            else:
                ret_shift = 0
        if not ret_match:
            self.output("WARNING: no ret instruction found in the function body, assuming 0x0 shift")
            ret_shift = 0

        return ret_shift

    def check_stub(self, ea):
        '''
        Checks if we are calling into a stub instead of a real function. Currently only supports MS compiler / Windows 7 API (like kernel32.dll)
        There are more to implement, for example Cygwin uses different ones that are not currently supported.

        @param ea: address to check for a stub
        '''

        ## several different types of stubs spotted in kernel32.dll one Windows 7 32bit, maybe others dll as well ?
        # type 1 - simple jump to offset - need to do 1 single step


        # a bit of a workaround - we need to know if it is code or note before making it code. Needed for code_discovery

        if(isCode(GetFlags(ea))):
            self.isCode = True
        else:
            self.isCode = False
            MakeCode(ea)

        disasm = GetDisasm(ea)
        if re.match('^jmp', disasm):
            #print "in check_stub(): JMP stub detected"
            return 1
        # type 2 - strange do-nothing-instruction chain like the below
        # kernel32.dll:76401484 8B FF                         mov     edi, edi
        # kernel32.dll:76401486 55                            push    ebp
        # kernel32.dll:76401487 8B EC                         mov     ebp, esp
        # kernel32.dll:76401489 5D                            pop     ebp
        # kernel32.dll:7640148A E9 2D FF FF FF                jmp     sub_764013BC
        dbytes = GetManyBytes(ea, 7, use_dbg=True)
        if dbytes == "\x8b\xff\x55\x8b\xec\x5d\xe9" or dbytes == "\x8b\xff\x55\x8b\xec\x5d\xeb":
            return 5
        # no stubs. You can define your custom stubs here
        return 0

    def is_fake_call(self, ea):
        '''
        Check if it is a fake call and function should not be analyzed there
        Currently only checking call-to-pops, what else ?
        '''
        mnem = GetMnem(ea)
        return re.match('pop', mnem)

class AMD64CapHook(FunCapHook):
    '''
    AMD64/IA64 architecture support class. Not everything works here, no determination of actual number of arguments passed via registry.
    We depend on IDA here but I don't know how to get that info from IDA and if this is possible at all.
    '''
    def __init__(self, **kwargs):
        self.arch = 'amd64'
        self.bits = 64
        self.CMT_CALL_CTX = [re.compile('^RDI'), re.compile('^RSI'), re.compile('^RDX'), re.compile('^RCX')] # we are capturing 4 args, but it can be extended
        self.CMT_RET_SAVED_CTX = [re.compile('^RDI'), re.compile('^RSI'), re.compile('^RDX'), re.compile('^RCX'), re.compile('^arg')]
        self.CMT_RET_CTX = [re.compile('^RAX')]
        FunCapHook.__init__(self, **kwargs)

    def is_ret(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        mnem = GetMnem(ea)
        return re.match('ret', mnem)

    def is_call(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetMnem(ea)
        return re.match('call', mnem)

    def is_jump(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetMnem(ea)
        return re.match('jmp', mnem)

    def get_context(self, general_only=True, ea=None, depth=None, stack_offset = 1):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack

        @param general_only: only general registers (names start from R)
        @param ea: Address belonging to a function. If not None, stack will be examined for arguments
        @param depth: stack depth to capture - if None then number of it is determined automatically based on number of arguments in the function frame
        '''
        regs = []

        for x in idaapi.dbg_get_registers():
            name = x[0]
            if not general_only or (re.match("R", name) and name != 'RS'):
                value = idc.GetRegValue(name)
                regs.append({'name': name, 'value': value, 'deref': self.dereference(value, 2 * self.STRING_LENGTH)})
        if ea != None or depth != None:
            if ea != None or depth != None:
                regs = regs + self.get_stack_args(ea, depth=depth, stack_offset=stack_offset)
        return regs

    def get_stack_args(self, ea, depth = None, stack_offset = 1):
        '''
        Captures args from memory. If not depth given, number of args is dynamically created from IDA's analysis
        '''
        l = []
        stack = idc.GetRegValue('RSP')
        if depth == None: depth = self.get_num_args_stack(ea)+1
        argno = 0
        for arg in range(stack_offset, depth):
            value = DbgQword(stack+arg*8)
            l.append({'name': "arg_%02x" % argno, 'value': value, 'deref': self.dereference(value, 2 * self.STRING_LENGTH)})
            argno = argno + 8
        return l

    def get_ip(self):
        return GetRegValue('RIP')

    def get_sp(self):
        return GetRegValue('RSP')

    def get_saved_sp(self, context):
        return self.getRegValueFromCtx('RSP', context)

    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return DbgQword(GetRegValue('RSP'))

    def calc_ret_shift(self, ea):
        '''
        Calculates additional stack shift when returning from a function e.g. for 'ret 5h' it will return 5

        @param ea: address belonging to a function
        '''
        first_head = GetFunctionAttr(ea, FUNCATTR_START)
        curr_head = PrevHead(GetFunctionAttr(ea, FUNCATTR_END))
        while curr_head >= first_head:
            mnem = GetMnem(curr_head)
            ret_match = re.match('ret', mnem)
            if ret_match:
                break
            curr_head = PrevHead(curr_head)
        if curr_head >= first_head:
            op = GetOpnd(curr_head, 0)
            if op:
                ret_shift = int(re.sub('h$', '', op), 16)
            else:
                ret_shift = 0
        if not ret_match:
            self.output("WARNING: no ret instruction found in the function body, assuming 0x0 shift")
            ret_shift = 0
        return ret_shift

    def check_stub(self, ea):
        '''
        Checks if we are calling into a stub instead of a real function.

        @param ea: address to check for a stub
        '''

        disasm = GetDisasm(ea)
        # if JMP at the beginning of the function, single step it
        if re.match('^jmp', disasm):
            return 1
        # no stubs
        return 0

    def is_fake_call(self, ea):
        '''
        Check if it is a fake call and function should not be analyzed there
        Currently only checking call-to-pops, what else ?
        '''
        mnem = GetMnem(ea)
        return re.match('pop', mnem)


class ARMCapHook(FunCapHook):
    '''
    ARM/Thumb architecture. Not every feature supported yet, especially stack-based argument capturing.
    First 4 args are via registers so we capture them though.
    '''

    def __init__(self, **kwargs):
        self.arch = 'arm'
        self.bits = 32
        self.CMT_CALL_CTX = [re.compile('R0$'), re.compile('R1$'), re.compile('R2$'), re.compile('R3$')]
        self.CMT_RET_SAVED_CTX = [re.compile('R0$'), re.compile('R1$'), re.compile('R2$'), re.compile('R3$')]
        self.CMT_RET_CTX = [re.compile('R0$')]
        FunCapHook.__init__(self, **kwargs)

    def is_ret(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        disasm = GetDisasm(ea)
        return re.match('POP.*,PC\}', disasm) or re.match('BX(\s+)LR', disasm)

    def is_call(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''

        mnem = GetMnem(ea)
        return re.match('BL', mnem)

    def is_jump(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''

        mnem = GetMnem(ea)
        return re.match('B\s+', mnem)

    def get_context(self, general_only=True, ea=None, depth=None):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack

        '''

        l = []
        for x in idaapi.dbg_get_registers():
            name = x[0]
            value = idc.GetRegValue(name)
            l.append({'name': name, 'value': value, 'deref': self.dereference(value, 2 * self.STRING_LENGTH)})
            # don't know yet how to get the argument frame size on this arch so we don't show stack-passed arguments here
            # Still, we have first four arguments in registers R0-R4
        return l

    # this is currently not implemented but I will look into this in the future
    def get_stack_args(self, ea, depth = None, stack_offset = 1):
        return []

    def get_ip(self):
        return GetRegValue('PC')

    def get_sp(self):
        return GetRegValue('SP')

    def get_saved_sp(self, context):
        return self.getRegValueFromCtx('SP', context)

    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''

        # clearing the low bit (denotes ARM or Thumb mode)
        return GetRegValue('LR') & 0xFFFFFFFE

    def calc_ret_shift(self, ea):
        return 0 # no ret_shift here

    # don't know about stubs on this platform - worth to check
    def check_stub(self, ea):
        return 0

    def is_fake_call(self, ea):
        '''
        Not implemented for this platform yet
        '''
        return False



class CallGraph(GraphViewer):
    '''
    Class to draw real function call graphs based on stack capture (not like in IDA's trace)
    It will draw all sorts of indirects calls (CALL DWORD etc.)
    Code borrowed from MyNav project and modified
    '''

    def __init__(self, title, calls, exact_offsets):
        GraphViewer.__init__(self, title, calls)
        self.calls = calls
        self.nodes = {}
        self.exact_offsets = exact_offsets

    # warning: this won't work after code relocation !
    def OnRefresh(self):
        self.Clear()
        node_callers = {}
        for hit, call in self.calls.items():
            #current_call = self.calls[hit]
            name = call['name']
            current_name = GetFunctionName(hit) # check if the user has changed the name of a function
            if current_name:
                name = current_name
            #name = current_call['name']
            #print "adding primary node %x" % hit
            if not node_callers.has_key(hit):
                node_callers[hit] = []
                self.nodes[hit] = self.AddNode((hit, name))
            for caller in self.calls[hit]['callers']:
                if self.exact_offsets == True:
                    caller_name = caller['offset']
                    graph_caller = caller['ea']
                else:
                    graph_caller = GetFunctionAttr(caller['ea'], FUNCATTR_START)
                    if graph_caller == 0xffffffff: # no symbol exist
                        graph_caller = caller['ea']
                        caller_name = caller['name']
                    else:
                        caller_name = GetFunctionName(graph_caller)
                if not node_callers.has_key(graph_caller):
                    #print "adding node %x" % caller
                    self.nodes[graph_caller] = self.AddNode((graph_caller, caller_name))
                    node_callers[graph_caller] = []
                if not graph_caller in node_callers[hit]:
                    #print "adding edge for %x --> %x" % (graph_caller, hit)
                    self.AddEdge(self.nodes[graph_caller], self.nodes[hit])
                    node_callers[hit].append(graph_caller)
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

###
# automation scripts examples - works for win32 and win64-bit
# this should be in a separate file of course
# but since IDA doesn't like it too much we leave it here
###

class Auto:

    def win_call_capture(self):
        '''
        Runs a program and captures all "call" instructions
        '''
        d.off()
        d.delAll()
        start = GetEntryOrdinal(0)
        AddBpt(start)
        segname = SegName(start)
        StartDebugger('', '', '')
        GetDebuggerEvent(WFNE_SUSP, -1);
        print "Auto: program entry point reached"
        DelBpt(start)
        d.addStop(LocByName("ntdll_RtlExitUserProcess"))
        d.addStop(LocByName("kernel32_ExitProcess"))
        d.on()
        d.hookSeg(seg = segname)
        ResumeProcess()

    def win_func_capture(self):
        '''
        Runs a program and captures function starts and rets
        '''
        d.off()
        d.delAll()
        start = GetEntryOrdinal(0)
        AddBpt(start)
        StartDebugger('', '', '')
        GetDebuggerEvent(WFNE_SUSP, -1);
        print "Auto: program entry point reached"
        DelBpt(start)
        d.addStop(LocByName("ntdll_RtlExitUserProcess"))
        d.addStop(LocByName("kernel32_ExitProcess"))
        d.on()
        d.addCallee()
        ResumeProcess()

    def win_code_discovery(self):
        '''
        Runs a program, captures all call instructions, and recursively adds new code if spotted (for obfuscator etc.)
        '''
        d.off()
        d.delAll()
        start = GetEntryOrdinal(0)
        AddBpt(start)
        StartDebugger('', '', '')
        GetDebuggerEvent(WFNE_SUSP, -1);
        print "Auto: program entry point reached"
        DelBpt(start)
        d.addStop(LocByName("kernel32_ExitProcess")) # last breakpoint before the process terminates, to give a chance to take a memory snapshot
        d.addStop(LocByName("ntdll_RtlExitUserProcess")) # to be sure we add 2 possibilities, there is probably more ...
        d.on()
        d.code_discovery = True
        d.addCJ(func = GetFunctionName(start))
        ResumeProcess()

###
# main()
###

debugger = False

try:
    (arch, bits) = get_arch()
    debugger = True
except TypeError:
    print "FunCap: please select a debugger first"


if debugger:
    try:
        d.off()
    except: AttributeError

    if arch == 'x86':
        d = X86CapHook()
    elif arch == 'amd64':
        d = AMD64CapHook()
    elif arch == 'arm' and bits == 32:
        d = ARMCapHook()
    else:
        raise "FunCap: architecture not supported"

    a = Auto()
    d.on()
