'''
Created on Nov 21, 2012

@author: deresz@gmail.com
@version: 0.4

FunCap. A script to capture function calls during debug session in IDA.
It is created to help quickly importing some runtime data into static IDA database to boost static analysis.
Was meant to be multi-modular but seems IDA does not like scripts broken in several files/modules.
So we got one fat script file now :)

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

# IDA imports

import sys
from idaapi import *
from idautils import *
from idc import *

# utility functions

def FormatOffset(ea):
    offset = GetFuncOffset(ea)    
    if offset == "" or offset == None:
        offset = "0x%x" % ea
    return offset

def getArch():
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

# throw it to a separate file later on

class FunCapHook(DBG_Hooks):
    '''
    Main class to inherit from DBG_Hooks
    '''  
 
    # some static constants
    STRING_EXPLORATION_MIN_LENGTH = 2
    STRING_EXPLORATION_BUF_SIZE = 128
    FUNC_COLOR = 0xF7CBEA
    ITEM_COLOR = 0x70E01B
    CALL_COLOR = 0x33FF33
    BB_COLOR = 0xF3FA39
  
    def __init__(self, **kwargs):
        '''        
        @param outfile: log file where the output dump will be written (None = no logging)
        @param delete_breakpoints: do we delete a breakpoint after first pass ?
        @param hexdump: do we include hexdump in dump and in IDA comments ?
        @param comments: do we add IDA comments on top of each function ?
        @param resume: resume program after hitting a breakpoint ?
        @param depth: current stack depth capture for non-function hits"
        @param colors: do we fill all the function blocks with colors when the breakpoint hits?
        @param nofunc_colors: do we mark breakpoints hits which are not on function start ? 
        '''
        self.outfile = kwargs.get('outfile', None)
        self.delete_breakpoints = kwargs.get('delete_breakpoints', False)
        self.hexdump = kwargs.get('hexdump', False)
        self.comments = kwargs.get('comments', True)
        self.resume = kwargs.get('resume', True)
        self.depth = kwargs.get('depth', 0)
        self.colors = kwargs.get('colors', True)
        self.output_console = kwargs.get('output_console', True)
        self.overwrite_existing = kwargs.get('output_console', False) # not implemented yet - to overwrite existing capture comments in IDA
        
        # TODO: need to find better way do determine architecture ...
        
        self.commented = {}
        self.currentFormatOffsets = []
        self.current_call = None
        self.saved_contexts = {}
        self.function_calls = {}
        self.calls_graph = {}
        DBG_Hooks.__init__(self)
        
        self.out = None

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

                        if self.isRet(head):
                            AddBpt(head)
    
    def addCallee(self):
        '''
        Add breakpoints on both function starts and return instructions
        '''
        self.addFuncStart()
        self.addFuncRet()
        
    def addCaller(self, func = "", recursive = False):
        '''
        Add breakpoints on function calls
        
        @param func: this should be a function name or "screen". If given, breakpoints will only be put within this range. Screen means
            function pointed by the current cursor
        @param recursive: if True, the subfunction calls will also be captured
        '''
        
        if func == "screen":
            ea = ScreenEA()
            f = get_func(ea)
            start_ea = f.startEA
            end_ea = f.endEA
            self.addCallBp(start_ea, end_ea)
        elif func != "":
            ea = LocByName(func)
            f = get_func(ea)
            start_ea = f.startEA
            end_ea = f.endEA
            self.addCallBp(start_ea, end_ea)
        else:
            for seg_ea in Segments():
                # For each of the defined elements
                start_ea = seg_ea
                end_ea = SegEnd(seg_ea)
                self.addCallBp(start_ea, end_ea)
    
    def graph(self, exact_offsets = False):
        '''
        Draw the graph
        
        @param exact_offsets: if enabled each function call with offset(e.g. function+0x12) will be treated as graph node
            if disabled, only function name will be presented as node (more regular graph but less precise information)
        '''
        CallGraph("FunCap: function calls", self.calls, exact_offsets).Show()
    
    ###                
    # END of public interface
    ###
    
    def addCallBp(self, start_ea, end_ea):
        '''
        Add breakpoints on every subrountine call instruction within the scope (start_ea, end_ea)
        '''
        for head in Heads(start_ea, end_ea):

            # If it's an instruction
            if isCode(GetFlags(head)):

                if self.isCall(head):
                    AddBpt(head)
        
    def getNumArgsStack(self, addr):        
        '''
        Get the size of arguments frame
        '''
        argFrameSize = GetStrucSize(GetFrame(addr)) - GetFrameSize(addr) + GetFrameArgsSize(addr)
        return argFrameSize / (self.bits/8)
    
    def getCaller(self):
        '''
        Return the formatted caller func name + its address
        '''
        ret = self.return_address()
        return FormatOffset(ret) + " (0x%x)" % ret
    
    def getRegValueFromCtx(self, name, context):
        
        for reg in context:
            if reg['name'] == name:
                return reg['value']
        
    def add_comments(self, ea, lines):
        '''
        Add context dump as IDA comments
        '''
        idx = 0
        for line in lines:
            # workaround with Eval() - ExtLinA() doesn't work well in idapython
            line_sanitized = line.replace('"', '\\"')
            ret = idc.Eval('ExtLinA(%d, %d, "%s");' % (ea, idx, line_sanitized))
            if ret:
                print "idc.Eval() returned an error: %s" % ret
            idx += 1
        self.commented[ea] = True
    
    def format_normal(self, regs):
        lines = []
        if self.bits == 32:
            for reg in regs:
                lines.append("%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        else:
            for reg in regs:
                lines.append("%3s: 0x%016x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        return (lines, lines)
    
    def format_call(self, regs):
        full_ctx = []
        cmt_ctx = []
        for reg in regs:
            full_ctx.append("%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
            if any(regex.match(reg['name']) for regex in self.CMT_CALL_CTX):
                # we can shorten 'deref' if needed here
                cmt_ctx.append("   %3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        return (full_ctx, cmt_ctx)
    
    def format_return(self, regs, saved_regs):
        full_ctx = []
        cmt_ctx = []
        for reg in regs:
            full_ctx.append("%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
            if any(regex.match(reg['name']) for regex in self.CMT_RET_CTX):
                cmt_ctx.append("   %3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        if saved_regs:
            for reg in saved_regs:
                if any(regex.match(reg['name']) for regex in self.CMT_RET_SAVED_CTX):
                    new_deref = self.smart_dereference(reg['value'], print_dots=True, hex_dump=self.hexdump)
                    full_ctx.append("s_%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(new_deref)))
                    cmt_ctx.append("   s_%3s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(new_deref)))
        return (full_ctx, cmt_ctx)
    
    def dump_regs(self, lines, outfile=None):
        for line in lines:
            if outfile != None:
                outfile.write(line + "\n")
            else:
                print line

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
        hslice = ""

        for byte in data:
            if addr % 16 == 0:
                dump += " "

                for char in slice:
                    if ord(char) >= 32 and ord(char) <= 126:
                        dump += char
                    else:
                        dump += "."

                dump += "\n%s%04x: " % (prefix, addr)
                hslice = ""

            dump  += "%02x " % ord(byte)
            hslice += byte
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
    
    def dump_context(self, header, context_full):
        '''
        Dumping full execution context to file and console depending on the options
        '''
        if self.output_console:
            print header
            self.dump_regs(context_full)        
            print
        if self.outfile:
            self.out.write(header + "\n")
            self.dump_regs(context_full, self.out)
            self.out.write("\n")
            self.out.flush()
    
    def next_ins(self, ea):
        end = idaapi.cvar.inf.maxEA
        return idaapi.next_head(ea, end)
    
    ###
    # debugging hooks
    ###
    
    
    def dbg_bpt(self, tid, ea):
        '''
        Callback routine called each time the breakpoint is hit
        '''
        
        # TODO: recompose this. Put handlers in separate functions
        
        if ea in self.function_calls.keys(): # coming back from a call we previously stopped on
            # need to get context from within a called function
            function_call = self.function_calls[ea]
            ret_shift = function_call['ret_shift']
            raw_context = self.getContext()
            #raw_context = self.getContext(stack_offset = 0 - ret_shift, depth=function_call['num_args'] - ret_shift) # no stack here ?
            header = "Returning from call to %s(), execution resumed at %s (0x%x)" % (function_call['func_name'], FormatOffset(ea), ea)
            if self.CMT_RET_SAVED_CTX:
                sp = self.getSP()
                sp = sp - ret_shift
                if self.saved_contexts.has_key(sp):
                    saved_context = self.saved_contexts[sp]
                    del self.saved_contexts[sp]
                else:
                    print "WARNING: saved context not found for function %s stack pointer 0x%x" % (function_call['func_name'], sp)
                    saved_context = None
            else:
                saved_context = None
            (context_full, context_comments) = self.format_return(raw_context, saved_context)
            DelBpt(ea) #TODO might be double deleted - this function needs to be re-written
            
        elif ea in Functions(): # start of a function
            header = "Function call: %s (0x%x) " % (GetFunctionName(ea),ea) + "called by " + self.getCaller()
            raw_context= self.getContext(ea=ea)
            if self.colors:
                SetColor(ea, CIC_FUNC, self.FUNC_COLOR)
            
            # update data for graph
            if not self.calls_graph.has_key(ea):
                self.calls_graph[ea] = {}
            self.calls_graph[ea][self.return_address()] = True
            (context_full, context_comments) = self.format_normal(raw_context)
             
        elif self.isRet(ea): # stopped on a ret instruction
            function_name = GetFunctionName(ea)
            if function_name:
                header = "Return from function: %s (0x%x) " % (function_name,ea) + "to " + self.getCaller()
                raw_context = self.getContext(ea=ea)
            else:
                header = "Returning from unknown function (0x%x) " % ea + "to " + self.getCaller()
                raw_context = self.getContext(ea=ea, depth=0)
            if self.colors:
                SetColor(ea, CIC_ITEM, self.ITEM_COLOR)
            (context_full, context_comments) = self.format_normal(raw_context)    
                         
        elif self.isCall(ea): # stopped on a call to a function
            # we need to register context before step in
            self.current_caller = { 'addr' : ea, 'ctx' : self.getContext(ea=ea, depth=0) }
 
            if self.colors:
                SetColor(ea, CIC_ITEM, self.CALL_COLOR)

            request_step_into()
            run_requests()
            return 0
        
        else: # some other address
            header = "Address: 0x%x" % ea
            # no argument dumping if not function
            raw_context = self.getContext(ea=ea, depth=self.depth)
            (context_full, context_comments) = self.format_normal(raw_context)
            if self.colors:
                SetColor(ea, CIC_ITEM, self.ITEM_COLOR)
        
        if self.delete_breakpoints:
            DelBpt(ea)
        if self.comments and not self.commented.has_key(ea):
            self.add_comments(ea, context_comments)
 
        self.dump_context(header, context_full)
 
        # disabled now for testing but will be enabled finally
        if self.resume: ResumeProcess()
        return 0
        
    def dbg_step_into(self):
        # if we are here - means this is after single step into a call function
        # so this must be a function (btw - we don't use our plugin with obfuscated code - unpack it yourself first!)
        ret_addr = self.return_address()
        if (not hasattr(self, 'current_caller')) or ret_addr != self.next_ins(self.current_caller['addr']):
            # that's not us - return to IDA
            #print "ret_addr: 0x%x, current_caller = 0x%x" % (ret_addr, self.current_caller['addr'])
            self.current_caller = None
            print "FunCap: it's not me"
            return 0
        
        ea = self.getIP()
        
        ### TODO: trampoline bypass (in kernel32 on Windows 7 for example)
        
        caller_ea = self.current_caller['addr']
        caller = FormatOffset(caller_ea)
        
        # update data for graph
        if not self.calls_graph.has_key(ea):
            self.calls_graph[ea] = {}
        self.calls_graph[ea][self.return_address()] = True

        arguments = []
        num_args = 0
        name = GetFunctionName(ea)
    
        if not name:
            # let's try to create a function here (works for mapped library files etc.)
            refresh_debugger_memory() # need to call this here, thank you Ilfak !
            r = MakeFunction(ea) # BUG in IDA - does not work atm
            if(r):
                name = GetFunctionName(ea)
                func_end = GetFunctionAttr(ea, FUNCATTR_END)
                AnalyzeArea(ea, func_end)
            else:
                name = Name(ea) # last try
        if name:
            num_args = self.getNumArgsStack(ea) 
            arguments = self.getStackArgs(ea=ea, depth=num_args+1)
        else:
            name = "0x%x" % ea
            
        header = "Function call: %s to %s (0x%x)" % (caller, name, ea)
        raw_context = self.current_caller['ctx'] + arguments
        self.current_caller = None
       
        # hash of all function call instances (indexed by stack frame address)
        # we need this to update references to arguments when exiting the function
        if self.CMT_RET_SAVED_CTX:
            self.saved_contexts[self.getSavedSP(raw_context)] = raw_context
    
        (context_full, context_comments) = self.format_call(raw_context)
        self.dump_context(header, context_full)
        if self.comments and not self.commented.has_key(caller):
            self.add_comments(caller_ea, context_comments)
            MakeComm(caller_ea, "%s()" % name)
    
        AddBpt(ret_addr) # catch return from the function
        # hash of all call instructions (indexed by return address)
        if not self.function_calls.has_key(ret_addr):
            # determine the stack shift at ret instruction
            ret_shift = self.calc_ret_shift(ea)
            self.function_calls[ret_addr] = { 'calling_addr' : caller_ea, 'ret_addr' : ret_addr, 'func_name' : name, \
                                             'func_addr' : ea, 'num_args' : num_args, 'ret_shift' : ret_shift}
            
        if self.colors:
            SetColor(ea, CIC_FUNC, self.FUNC_COLOR)
        if self.resume: ResumeProcess()    
        
        return 0
 
# architecture-dependent classes that inherit from funcap core class

class X86CapHook(FunCapHook):
    '''
    X86 32-bit architecture 
    '''
    def __init__(self, **kwargs):
        self.arch = 'x86'
        self.bits = 32
        self.CMT_CALL_CTX = [re.compile('^arg.*')]
        self.CMT_RET_CTX = [re.compile('EAX')]
        self.CMT_RET_SAVED_CTX = [re.compile('^arg.*')]
        FunCapHook.__init__(self, **kwargs)
    
    def isRet(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        mnem = GetMnem(ea)
        return re.match('ret', mnem)       
            
    def isCall(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetMnem(ea)
        return re.match('call', mnem)
  
    def getContext(self, general_only=True, ea=None, depth=None, stack_offset = 1):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack
        
        @param general_only: only general registers (names start from E or R) - only Intel arch currently
        @param ea: if not None, stack will be examined for arguments
        @depth: stack depth - if none then number of arguments is determined automatically
        '''
        regs = []        
        for x in idaapi.dbg_get_registers():
            name = x[0]
            if not general_only or (re.match("E", name) and name != 'ES'):
                value = idc.GetRegValue(name)
                regs.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
        if ea != None or depth != None:
            regs = regs + self.getStackArgs(ea, depth=depth, stack_offset=stack_offset)
        return regs 
    
    def getStackArgs(self, ea, depth = None, stack_offset = 1):
        '''
        Captures args from memory. If not depth given, number of args is dynamically created from IDA's analysis
        '''
        l = []
        stack = idc.GetRegValue('ESP')
        if depth == None: depth = self.getNumArgsStack(ea)+1
        argno = 0
        for arg in range(stack_offset, depth):
            # TODO - try-catch for non readable stack (might happen in some really tricky code)
            value = DbgDword(stack+arg*4)
            l.append({'name': "arg_%02x" % argno, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})  
            argno = argno + 4
        return l
    
    def getIP(self):
        return GetRegValue('EIP')
    
    def getSP(self):
        return GetRegValue('ESP')
    
    def getSavedSP(self, context):
        return self.getRegValueFromCtx('ESP', context)
    
    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return DbgDword(GetRegValue('ESP'))
    
    def calc_ret_shift(self, ea):
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
            print "WARNING: no ret instruction found in the function body, assuming 0x0 shift"
            ret_shift = 0
            
        return ret_shift

class AMD64CapHook(FunCapHook):
    '''
    AMD64/IA64 architecture support class. Not everything works here, no determination of actual number of arguments passed via registry.
    We depend on IDA here but I don't know how to get that info from IDA and if this is possible at all.
    '''
    def __init__(self, **kwargs):
        self.arch = 'amd64'
        self.bits = 64
        self.CMT_CALL_CTX = [re.compile('rdi'), re.compile('rsi'), re.compile('rdx'), re.compile('rcx')] # we are capturing 4 args, but it can be extended 
        self.CMT_RET_SAVED_CTX = [re.compile('rdi'), re.compile('rsi'), re.compile('rdx'), re.compile('rcx')]
        self.CMT_RET_CTX = [re.compile('rax')]
        FunCapHook.__init__(self, **kwargs)
    
    def isRet(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        mnem = GetMnem(ea)
        return re.match('ret', mnem)
            
    def isCall(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
        mnem = GetMnem(ea)
        return re.match('call', mnem)
        
    def getContext(self, general_only=True, ea=None, depth=None):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack
        
        @param general_only: only general registers (names start from E or R) - only Intel arch currently
        @param ea: if not None, stack will be examined for arguments
        @depth: stack depth - if none then number of arguments is determined automatically
        '''
        regs = []        
        
        for x in idaapi.dbg_get_registers():
            name = x[0]
            if not general_only or (re.match("R", name) and name != 'RS'):
                value = idc.GetRegValue(name)
                regs.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
        if ea != None or depth != None:
            if ea != None or depth != None:
                stack = self.getStackArgs(ea, depth)
        return regs + stack 
    
    def getStackArgs(self, ea, depth = None, stack_offset = 1):
        '''
        Captures args from memory. If not depth given, number of args is dynamically created from IDA's analysis
        '''
        l = []
        stack = idc.GetRegValue('RSP')
        if depth == None: depth = self.getNumArgsStack(ea)+1
        argno = 0
        for arg in range(stack_offset, depth):
            value = DbgQword(stack+arg*8)
            l.append({'name': "arg_" % argno, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})  
            argno = argno + 8
        return l
    
    def getIP(self):
        return GetRegValue('RIP')
    
    def getSP(self):
        return GetRegValue('RSP')
 
    def getSavedSP(self, context):
        return self.getRegValueFromCtx('RSP', context)
    
    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return DbgQword(GetRegValue('RSP'))    
    
    def calc_ret_shift(self, ea):
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
            print "WARNING: no ret instruction found in the function body, assuming 0x0 shift"
            ret_shift = 0
        else:
            return ret_shift

    
class ARMCapHook(FunCapHook):
    '''
    ARM architecture. Not every feture supported yet, especially stack-based argument capturing. First 4 are registers so we capture them.
    '''
    
    def __init__(self, **kwargs):
        self.arch = 'arm'
        self.bits = 32
        self.CMT_CALL_CTX = [re.compile('R0'), re.compile('R1'), re.compile('R2'), re.compile('R3')] # we are capturing 4 args, but it can be extended 
        self.CMT_RET_SAVED_CTX = [re.compile('R0'), re.compile('R1'), re.compile('R2'), re.compile('R3')]
        self.CMT_RET_CTX = [re.compile('R0')]
        FunCapHook.__init__(self, **kwargs)
    
    def isRet(self, ea):
        '''
        Check if we are at return from subroutine instruction
        '''
        disasm = GetDisasm(ea)
        return re.match('POP.*,PC\}', disasm) or re.match('BX(\s+)LR', disasm)
            
    def isCall(self, ea):
        '''
        Check if we are at jump to subrouting instruction
        '''
            
        mnem = GetMnem(ea)
        return re.match('BL', mnem)
  
    def getContext(self, general_only=True, ea=None, depth=None):
        '''
        Captures register states + arguments on the stack and returns it in an array
        We ask IDA for number of arguments to look on the stack
        
        @param general_only: only general registers (names start from E or R) - only Intel arch currently
        @param ea: if not None, stack will be examined for arguments
        @depth: stack depth - if none then number of arguments is determined automatically
        '''
        # get context for Intel and ARM architectures
        l = []        
        for x in idaapi.dbg_get_registers():
            name = x[0]
            value = idc.GetRegValue(name)
            l.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
            # don't know yet how to get the argument frame size on this arch so we don't show stack-passed arguments here
            # Still, we have first four arguments in registers R0-R4
        return l 
    
    def getIP(self):
        return GetRegValue('PC')
    
    def getSP(self):
        return GetRegValue('SP')
    
    def getSavedSP(self, context):
        return self.getRegValueFromCtx('SP', context)
    
    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return GetRegValue('LR')
   
    def calc_ret_shift(self, ea):
        return 0 # no ret_shift here

    
class CallGraph(GraphViewer):
    '''
    Class to draw real function call graphs based on stack capture (not like in IDA's trace)
    It will draw all sorts of indirects calls (CALL DWORD etc.)
    '''

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

###
# main()
###

(arch, bits) = getArch()

outfile = os.path.expanduser('~') + "/funcap.txt"

if arch == 'x86':
    d = X86CapHook(outfile=outfile)
elif arch == 'amd64':
    d = AMD64CapHook(outfile=outfile)
elif arch == 'arm' and bits == 32:
    # ARM64 not supported for the moment
    d = ARMCapHook(outfile)
else:
    raise "Architecture not supported"

d.on()