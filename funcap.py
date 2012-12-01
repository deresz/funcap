'''c v   
Created on Nov 21, 2012

IDApython script for simple code coverage and function call recording

@author: deresz
@version: 0.1
'''

from idc import *
from idaapi import *
import sys, re

class FunCapHook(DBG_Hooks):
    '''
    Main class to inherit from DBG_Hooks
    '''  

    # some static constants
    STRING_EXPLORATION_MIN_LENGTH = 2
    STRING_EXPLORATION_BUF_SIZE = 128
    FUNC_COLOR = 0xF7CBEA;
    ITEM_COLOR = 0x70E01B;
  
    def __init__(self, outfile="funcap.txt", delete_breakpoints = False, hexdump = False, mark = True, resume = False):
        '''        
        @param outfile: log file where the output dump will be written
        @param delete_breakpoints: do we delete a breakpoint after first pass ?
        @param hexdump: do we include hexdump in dump and in IDA comments ?
        @param mark: do we add IDA comments on top of each function ?
        @param resume: resume program after hitting a breakpoint ?
        '''
        self.outfile = outfile
        self.delete_breakpoints = delete_breakpoints
        self.hexdump = hexdump
        self.mark = mark
        self.resume = resume
        
        # FIXME: rneed to find better way do determine architecture ...
        (self.arch, self.bits) = self.getArch()
        
        self.marked = {}
        DBG_Hooks.__init__(self)

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
        if not arch:
            raise "Architecture currently not supported"
        return (arch, bits)
            
        return (self.arch, self.bits)
  
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
    
        else:
            raise "Unknown arch"
    
        return l 
    
    def dbg_bpt(self, tid, ea):
        if ea not in Functions():
            print "Address: 0x%x" % ea
            # no argument dumping if not function
            # TODO: we can maybe dump local variables instead in the future ?
            context = self.getContext(ea=ea, depth=0)
            SetColor(ea, CIC_ITEM, self.ITEM_COLOR)
        else:
            print "Function: %s (0x%x): " % (GetFunctionName(ea),ea)
            context = self.getContext(ea=ea)
            # this is maybe not needed as we can colorize via trace function in IDA
            SetColor(ea, CIC_FUNC, self.FUNC_COLOR)
        lines = self.format_reg_output(context)
        if self.delete_breakpoints:
            DelBpt(ea)
        if self.mark and not self.marked.has_key(ea):
            self.add_comments(ea, lines)
            self.marked[ea] = True
        self.dump_regs(lines)        
        print           
        # disabled now for testing but will be enabled finally
        if self.resume: ResumeProcess()
        return 0
    
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
                lines.append("%s: 0x%08x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        else:
            for reg in regs:
                lines.append("%s: 0x%16x --> %s" % (reg['name'], reg['value'], repr(reg['deref'])))
        return lines
    
    def dump_regs(self, lines):
        for line in lines:
            print line

    # the following three functions are adopted from PaiMei by Pedram Amini
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

debugger = FunCapHook()
debugger.hook()
