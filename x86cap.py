'''
Created on Nov 21, 2012

@author: deresz@gmail.com
@version: 0.3

X86 capture module

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

from funcap import *
from idc import *
from idaapi import *
from idautils import *

class X86CapHook(FunCapHook):
    
    def __init__(self, **kwargs):
        self.arch = 'x86'
        self.bits = 32
        self.CMT_CALL_CTX = [re.compile('arg.*')]
        self.CMT_RET_CTX = [re.compile('EAX')]
        self.CMT_RET_SAVED_CTX = [re.compile('^arg.*')] # be able to see how the arguments have changed
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
            if not general_only or (re.match("E", name) and name != 'ES'):
                value = idc.GetRegValue(name)
                regs.append({'name': name, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})
        if ea != None or depth != None:
            stack = self.getStackArgs(ea, depth=depth)
        return regs + stack 
    
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
            l.append({'name': "arg_" % argno, 'value': value, 'deref': self.smart_dereference(value, print_dots=True, hex_dump=self.hexdump)})  
            argno = argno + 4
        return l
    
    def getIP(self):
        return GetRegValue('EIP')
    
    def getSavedSP(self, context):
        return self.getRegValueFromCtx('ESP', context)
    
    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return DbgDword(GetRegValue('ESP'))

