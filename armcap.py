'''
Created on Nov 21, 2012

@author: deresz@gmail.com
@version: 0.3

ARM capture module

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

class ARMCapHook(FunCapHook):
    
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
    
    def getSavedSP(self, context):
        return self.getRegValueFromCtx('SP', context)
    
    def return_address(self):
        '''
        Get the return address stored on the stack or register
        '''
        return GetRegValue('LR')