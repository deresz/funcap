'''
Created on Nov 21, 2012

@author: deresz@gmail.com
@version: 0.3

This is a script to load in IDA python that enables funcap.
It is also an example of how to use the module, if someone want to instrument it in a different way.

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

from amd64cap import *
from armcap import *
from x86cap import *
from funcap import *

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