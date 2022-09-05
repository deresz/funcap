'''
Created on 21 janv. 2014

@author: deresz
'''

import hashlib
import pickle
from idaapi import *
from idautils import *
from idc import *

BYTES_COMPARE = 10

renamed_functions = {}

for f in list(Functions()):
    name = idc.get_func_name(f)
    if re.match("sub_", name):
        continue
    function = get_func(f)
    flen = function.size()
    if flen < BYTES_COMPARE:
        bytes_read = flen
    else:
        bytes_read = BYTES_COMPARE
    start_bytes = idc.get_bytes(function.start_ea, bytes_read)
    m = hashlib.md5()
    m.update("%x".encode('utf-8') % flen)
    m.update(start_bytes)
    digest = m.digest()
    renamed_functions[digest] = name
    print("Function name %s saved" % name)

dumpfile = os.path.expanduser('~') + "/fun.dump"
pickle.dump(renamed_functions, open(dumpfile, "wb"))
print("Dumped function names to %s." % dumpfile)
