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

dumpfile = os.path.expanduser('~') + "/fun.dump"
renamed_functions = pickle.load(open(dumpfile, "rb"))
print("Loading function names from %s." % dumpfile)

for f in list(Functions()):
    name = idc.get_func_name(f)

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
    if digest in renamed_functions.keys():
        new_name = renamed_functions[digest]
        print("Renaming %s to %s" % (name, new_name))
        set_name(function.start_ea, new_name)

