'''
Created on 21 janv. 2014

@author: deresz
'''

import os, re, md5
import pickle
from idaapi import *
from idautils import *
from idc import *

BYTES_COMPARE = 10

dumpfile = os.path.expanduser('~') + "/fun.dump"
renamed_functions = pickle.load(open(dumpfile, "r"))
print "Loading function names from %s." % dumpfile

for f in list(Functions()):
    name = GetFunctionName(f)

    function = get_func(f)
    flen = function.size()
    if flen < BYTES_COMPARE:
        bytes_read = flen
    else:
        bytes_read = BYTES_COMPARE
    start_bytes = GetManyBytes(function.startEA, bytes_read)
    m = md5.new()
    m.update("%x" % flen)
    m.update(start_bytes)
    digest = m.digest()
    if digest in renamed_functions.keys():
        new_name = renamed_functions[digest]
        print "Renaming %s to %s" % (name, new_name)
        MakeName(function.startEA, new_name)

