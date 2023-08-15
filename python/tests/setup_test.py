import os
import sys

sys.path += ('..', '../.libs')

if hasattr(os, 'add_dll_directory'):
    os.add_dll_directory(os.path.join(os.getcwd(), '..', '..', '.libs'))
