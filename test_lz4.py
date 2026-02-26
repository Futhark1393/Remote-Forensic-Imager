import sys
sys.path.insert(0, ".")
from fx.core.acquisition.lz4_writer import LZ4Writer
import tempfile
import os
import lz4.frame
path = tempfile.mktemp(suffix=".dd.lz4")
w = LZ4Writer(path)
w.write(b"Hello LZ4")
w.close()
print("LZ4Writer write complete.")
with lz4.frame.open(path, "rb") as f:
    print("Read from lz4:", f.read())
os.unlink(path)
