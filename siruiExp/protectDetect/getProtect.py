from pwn import *
import logging
log = logging.getLogger(__name__)

def getProperties(binary_name):
    
    properties = {}
    binary = ELF(binary_name)
    properties["aslr"] = binary.aslr
    properties["arch"] = binary.arch
    properties["canary"] = binary.canary
    properties["got"] = binary.got
    properties["nx"] = binary.nx
    properties["pie"] = binary.pie
    properties["plt"] = binary.plt
    properties["relro"] = binary.relro

    return properties
def setLog():
    log = logging.getLogger("SiruiEXP")
    stream_fmt = '%(name)s================%(asctime)s================:     %(message)s'
    fmt = logging.Formatter(fmt = stream_fmt)
    # 创建控制台Handler
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt=fmt)
    log.setLevel("INFO")
    log.addHandler(stream_handler)
    return log