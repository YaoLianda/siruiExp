import r2pipe
import json
import logging
import sys
import os
sys.path.append(os.path.abspath(os.path.join(__file__, "..", "..","..")))
from protectDetect.getProtect import getProperties
from protectDetect.getProtect import setLog

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log= logging.getLogger('SiruiExp')
log2 =logging.getLogger('pwnlib.elf.elf')
log2.disabled=True
'''
    这是脆弱函数检测文件
    getVulnFunc:获取一些可以劫持的函数信息,例如调用了system函数
    getControlFunc:获取一些堆操作的函数信息
'''


def getVulnFunc(binary_name):
    
    vulnFunctions = {}

    # Initilizing r2 with with function call refs (aac)
    r2 = r2pipe.open(binary_name)
    r2.cmd("aaa")##首先执行一个深度的静态分析

    functions = [func for func in json.loads(r2.cmd("aflj"))]#获得函数列表以josn格式返回
     
    # 检查提供system("/bin/sh")的函数
    for func in functions:
        if "system" in str(func["name"]):##查看system是否在符号名列表内
            system_name = func["name"]

            # Get XREFs:参考这个地址或者符号的函数，find data/code references to this address and print in json format
            #[{"from":134517236,"type":"CALL","perm":"--x","opcode":"call sym.imp.system","fcn_addr":134517190,
            # "fcn_name":"sym.print_flag","realname":"print_flag","refname":"sym.imp.system"}]
            refs = [ 
                func for func in json.loads(r2.cmd("axtj @ {}".format(system_name)))
            ]
            for ref in refs:
                if "fcn_name" in ref:
                    vulnFunctions[ref["fcn_name"]] = ref
                    #{"sym.print_flag":ref}
    # Check for function that reads flag.txt
    # Then prints flag.txt to STDOUT

    return vulnFunctions

def getControlFunc(binary_name):
    controlFunctions={}
    addlists =["sym.add","sym.create"]
    dellists =['sym.del','sym.delete','sym.remove']
    editlists=['sym.edit','sym.change']
    showlists =['sym.print','sym.show']
    r2 = r2pipe.open(binary_name)
    r2.cmd("aaa")##首先执行一个深度的静态分析

    functions = [func for func in json.loads(r2.cmd("aflj"))]#获得函数列表以josn格式返回
    controlFunctions['add']=[]
    controlFunctions['del']=[]
    controlFunctions['edit']=[]
    controlFunctions['show']=[]
    for func in  functions:
        for add in addlists:
            if add in str(func["name"]):
               
                controlFunctions['add'].append({func["name"],hex(func["offset"])})
        for delete in dellists:
            if delete in str(func['name']):
                
                controlFunctions['del'].append({func["name"],hex(func["offset"])})
        for edit in editlists:
            if edit in str(func["name"]):
                
                controlFunctions['edit'].append({func["name"],hex(func["offset"])})
        for show in showlists:
            if show in str(func['name']):
                
                print(func['name'])
                controlFunctions['show'].append({func["name"],hex(func["offset"])})
    return controlFunctions

if __name__ =="__main__":
    target_front_path = "/home/yld/target_program/"
    target = target_front_path+"/user_after_free/hitconTraining_uaf/hacknote"
    '''
     sym.add_note
     sym.print_note
     sym.del_note
    '''
    #target = target_front_path+"/heapoverflow_unlink_attack/hitconTraining_magicheap/magicheap"
    '''
     sym.create_heap
     sym.delete_heap
     sym.edit_heap
    '''
    #target = target_front_path+"/heapoverflow_unlink_attack/hitconTraining_bamboobox/bamboobox";
    '''
    sym.add_item
    sym.change_item
    sym.remove_item
    sym.show_item
    '''
    #target = target_front_path+"/heapoverflow_unlink_attack/hitconTraining_unlink/bamboobox";
    #target = target_front_path+"/doublefree/0CTF2015_freenote/freenote_x64";
    propertis = getProperties(target)
    vulnFunctions={}
    controlFunctions={}
    # print(propertis)
    if(propertis['pie']):
        log.info("开启了PIE不能进一步分析")
    else:
        vulnFunctions=getVulnFunc(target)
        controlFunctions=getControlFunc(target)
    log.info("分析完成")
    if vulnFunctions=={}:
        log.info("没有可以直接劫持的敏感函数")
    else:
        log.info("有直接劫持的敏感函数")
    if controlFunctions=={}:
        log.info("需要人工制定指定敏感操作模板文件")
    else:
        log.info(controlFunctions)

    #下一步explore探索，找到轨迹，记录基本块
    #下一步约束内容
    #dump输入
    #定位s address
    #pdj json格式汇编代码
    #缺陷分析代码暂时不写，使用人工指定
    #后面使用fuzzing或者其他技术进行分析

