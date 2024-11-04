# -*- encoding: utf-8

import argparse, os, sys
from arch import Arch
from arch.arml import ArmLArch
from arch.armlt import ArmLTArch
from lib.misc.logger import Logger
from lib import Binary, Cache, Func
from typing import Dict, List, TextIO
from config.constant import ARCH_ARML, ARCH_ARML_THUMB, RT_HAS_RET, RT_NO_RET, RT_NONE


class TaiE:
    '''
    程序分析类
    '''
    
    # 日志记录
    logger:Logger = Logger('TaiE')

    # 指令集架构与对应执行器的映射关系
    arch2analyzer:Dict[int, Arch] = {
        ARCH_ARML: ArmLArch,
        ARCH_ARML_THUMB: ArmLTArch
    }

    @classmethod
    def funcs_in(cls, bin:Binary, tag:str='') -> List[Func]:
        '''
        二进制中的函数清单
        '''
        # 选择对应的分析器
        arch:Arch = cls.arch2analyzer[bin.arch]
        # 清理缓存
        Cache.clear()
        # 获取分析结果
        return arch.funcs_in(bin, tag=tag)
    
    @classmethod
    def funcs_of(cls, file:str, arch:int, text_base:int=-1, data_base:int=-1, tag:str='') -> List[Func]:
        '''
        文件中的函数清单
        '''
        # 构造相应的二进制文件
        bin:Binary = Binary(file, arch, text_base=text_base, data_base=data_base)
        # 获取函数分析结果
        return cls.funcs_in(bin, tag=tag)


if __name__ == '__main__':
    argparser:argparse.ArgumentParser = argparse.ArgumentParser()
    argparser.add_argument('file', 
                            help='The path of the file to be anyalyzed.')
    argparser.add_argument('-a', '--arch', 
                            choices=['arml', 'armlt'], 
                            default='arml',
                            help='The instruction set architectue of the target file.')
    argparser.add_argument('-tb', '--text_base', type=int,
                            default=-1,
                            help='The base address of the .text segment.')
    argparser.add_argument('-db', '--data_base', type=int,
                            default=-1, 
                            help='The base address of the .data segment.')
    argparser.add_argument('-o', '--output',
                            default='',
                            help='The path of the file used for saving the results.')
    argparser.add_argument('-l', '--level', 
                            choices=['i', 'w', 'e', 'd', 'n'],
                            default='i',
                            help='Logging level.')
    logger:Logger = Logger('MAIN')
    # 解析参数
    args:argparse.Namespace = argparser.parse_args()
    # 检查文件存在与否
    if not os.path.isfile(args.file): 
        logger.error(f'File {args.file} not found.')
        exit(1)
    # 获取指令集
    arch:int = [ARCH_ARML, ARCH_ARML_THUMB][['arml', 'armlt'].index(args.arch)]
    # 日志输出等级
    log_level:int = logger.set_global_level([Logger.L_INFO, Logger.L_WARN, Logger.L_ERROR, Logger.L_DEBUG, Logger.L_NONE]['iwedn'.index(args.level)])
    tag:str = f'.{args.tag}' if len(args.tag) > 0 and not args.tag.startswith('.') else args.tag
    size:int = os.path.getsize(args.file)
    # 切
    funcs:List[Func] = TaiE.funcs_of(args.file, arch, args.text_base, args.data_base, tag=tag)
    # 排个序
    funcs.sort(key=lambda f:f.head)
    output:TextIO = sys.stdout
    # 如果设置了输出文件 则输出至文件中 否则直接打印
    if len(args.output.strip()) > 0: output = open(args.output, 'w')
    # 输出结果
    output.write(f'#, Head, Tail, Identified By, Has Return\n')
    for i in range(len(funcs)): output.write(f'{i}, {hex(funcs[i].head)}, {hex(funcs[i].tail)}, {["None", "Callee", "Callee In Callsite", "Scanned From Tail", "Others"][funcs[i].identified_by]}, {["?", "√", "x"][[RT_NONE, RT_HAS_RET, RT_NO_RET].index(funcs[i].return_type)]}\n')
    if len(args.output.strip()) > 0: output.close()

