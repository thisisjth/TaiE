#!python3.9
# -*- encoding: utf-8 -*-

__VERSION__:str = '0315'

# 函数返回值类型 
# 不确定
RT_NONE:int   = 0
# 有返回值
RT_HAS_RET:int= 1
# 无返回值
RT_NO_RET:int = 2

# 函数识别来源
# 不确定
IB_NONE:int   = 0
# 被调函数
IB_CALLEE:int = 1
# callsite里的被调用函数
IB_CALLEE_IN_CALLSITE:int = 2
# 从上一个函数尾部开始扫描获得
IB_SCANED_FROM_TAIL:int = 3
# 其他来源
IB_OTHER:int  = 4

# 指令集架构类型
ARCH_ARML:int       = 3
ARCH_ARML_THUMB:int = 8

# 栈特性满足情况
STACK_UNSATISFIED:int   = 0
STACK_SATISFIED:int     = 1
STACK_UNINITIALIZED:int = 2

# 函数的执行路径上对无返回函数的调用情况
# 所有执行路径上都没有调用无返回函数
CT_NONE:int = 0
# 有的调用了有的没有
CT_PART:int = 1
# 所有执行路径上都调用了无返回函数
CT_ALL:int = 2
