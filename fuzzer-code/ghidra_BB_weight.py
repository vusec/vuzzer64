#TODO This script performs the static analysis part of VUzzer. For a given binary, it computes a weight of each basic block of each function. It also extracts immediates from each CMP instruction.
#@author: Sanjay Rawat 
#@category: VUzzer Static Analysis
#@keybinding 
#@menupath tools.Static Analysis.VUzzer
#@toolbar 


#TODO Add User Code Here
#from ghidra.program.model.block import *
#from ghidra.program.model.listing import * 
import ghidra.program.model.block as BL
from ghidra.program.model.lang.OperandType import SCALAR, REGISTER
from collections import deque
import timeit
import sys
import struct
import pickle
import os
import gc
## global variables ##
backedges=list()# list of the backedges, preseorented as tuple (srcBB,dstBB)
#edges=dict() # dictionary to keep edges weights key=(srcBB,destBB), value=weight
weights=dict() # dictionary to keep weights of the BBs. key=BBaddress, value=weight. Weight is calculated as w=1.0/reaching prob.
#where reaching prob(B) = Sum_i \in Pred(B){ weight_edge(i,B)*weight(i)}
# All of the backedges have 0 weights, i.e. they have no influence on the weight of the target BB.
uncovered_edges=0
sbm=BL.BasicBlockModel(currentProgram)
image_base=currentProgram.getImageBase().getOffset()
def dead(msg):
    printf("[*] %s\n", msg)
    sys.exit(0)


def getWeight(function):
    ''' This function computes the weight of each edge in the CFG of a function. As input, it takes the iterator for the BB corresponding to a CFG.
    It returns a dictionary, where the key is the edge, repreentated as (srcBB,DstBB) and th e value is the weight. For a given BB, the weight is computed as 1.0/out_degree of BB. 
    
    Note: Ghidra memory model creates references for the edges. In doing so, it creates references for CALL also, which means that if we use getDestinations() or getSources(), we also get edges
    corresponding to calls and indirection (jumping to jumptable e.g.). In particular, within a function, even if we try to get the incoming edges for root node, we get references to all the callers
    that call this fuunction. So, we neglect such calls by using getFlowType().isCall() and getFlowType().isIndirect().


    '''
    weight=dict()
    block_weight=dict()
    total=0 #counts the total blocks in this function
    BBIterator=sbm.getCodeBlocksContaining(function.getBody(),monitor)
    #edges=list()
    while BBIterator.hasNext():
        block=BBIterator.next()
        total = total+1
        #print "BB: 0x%x" % block.getFirstStartAddress().getOffset()
        blk_adr=block.getFirstStartAddress().getOffset()
        block_weight[block.getFirstStartAddress().getOffset()]=0.0
        dest=block.getDestinations(monitor)
        count=0
        edges=list()
        #edges.clear()
	while (dest.hasNext()):
	    dbb = dest.next();
            if dbb.getFlowType().isCall()== True or dbb.getFlowType().isIndirect()==True:
                continue
            count= count+1
            dst_address= dbb.getDestinationAddress().getOffset()
            edges.append((block.getFirstStartAddress().getOffset(), dst_address))
        if count ==0:
            continue
        for ed in edges:
            weight[ed]=1.0/count
        del edges
    # Ghidra has something weird. For very exceptional cases, it so happen that if we iterate all codeblocks, few BBs are missed. Thus, if we get parents of each block, we get reference from a block which is not searchable in the earlier case. So, we have check explicitely for such cases. thus the code below:
    BBIterator=sbm.getCodeBlocksContaining(function.getBody(),monitor)
    while BBIterator.hasNext():
        block=BBIterator.next()
        src_blocks=block.getSources(monitor)
        while src_blocks.hasNext():
            sbb=src_blocks.next()
            if sbb.getFlowType().isCall() == True or sbb.getFlowType().isIndirect()== True or sbb.getFlowType().isTerminal()== True:
                continue
            sbba=sbb.getSourceAddress().getOffset()
            if sbba not in block_weight:
                block_weight[sbba]=1.0
                weight[(sbba,block.getFirstStartAddress().getOffset())]=1.0


    return weight, block_weight, total
 

#
def getBBScore(function):
    '''
    This function computes reachability score for the each BB in a given function. It uses a fix-point iteration to do so.
    for the given BB, it gets its parents and computes a score as sum(w*i), where w is weight of the parents and i is the weight of the corresponding edge.

    '''
    blocks=sbm.getCodeBlocksContaining(function.getBody(),monitor)
    global uncovered_edges   
    root=function.getEntryPoint().getOffset()
    fun_name=function.getName()
    eweight,bweight, total_bb=getWeight(function)
    if getLength(function) != total_bb:
        println( getLength(function) +', ' +total_bb)
        dead("not equal BBs!")
    bweight[function.getEntryPoint().getOffset()]=1.0 #asigne a weight 1.0 to the root node of the function.
    fixed_point=False
    #blocks=sbm.getCodeBlocksContaining(function.getBody(),monitor)# we get the BB iterator again to start our fixed point computation
    bb_done=list()#this list keeps track of BBs who have already got to the fix point.
    # in order to deal with the loop (in the presence of lop, the fixed point iteration will keep on going), we use the following heuristic:
    # the root node is assumed to have achieved fixed point (its value does not change). Any node whose value gets updated once is registered. A node whose all parents have got registered
    #is said to have got fixed point.
    fixed_done=list()
    fixed_done.append(root)

    bb_done.append(root)# we can assume that root node is in fixed point state
    loop_count=0
    while(fixed_point==False):
        #printf( "## Iter: %d - %s\n",loop_count, fun_name)
        monitor.checkCanceled()
        prev_weight=bweight.copy()
        loop_count +=1
        count=0
        blocks=sbm.getCodeBlocksContaining(function.getBody(),monitor)# we get the BB iterator again to start our fixed point computation
        while blocks.hasNext():
            #print "Count: ", count
            bb=blocks.next()
            bba=bb.getFirstStartAddress().getOffset()
            #printf("BB: 0x%x\n",bba)
            if bba in fixed_done:
                count +=1
                continue
            src_blocks=bb.getSources(monitor)
            temp=0
            tcount=0
            fixed_count=0
            while src_blocks.hasNext():
                sbb=src_blocks.next()
                if sbb.getFlowType().isCall() == True or sbb.getFlowType().isIndirect()== True:# or sbb.getFlowType().isTerminal()== True:
                    continue
                sbba=sbb.getSourceAddress().getOffset()
                tcount +=1
                if sbba in bb_done:
                    fixed_count += 1
                #print "\t[*] 0x%x type: %s" % (sbba,sbb.getFlowType().getName())
                # there seems to be a bug in Ghidra due to which certain edges are disappeared (Yes, it is really strange!). We have to manually insert such edges with a default weight 0.5.
                try:
                    temp= temp + (bweight[sbba] * eweight[(sbba,bba)])
                except KeyError:
                    uncovered_edges +=1
                    temp= temp + (bweight[sbba] * 0.5)
                #if (sbba,bba) not in eweight:
                    # there seems to be a bug in Ghidra due to which certain edges are disappeared (Yes, it is really strange!). We have to manually insert such edges with a default weight 0.5.
                    #uncovered_edges +=1
                    #eweight[(sbba,bba)=0.5
                #temp= temp + (bweight[sbba] * eweight[(sbba,bba)])
            #print "src: %d, src_done: %d"%(tcount,fixed_count)
            #printf("src: %d, src_done: %d\n",tcount,fixed_count)		 
            if tcount == fixed_count:
                fixed_done.append(bba)
                #count += 1
            if temp < prev_weight[bba]:
                # we are checking for monotonicity of the iteration. the weight should increase or remain same on each iteration.
                dead("Monotonicity failes!")
            if temp != prev_weight[bba]:
                #count += 1
                #print "updated 0x%x"%bba
                #printf("updated 0x%x\n",bba)
                bb_done.append(bba)
            bweight[bba]=temp
            #print "Count: %d/%d - %d"% (count,total_bb, loop_count) 
        if count == total_bb or loop_count > total_bb:
            fixed_point= True
    return bweight


def getLength(function):
    '''
    given a function, the function returns the number of basic blocks in it.
    
    '''
    count=0
    blocks=sbm.getCodeBlocksContaining(function.getBody(), monitor)
    while (blocks.hasNext()):
        bb = blocks.next();
	count +=1
    return count



def getCMPData(function):
    '''
    Given a function as input, this function iterates over its insturctions and extract the immediate values from CMP instructions.

    '''
    result_full=set()# contains the strings found as opearnd to CMP
    result_bytes=set()# contains individual bytes from the strings found above.
    result_short=set() # contains strings found in result_full, after truncating initial zeros.
    instIterator = currentProgram.getListing().getInstructions(function.getBody(), True)
    while instIterator.hasNext():
        monitor.checkCanceled()
        inst=instIterator.next()
        if inst.getMnemonicString()=='CMP':
            
            #print "%s- Label: %s"%(inst.getLabel(), inst.getMinAddress().toString())
            #print "Label: %s"%inst.getLabel()
            #ops=inst.getNumOperands()
            
            if (inst.getOperandType(1) & SCALAR) != 0:
                if (inst.getOperandType(0) & REGISTER) != 0:
                    if inst.getScalar(1).isSigned():
                        continue
                    #print "%s- Label: %s"%(inst.getLabel(), inst.getMinAddress().toString())
                    #print "Opnd val: %s"%inst.getScalar(1).toString()
                    bit_len=inst.getRegister(0).getBitLength()
                    #print "@@ len %d"%bit_len
                    if bit_len ==8:
                        result_full.add(struct.pack('>B',inst.getScalar(1).getValue()))
                    elif bit_len == 16:
                        result_full.add(struct.pack('>H',inst.getScalar(1).getValue()))
                    elif bit_len == 32:
                        result_full.add(struct.pack('>I',inst.getScalar(1).getValue()))
                    elif bit_len == 64:
                        result_full.add(struct.pack('>Q',inst.getScalar(1).getValue()))
                    else:
                        pass

    for st in result_full:
        result_short.add(st.lstrip('\x00'))
    for ele in result_short:
        for ch in ele:
            result_bytes.add(ch)
    #result_full.update(names)
    del result_full
    return [result_short, result_bytes]

def main():
    ''' main function
    '''
    gc.enable()
    start=timeit.default_timer()
    clist=currentProgram.getListing()
    fweight=dict()
    print "started analysis..."
    func_manager=currentProgram.getFunctionManager()
    str_full=set()# set of the strings appearing in CMP instructions
    str_bytes=set() # set of individual bytes of the strings in the above set
    bb_weight=dict()
    total_bb=0 #total number of BBs analyzed
    total_func=0 # total number of functions analyzed
    global uncovered_edges


    #let's iterate over all the functions
    func_iter=clist.getFunctions(True)
    while (func_iter.hasNext() and monitor.isCancelled() != True):
        function=func_iter.next()
        if function.isThunk()==True or function.isExternal()==True:
            continue
        bb_count=getLength(function)
        if bb_count <= 1:
            continue
        total_bb= total_bb + bb_count
        total_func += 1
        #print "In: %s"%function.getName()
        #printf("In: %s\n",function.getName())        
        root=function.getEntryPoint().getOffset()
        
        temp=getCMPData(function)
        str_full.update(temp[0])
        str_bytes.update(temp[1])

        bb_weight.update(getBBScore(function))
        #print "[*] done...."
        for bb in bb_weight:
            #print "BB: 0x%x - %3.2f"%(bb-image_base, 1.0/bb_weight[bb])
            #printf("BB: 0x%x - %3.2f\n", (bb-image_base), 1.0/bb_weight[bb])            
            fweight[bb-image_base]=(1.0/bb_weight[bb], root)
            # the 'root' is added for the compatibility purpose. it has no value as such.
    str_final=[str_full, str_bytes]
    path,file_name=os.path.split(currentProgram.getExecutablePath())
    str_file=file_name + '.names'
    bb_file=file_name + '.pkl'
    str_path=os.path.join(path,str_file)
    bb_path=os.path.join(path,bb_file)
    str_fd=open(str_path, 'w')
    pickle.dump(str_final,str_fd)
    str_fd.close()
    bb_fd=open(bb_path,'w')
    pickle.dump(fweight,bb_fd)
    bb_fd.close()

    stop=timeit.default_timer()
    printf("[*] Total time: %5.5f", stop-start)
    printf("total functions analysed: %d\n total Basic blocks analysed: %d\n total uncovered edges added: %d\n", total_func,total_bb,uncovered_edges)    
    #print "[*] Total time: ", stop-start
    #print " total functions analysed: %d"% total_func
    #print " total Basic blocks analysed: %d"% total_bb

if __name__ =="__main__":
    main()
