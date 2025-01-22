'''
:Date:            1/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP
from AAC import AAC
import re, random, copy
import time
#---------------------------------------------------------------


def wordList_prep(num_words):
    f = open('./words.txt','r')
    lines = f.readlines()
    
    word_list = []
    i = 0
    indices = random.sample(range(1, 466466), num_words)
    for i in indices:
        word = lines[i]
        word = word.split('\n')[0]
        word = word.replace("'", "")
        word = word.replace("-", "")
        word_list.append(word.upper())
    f.close()
    return word_list

def create_user_attrs_list(n):
    
    word_list = wordList_prep(n)
    
    attr_list = []
    for i in word_list:
        attr = i
        attr_list.append(attr)
    return attr_list    

def measure_average_times_aac(aac, attr_list, n ,N):   
    
    sum_Setup=0
    sum_IKeyGen=0
    sum_CredReq=0
    sum_WSGen=0
    sum_pIssue=0
    sum_pCredVfy=0
    sum_Adaptor=0
    sum_Ext=0
    sum_CredVfy=0
    sum_Show=0
    sum_TokVfy=0

    for i in range(N):       
        # sum_Setup time
        start_setup = time.time()
        pp =  aac.Setup(n)        
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_Setup += time_setup
        

        # sum_IKeyGen time
        start_setup = time.time()
        (isk, ipk) = aac.IKeyGen(pp)
        end_setup = time.time()
        time_IKeyGen = end_setup-start_setup
        sum_IKeyGen += time_IKeyGen

        # sum_CredReq time
        start_setup = time.time()
        (usk, upk, req, ret) = aac.CredReq(pp, attr_list)
        end_setup = time.time()
        time_CredReq = end_setup-start_setup
        sum_CredReq += time_CredReq

        # sum_WSGen time
        start_setup = time.time()
        (wit, stm) = aac.WSGen(pp)
        end_setup = time.time()
        time_WSGen = end_setup-start_setup
        sum_WSGen += time_WSGen

        # pIssue time
        start_setup = time.time()
        (pcred, ret1, ret2) = aac.pIssue(pp, isk, ipk, stm, req)
        end_setup = time.time()
        time_pIssue = end_setup-start_setup
        sum_pIssue += time_pIssue

        # pCredVfy time
        start_setup = time.time()
        (ret1, ret2, ret3) = aac.pCredVfy(pp, ipk, usk, upk, pcred)
        end_setup = time.time()
        time_pCredVfy = end_setup-start_setup
        sum_pCredVfy += time_pCredVfy

        # Adaptor time
        start_setup = time.time()
        cred = aac.Adaptor(pp, pcred, wit)
        end_setup = time.time()
        time_Adaptor = end_setup-start_setup
        sum_Adaptor += time_Adaptor
        
        # Ext time
        start_setup = time.time()
        (wit, ret) = aac.Ext(pp, pcred, cred)
        end_setup = time.time()
        time_Ext = end_setup-start_setup
        sum_Ext += time_Ext
        
        # CredVfy time
        start_setup = time.time()
        (ret1, ret2 ) = aac.CredVfy(pp, ipk, usk, upk, cred)
        end_setup = time.time()
        time_CredVfy = end_setup-start_setup
        sum_CredVfy += time_CredVfy
        
        # Show time
        start_setup = time.time()
        (tok, ctx) = aac.Show(pp, ipk, usk, upk, cred)
        end_setup = time.time()
        time_Show = end_setup-start_setup
        sum_Show += time_Show
        
        # TokVfy time
        start_setup = time.time()
        (ret1, ret2) = aac.TokVfy(pp, ipk, tok, ctx)
        end_setup = time.time()
        time_TokVfy = end_setup-start_setup
        sum_TokVfy += time_TokVfy
    
    print('Size of (pp) = {}'.format(len(str(pp))))
    print('Size of (isk) = {}'.format(len(str(isk))))
    print('Size of (ipk) = {}'.format(len(str(ipk))))
    print('Size of (usk) = {}'.format(len(str(usk))))
    print('Size of (upk) = {}'.format(len(str(upk))))
    print('Size of (req) = {}'.format(len(str(req))))
    print('Size of (wit) = {}'.format(len(str(wit))))
    print('Size of (stm) = {}'.format(len(str(stm))))
    print('Size of (pcred) = {}'.format(len(str(pcred))))
    print('Size of (cred) = {}'.format(len(str(cred))))
    print('Size of (tok) = {}'.format(len(str(tok))))
        
    sum_Setup = sum_Setup/N
    sum_IKeyGen = sum_IKeyGen/N
    sum_CredReq = sum_CredReq/N
    sum_WSGen = sum_WSGen/N
    sum_pIssue = sum_pIssue/N
    sum_pCredVfy = sum_pCredVfy/N
    sum_Adaptor = sum_Adaptor/N
    sum_Ext = sum_Ext/N
    sum_CredVfy = sum_CredVfy/N
    sum_Show = sum_Show/N
    sum_TokVfy = sum_TokVfy/N
    
    print('Running times (ms) curve: \nsum_Setup={} \nsum_IKeyGen={}  \nsum_CredReq={}  \nsum_WSGen={} \nsum_pIssue={} \nsum_pCredVfy={} \nsum_Adaptor={} \n sum_Ext={}\nsum_CredVfy={} \nsum_Show={}  \nsum_TokVfy={}\n'.format(sum_Setup*1000, sum_IKeyGen*1000, sum_CredReq*1000, sum_WSGen*1000, sum_pIssue*1000, sum_pCredVfy*1000, sum_Adaptor*1000, sum_Ext*1000, sum_CredVfy*1000, sum_Show*1000, sum_TokVfy*1000))
    

        
def main():

    sum_e1=0
    sum_e2=0
    sum_et=0
    sum_ep=0
    N=20
    n = 10
    # instantiate a bilinear pairing map
    curve = 'BN254' #MNT159, MNT201, BN254
    pairing_group = PairingGroup(curve)
    print('Test Curve: {}'.format(curve))
    

    for i in range(N):
        # e1 time
        r1 = pairing_group.random(ZR)
        g1 = pairing_group.random(G1)
        start_setup = time.time()
        R1 = g1 ** r1
        end_setup = time.time()
        time_e1 = end_setup-start_setup
        sum_e1 = sum_e1 + time_e1
        # e2 time
        r2 = pairing_group.random(ZR)
        g2 = pairing_group.random(G2)
        start_setup = time.time()
        R2 = g2 ** r2
        end_setup = time.time()
        time_e2 = end_setup-start_setup
        sum_e2 = sum_e2 + time_e2
        # eT time
        rt = pairing_group.random(ZR)
        gt = pairing_group.random(GT)
        start_setup = time.time()
        RT = gt ** rt
        end_setup = time.time()
        time_et = end_setup-start_setup
        sum_et = sum_et + time_et

        # ep time        
        start_setup = time.time()
        gp = pair(g1,g2)
        end_setup = time.time()
        time_ep = end_setup-start_setup
        sum_ep = sum_ep + time_ep
    time_e1 = sum_e1/N
    time_e2 = sum_e2/N
    time_et = sum_et/N
    time_ep = sum_ep/N

    print('Running times (ms) curve: \ne1={}  \ne2={}  \net={}  \nep={}'.format(time_e1*1000, time_e2*1000, time_et*1000, time_ep*1000))

   
    attr_list = create_user_attrs_list(n)
    aac = AAC(pairing_group)
    
    measure_average_times_aac(aac, attr_list, n, N)   

    return    
      
if __name__ == "__main__":
    debug = True
    main()                 
           
