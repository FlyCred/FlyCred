'''
:Date:            1/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP
from FlyCred import FlyCred
import re, random, copy
import time, math
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

def create_list_and_policy(n_1, n_2):
    
    word_list = wordList_prep(n_1)
    
    kw_list, attr_list = [], []
    for i in word_list:
        kw = i
        attr = i
        kw = kw + ':' + str(random.choice(range(1, 10)))
        kw_list.append(kw)
        attr_list.append(attr)

    choice = [' and ']
    indices = random.sample(range(len(word_list)), n_2)
     
    kw_policy, attr_policy = '', '' 
    for i, num in enumerate(indices):
        policy_name = word_list[num]        
        k = random.choice(choice)    
        
        if i in range(len(indices) - 1):  
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 10))) + '' + k + ''
            attr_policy = attr_policy + policy_name + k + ''
        else:       
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 10)))
            attr_policy = attr_policy + policy_name

    return attr_list, attr_policy  

def create_user_attrs_list(n):
    
    word_list = wordList_prep(n)
    
    attr_list = []
    for i in word_list:
        attr = i
        attr_list.append(attr)
    return attr_list     

def measure_average_times_flycred(flycred, n , n_1, n_2, B ,N):   
    
    sum_Setup=0
    sum_IKeyGen=0
    sum_OKeyGen=0
    sum_CredReq=0
    sum_EncIss=0
    sum_EncVfy=0
    sum_Sign=0
    sum_DecCred=0
    sum_Show=0
    sum_TokVfy=0
    
    attr_list = create_user_attrs_list(n)
    
    (T_vec, F_o) = create_list_and_policy(n_1, n_2)
    
    F_e_list = {} 
    et_vec_list = {}
    for i in range(n_1):
        (et_vec_list[i], F_e_list[i]) = create_list_and_policy(n_1, n_2)
        
        
    opk_list = {}
    osk_list = {}   

    for i in range(N):       
        # sum_Setup time
        start_setup = time.time()
        pp = flycred.Setup(n, B, n_1, n_2)      
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_Setup += time_setup
        

        # sum_IKeyGen time        
        start_setup = time.time()
        (isk, ipk) = flycred.IKeyGen(pp)
        end_setup = time.time()
        time_IKeyGen = end_setup-start_setup
        sum_IKeyGen += time_IKeyGen

        # OKeyGen time
        for j in range(n_1):
            (osk_list[j], opk_list[j]) = flycred.OKeyGen(pp)
        start_setup = time.time()
        (osk_list[j], opk_list[j]) = flycred.OKeyGen(pp)
        end_setup = time.time()
        time_OKeyGen = end_setup-start_setup
        sum_OKeyGen += time_OKeyGen

        # sum_CredReq time
        start_setup = time.time()
        (usk, upk, req, ret) = flycred.CredReq(pp, attr_list)
        end_setup = time.time()
        time_CredReq = end_setup-start_setup
        sum_CredReq += time_CredReq

        # EncIss time
        start_setup = time.time()
        cct = flycred.EncIss(pp, isk, ipk, req, F_o, T_vec, F_e_list, opk_list)
        end_setup = time.time()
        time_EncIss = end_setup-start_setup
        sum_EncIss += time_EncIss

        # EncVfy time
        start_setup = time.time()
        flycred.EncVfy(pp, ipk, usk, upk, cct)
        end_setup = time.time()
        time_EncVfy = end_setup-start_setup
        sum_EncVfy += time_EncVfy

        # Sign time
        dlt_list = {}
        for j in range(n_1):
            dlt_list[j] = flycred.Sign(pp, osk_list[j], opk_list[j], T_vec[j], et_vec_list[j])
        start_setup = time.time()
        dlt_list[j] = flycred.Sign(pp, osk_list[j], opk_list[j], T_vec[j], et_vec_list[j])
        end_setup = time.time()
        time_Sign = end_setup-start_setup
        sum_Sign += time_Sign
        
        # DecCred time
        start_setup = time.time()
        cred, ret11, ret12, ret21, ret31, ret41, ret42 = flycred.DecCred(pp, ipk, usk, upk, cct, opk_list, T_vec, et_vec_list, dlt_list)
        end_setup = time.time()
        time_DecCred = end_setup-start_setup
        sum_DecCred += time_DecCred
        
        
        # Show time
        start_setup = time.time()
        tok, ctx = flycred.Show(pp, ipk, usk, upk, cred)
        end_setup = time.time()
        time_Show = end_setup-start_setup
        sum_Show += time_Show
        
        # TokVfy time
        start_setup = time.time()
        ret1, ret2 = flycred.TokVfy(pp, ipk, tok, ctx)
        end_setup = time.time()
        time_TokVfy = end_setup-start_setup
        sum_TokVfy += time_TokVfy
    
    print('Size of (pp) = {}'.format(len(str(pp))))
    print('Size of (attr_list) = {}'.format(len(str(attr_list))))
    print('Size of (T_vec) = {}'.format(len(str(T_vec))))
    print('Size of (F_o) = {}'.format(len(str(F_o))))
    print('Size of (isk) = {}'.format(len(str(isk))))
    print('Size of (ipk) = {}'.format(len(str(ipk))))
    print('Size of (osk) = {}'.format(len(str(osk_list[0]))))
    print('Size of (opk) = {}'.format(len(str(opk_list[0]))))
    print('Size of (usk) = {}'.format(len(str(usk))))
    print('Size of (upk) = {}'.format(len(str(upk))))
    print('Size of (req) = {}'.format(len(str(req))))
    print('Size of (cct) = {}'.format(len(str(cct))))
    print('Size of (dlt) = {}'.format(len(str(dlt_list[0]))))
    print('Size of (cred) = {}'.format(len(str(cred))))
    print('Size of (tok) = {}'.format(len(str(tok))))
        
    sum_Setup = sum_Setup/N
    sum_IKeyGen = sum_IKeyGen/N
    sum_OKeyGen = sum_OKeyGen/N
    sum_CredReq = sum_CredReq/N
    sum_EncIss = sum_EncIss/N
    sum_EncVfy = sum_EncVfy/N
    sum_DecCred = sum_DecCred/N
    sum_Show = sum_Show/N
    sum_TokVfy = sum_TokVfy/N
    
    print('Running times (ms) curve: \nsum_Setup={} \nsum_IKeyGen={}  \nsum_OKeyGen={}  \nsum_CredReq={} \nsum_EncIss={} \nsum_EncVfy={} \nsum_DecCred={} \nsum_Show={}  \nsum_TokVfy={}\n'.format(sum_Setup*1000, sum_IKeyGen*1000, sum_OKeyGen*1000, sum_CredReq*1000, sum_EncIss*1000, sum_EncVfy*1000, sum_DecCred*1000, sum_Show*1000, sum_TokVfy*1000))
    

        
def main():

    sum_e1 = 0
    sum_e2 = 0
    sum_et = 0
    sum_ep = 0
    N = 20
    n = 10       
    n_1 = 17
    n_2 = 17
    curve = 'BN254' #MNT159, MNT201, BN254
    lamda= 100 
    B = lamda/(math.log(n_1)+1)
    B =  math.ceil(B)
    print('Security Level = {} bit, B = {}'.format(lamda, B))
    # instantiate a bilinear pairing map
    
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


    flycred = FlyCred(pairing_group)
       
    
    
    measure_average_times_flycred(flycred, n, n_1, n_2, B, 1)   

    return    
      
if __name__ == "__main__":
    debug = True
    main()                 
           
