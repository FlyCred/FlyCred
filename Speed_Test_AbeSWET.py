'''
:Date:            1/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP
from AbeSWET import AbeSWET
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

def create_list_and_policy(n_1, n_2):
    
    word_list = wordList_prep(n_1)
    
    kw_list, attr_list = [], []
    for i in word_list:
        kw = i
        attr = i
        kw = kw + ':' + str(random.choice(range(1, 10)))
        kw_list.append(kw)
        attr_list.append(attr)

    choice = [' and ', ' or ']
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

def measure_average_times_abeswet(abeswet, m, T, attr_list, attr_policy, n_1, n_2, N):   
    
    sum_Setup=0
    sum_KeyGen=0
    sum_Sign=0
    sum_Vfy=0
    sum_Enc=0
    sum_Dec=0


    for i in range(N):       
        # sum_Setup time
        start_setup = time.time()
        pp = abeswet.Setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_Setup += time_setup
        

        # KeyGen time
        start_setup = time.time()
        (ssk, spk) =  abeswet.KeyGen(pp)
        end_setup = time.time()
        time_KeyGen = end_setup-start_setup
        sum_KeyGen += time_KeyGen

        # Sign time
        start_setup = time.time()
        dlt = abeswet.Sign(pp, ssk, spk, T, attr_list)
        end_setup = time.time()
        time_Sign = end_setup-start_setup
        sum_Sign += time_Sign

        # Vfy time
        start_setup = time.time()
        (ret1, ret2) = abeswet.Vfy(pp, spk, dlt)
        end_setup = time.time()
        time_Vfy = end_setup-start_setup
        sum_Vfy += time_Vfy

        # Enc time
        start_setup = time.time()
        ct = abeswet.Enc(pp, spk, m, T, attr_policy)
        end_setup = time.time()
        time_Enc = end_setup-start_setup
        sum_Enc += time_Enc

        # Dec time
        start_setup = time.time()
        (m1, ret) = abeswet.Dec(pp, ct, dlt)
        end_setup = time.time()
        time_Dec = end_setup-start_setup
        sum_Dec += time_Dec

        if m != m1:
            print("Dec failed for {}!".format(abeswet.name))
    
    print('Size of (pp) = {}'.format(len(str(pp))))
    print('Size of (ssk) = {}'.format(len(str(ssk))))
    print('Size of (spk) = {}'.format(len(str(spk))))
    print('Size of (T) = {}'.format(len(str(T))))
    print('Size of (m) = {}'.format(len(str(m))))
    print('Size of (attr_list) = {}'.format(len(str(attr_list))))
    print('Size of (dlt) = {}'.format(len(str(dlt))))
    print('Size of (attr_policy) = {}'.format(len(str(attr_policy))))
    print('Size of (ct) = {}'.format(len(str(ct))))

        
    sum_Setup = sum_Setup/N
    sum_KeyGen = sum_KeyGen/N
    sum_Sign = sum_Sign/N
    sum_Vfy = sum_Vfy/N
    sum_Enc = sum_Enc/N
    sum_Dec = sum_Dec/N

    
    print('Running times (ms) curve: \nsum_Setup={} \nsum_KeyGen={}  \nsum_Sign={}  \nsum_Vfy={} \nsum_Enc={} \nsum_Dec={}\n'.format(sum_Setup*1000, sum_KeyGen*1000, sum_Sign*1000, sum_Vfy*1000, sum_Enc*1000, sum_Dec*1000))
    

        
def main():

    sum_e1=0
    sum_e2=0
    sum_et=0
    sum_ep=0
    N=20
    n_1 = 10
    n_2 = 5
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

   
    attr_list, attr_policy = create_list_and_policy(n_1, n_2)
    T = pairing_group.random(ZR)
    m = pairing_group.random(ZR)
    abeswet = AbeSWET(pairing_group)
    
    measure_average_times_abeswet(abeswet, m, T, attr_list, attr_policy, n_1, n_2, N)   

    return    
      
if __name__ == "__main__":
    debug = True
    main()                 
           
