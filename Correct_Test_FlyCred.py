'''
:Date:            1/2025
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser
import time, math
from FlyCred import FlyCred


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

    #choice = [' and ', ' or ']
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
         
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254') #BN256  MNT224
    flycred = FlyCred(pairing_group)
       
    n = 5       
    n_1 = 5
    n_2 = 5
    B = 100/(math.log(n_1)+1)
    B =  math.ceil(B)
    print('B= {}'.format(B))

    attr_list = create_user_attrs_list(n)
    
    (T_vec, F_o) = create_list_and_policy(n_1, n_2)
    # print("T_vec= {}".format(T_vec))
    # print("F_o= {}".format(F_o))

    
    F_e_list = {} 
    et_vec_list = {}
    for i in range(n_1):
        (et_vec_list[i], F_e_list[i]) = create_list_and_policy(n_1, n_2)
        
        
    opk_list = {}
    osk_list = {}   
    pp = flycred.Setup(n, B, n_1, n_2)
    (isk, ipk) = flycred.IKeyGen(pp)
    
    for i in range(n_1):
        (osk_list[i], opk_list[i]) = flycred.OKeyGen(pp)
    
    (usk, upk, req, ret) = flycred.CredReq(pp, attr_list)
    
    cct = flycred.EncIss(pp, isk, ipk, req, F_o, T_vec, F_e_list, opk_list)
    
    flycred.EncVfy(pp, ipk, usk, upk, cct)
    
    dlt_list = {}
    for i in range(n_1):
        dlt_list[i] = flycred.Sign(pp, osk_list[i], opk_list[i], T_vec[i], et_vec_list[i])
    
    cred, ret11, ret12, ret21, ret31, ret41, ret42 = flycred.DecCred(pp, ipk, usk, upk, cct, opk_list, T_vec, et_vec_list, dlt_list)
    
    tok, ctx = flycred.Show(pp, ipk, usk, upk, cred)
    ret1, ret2 = flycred.TokVfy(pp, ipk, tok, ctx)
    
    
    
    
    
    
    


    

    
if __name__ == "__main__":
    debug = True
    main()
