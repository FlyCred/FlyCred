'''
:Date:            1/2025
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT, ZR
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from AbeSWET import AbeSWET


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
             
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT159') #BN256  MNT224
       
           
    n_1 = 10
    n_2 = 5

    attr_list, attr_policy = create_list_and_policy(n_1, n_2)



    abeswet = AbeSWET(pairing_group)
    pp = abeswet.Setup()
    (ssk, spk) =  abeswet.KeyGen(pp)
    T = pairing_group.random(ZR)
    dlt = abeswet.Sign(pp, ssk, spk, T, attr_list)
    
    (ret1, ret2) = abeswet.Vfy(pp, spk, dlt)
    if ret1 != True:
        print("Vfy failed for {}: eq1!".format(abeswet.name))
    if ret2 != True:
        print("Vfy failed for {}: eq2!".format(abeswet.name))
    m = pairing_group.random(ZR)
    ct = abeswet.Enc(pp, spk, m, T, attr_policy)
    
    (m1, ret) = abeswet.Dec(pp, ct, dlt)
    if ret != True:
        print("Dec failed for {}: Policy not satisfied!".format(abeswet.name))
    if m != m1:
        print("Dec failed for {}!".format(abeswet.name))
    

    
if __name__ == "__main__":
    debug = True
    main()
