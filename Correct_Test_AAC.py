'''
:Date:            1/2025
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from AAC import AAC

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

def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('BN254') #BN254  MNT159 MNT224
       

    
    # AAC test 
    n  = 10
    attr_list = create_user_attrs_list(n)
    
    aac = AAC(pairing_group)
    
    pp = aac.Setup(n)
    
    (isk, ipk) = aac.IKeyGen(pp)
    
    (usk, upk, req, ret) = aac.CredReq(pp, attr_list)
    if ret != True:
        print("CredReq failed for {}: verify attr number!".format(aac.name)) 
    
    (wit, stm) = aac.WSGen(pp)
    
    (pcred, ret1, ret2) = aac.pIssue(pp, isk, ipk, stm, req)
    if ret1 != True:
        print("pIssue failed for {}: verify zkp req!".format(aac.name))
    if ret2 != True:
        print("pIssue failed for {}: verify zkp stm!".format(aac.name))
    
    (ret1, ret2, ret3) = aac.pCredVfy(pp, ipk, usk, upk, pcred)
    if ret1 != True:
        print("pCredVfy failed for {}: verify zkp stm!".format(aac.name))
    if ret2 != True:
        print("pCredVfy failed for {}: verify pairing eq1!".format(aac.name))
    if ret3 != True:
        print("pCredVfy failed for {}: verify pairing eq2!".format(aac.name))
    
    cred = aac.Adaptor(pp, pcred, wit)
    
    (wit, ret) = aac.Ext(pp, pcred, cred)
    if ret != True:
        print("Ext failed for {}: verify wit!".format(aac.name))
    
    
    (ret1, ret2 ) = aac.CredVfy(pp, ipk, usk, upk, cred)
    if ret1 != True:
        print("CredVfy failed for {}: verify pair eq1!".format(aac.name))
    if ret2 != True:
        print("CredVfy failed for {}: verify pair eq2!".format(aac.name))
    
    (tok, ctx) = aac.Show(pp, ipk, usk, upk, cred)
    
    (ret1, ret2) = aac.TokVfy(pp, ipk, tok, ctx)
    if ret1 != True:
        print("TokVfy failed for {}: verify zkp tok!".format(aac.name))
    if ret2 != True:
        print("TokVfy failed for {}: verify pair eq!".format(aac.name))

    
if __name__ == "__main__":
    debug = True
    main()
