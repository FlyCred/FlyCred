'''

| From: "FlyCred"
| Published in: 2025

|
| type:           FlyCred: Verifiable and Expressive Conditional Credentials
| setting:        Pairing

:Authors:         Anonymous Authors
:Date:            01/2025
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from msp import MSP
from AbeSWET import AbeSWET
from AAC import AAC


debug = False
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
    
class FlyCred(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "FlyCred: Verifiable and Expressive Conditional Credentials"
        self.group = group_obj
        self.util = MSP(self.group, verbose) 
        self.aac = AAC(self.group)
        self.abeswet = AbeSWET(self.group)

    def Setup(self, n, B, n_1, n_2):
        """
        Generates the public parameters .
        """

        if debug:
            print('\nSetup algorithm:\n')        
        g = self.group.random(G1)
        g_ = self.group.random(G2)
        e_gg_ = pair(g, g_)
        Z = self.group.random(G1)       
        pp_swe = {'g': g, 'g_': g_, 'e_gg_': e_gg_, 'Z': Z }
        pp_aac = {'g': g, 'g_': g_, 'e_gg_': e_gg_, 'n': n}
        pp = {'B': B,'g': g, 'g_': g_, 'e_gg_': e_gg_, 'n_1': n_1, 'n_2': n_2, 'swe': pp_swe, 'aac': pp_aac}
        
        return pp
    
    def IKeyGen(self, pp):
        """
        Issuer key generation.
        """

        if debug:
            print('\n IKeyGen algorithm:\n')

        (isk, ipk) = self.aac.IKeyGen(pp['aac'])

        return isk, ipk
    
    def OKeyGen(self, pp):
        """
        Issuer key generation.
        """

        if debug:
            print('\n IKeyGen algorithm:\n')

        (osk, opk) = self.abeswet.KeyGen(pp['swe'])

        return osk, opk
    def CredReq(self, pp, attr_list):
        """
        Request for user credentials.
        """

        if debug:
            print('\n CredReq algorithm:\n')

        (usk, upk, req, ret) = self.aac.CredReq(pp['aac'], attr_list)
        if ret != True:
            print("CredReq failed for {}: verify attr number!".format(self.name)) 

        return usk, upk, req, ret
    
    def EncIss(self, pp, isk, ipk, req, F_o, T_vec, F_e_list, opk_list):
        
        """
        Issue encrypted credentials.
        """

        if debug:
            print('\n EncIss algorithm:\n')
            
        (wit, stm) = self.aac.WSGen(pp['aac'])
        
        (pcred, ret1, ret2) = self.aac.pIssue(pp['aac'], isk, ipk, stm, req)
        
        if ret1 != True:
            print("pIssue failed for {}: verify zkp req!".format(self.name))
        if ret2 != True:
            print("pIssue failed for {}: verify zkp stm!".format(self.name))
        
        policy = self.util.createPolicy(F_o)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        
        
        nodes = self.util.prune(policy, T_vec)
        if not nodes:
            print ("F_o not satisfied {}.".format(self.name))
            ret3 = False
        else:
            ret3 = True
        
        mu = [wit]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            mu.append(rand)
        sw = {}
        SW = {}
        index = {}
        for et, row in mono_span_prog.items():
            len_row = len(row)
            for j in range(pp['n_1']):
                if T_vec[j] == et:                    
                    sw[j] = sum(i[0] * i[1] for i in zip(row, mu[:len_row]))
                    SW[j] = pp['g'] ** sw[j]
                    index [et] = j
                    break

        opk = self.group.random(GT)
        T = self.group.random(ZR)
        (ret_vec, rF_e) = create_list_and_policy(pp['n_1'], pp['n_2'])
        
        
        rpolicy = self.util.createPolicy(rF_e)
        rmono_span_prog = self.util.convert_policy_to_msp(rpolicy)
        rnum_cols = self.util.len_longest_row
        
        
        if pp['n_1'] != len(sw):
            print(" LSSS failed for {}: len(sw) != n_1!".format(self.aac.name))
        
        SO = {}
        SH = {}
        w = {}
        W = {}
        r2 = {}
        r3 = {}
        r4 = {}
        mv = {}
        rmv = {}
        ct_ = {}
        fei = 1
        
        
        for j in range(2*len(sw)*pp['B']):
            w[j] = self.group.random(ZR)
            W[j] = pp['g'] ** w[j]
            r2[j] = self.group.random(ZR)
            r3[j] = self.group.random(ZR)
            r4[j] = self.group.random(GT)
            mv[j] = [r2[j]]
            rmv[j] = [self.group.random(ZR)]
            for i in range(rnum_cols-1):
                rand = self.group.random(ZR)
                mv[j].append(rand)
                rand = self.group.random(ZR)
                rmv[j].append(rand)
            
            ct_[j] = self.abeswet.EncUni(pp, opk, w[j], T, rpolicy, rmono_span_prog, rnum_cols, r2[j], r3[j], r4[j], mv[j])
            fei = fei * self.group.hash(str(W[j]), ZR) * self.group.hash(str(ct_[j]), ZR) 
        
        # Hash fei
        fei = fei * self.group.hash(str(pcred), ZR) * self.group.hash(str(opk), ZR) * self.group.hash(str(T), ZR) * self.group.hash(str(rF_e), ZR)
        fei = str(fei)
        
        bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
        cw = {}
        ct = {}
        pi = {}
        sww = []
        lenf = len(bit_fei)
        for j in range(2*len(sw)*pp['B']):
            if j%len(bit_fei) == 0:
                fei =  self.group.hash(str(fei), ZR)
                fei = str(fei)
                bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
                lenf = len(bit_fei)
            jj = j % lenf
            if bit_fei[jj] == '1':
                SO[j] = {'w': w[j], 'r2': r2[j], 'r3': r3[j], 'r4': r4[j], 'mv': mv[j]}
            else:
                i = j % len(sw)
                sww.append(i)
                cw[j] = sw[i] + w[j]
                policy = self.util.createPolicy(F_e_list[i])
                mono_span_prog = self.util.convert_policy_to_msp(policy)
                num_cols = self.util.len_longest_row
                ct[j] = self.abeswet.EncUni(pp['swe'], opk_list[i], w[j], T_vec[i], policy, mono_span_prog, num_cols, r2[j], r3[j], r4[j], mv[j])
                #zkp cct
                r = self.group.random(ZR)
                R1 = (opk_list[i]/opk) ** rmv[j][0]
                R2 = {}
                R3 = {}
                c = self.group.hash(str(ct[j]['ct0']),ZR) * self.group.hash(str(ct_[j]['ct0']),ZR) * self.group.hash(str(opk_list[i]),ZR) * self.group.hash(str(opk),ZR)
                l = 0
                gt = self.group.hash(T,G1)
                for attr, row in rmono_span_prog.items():
                    attr_stripped = self.util.strip_index(attr)
                    attrHash = self.group.hash(attr_stripped, G1)
                    len_row = len(row)
                    Mivtop1 = sum(k[0] * k[1] for k in zip(row, rmv[j][:len_row]))
                    R2[l] = (gt ** Mivtop1) * (attrHash ** r)                     
                    c = c * self.group.hash(str(R2[l]),ZR)    
                    l = l + 1               
                gt = self.group.hash(T_vec[i],G1)
                
                l = 0
                for attr, row in mono_span_prog.items():
                    attr_stripped = self.util.strip_index(attr)
                    attrHash = self.group.hash(attr_stripped, G1)
                    len_row = len(row)
                    Mivtop1 = sum(k[0] * k[1] for k in zip(row, rmv[j][:len_row]))
                    R3[l] = (gt ** Mivtop1) * (attrHash ** r)                    
                    c = c * self.group.hash(str(R3[l]),ZR)
                    l = l + 1
                s_r = r - c * r3[j]
                s = []
                for l in range(rnum_cols):
                    tt = rmv[j][l] - c * mv[j][l]
                    s.append(tt)      
                pi[j] = {'c': c, 's_r': s_r, 's': s}   
                SH[j] = {'j': j, 'cw': cw[j], 'ct': ct[j], 'pi': pi[j]}
        #print("EncIss sww ={}".format(sww))            
        cct = {'pcred': pcred, 'SW': SW, 'W': W, 'ct_': ct_, 'SO': SO, 'SH': SH, 'opk': opk, 'T': T, 'Fe': rF_e, 'F_o': F_o, 'T_vec': T_vec, 'F_e_list': F_e_list, 'opk_list': opk_list, 'index': index} 
        
        return cct
    
    def EncVfy(self, pp, ipk, usk, upk, cct):
        """
        Verifies the correctness of the encrypted credentials.
        """

        if debug:
            print('\n EncVfy algorithm:\n')
        # check pcred
        
        (ret11, ret12, ret13) = self.aac.pCredVfy(pp['aac'], ipk, usk, upk, cct['pcred'])
        if ret11 != True:
            print("pCredVfy failed for {}: verify zkp stm!".format(self.name))
        if ret12 != True:
            print("pCredVfy failed for {}: verify pairing eq1!".format(self.name))
        if ret13 != True:
            print("pCredVfy failed for {}: verify pairing eq2!".format(self.name))
        
        #check LLLS
        policy = self.util.createPolicy(cct['F_o'])
        nodes = self.util.prune(policy, cct['T_vec'])
        if not nodes:
            print ("EncVfy F_o not satisfied {}.".format(self.name))
            ret21 = False
        else:
            ret21 = True
        
        prod_sw = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            prod_sw *= cct['SW'][cct['index'][attr]]  
        
        if cct['pcred']['stm']['W'] != prod_sw:
            print ("EncVfy failed for LSSS{}.".format(self.name))
            ret22 = False
        else:
            ret22 = True
        
        # compute fei
        fei = 1
        for j in range(2*len(cct['SW'])*pp['B']):
            fei = fei * self.group.hash(str(cct['W'][j]), ZR) * self.group.hash(str(cct['ct_'][j]), ZR)
        fei = fei * self.group.hash(str(cct['pcred']), ZR) * self.group.hash(str(cct['opk']), ZR) * self.group.hash(str(cct['T']), ZR) * self.group.hash(str(cct['Fe']), ZR)
        fei = str(fei)
        bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
        
        
        rpolicy = self.util.createPolicy(cct['Fe'])
        rmono_span_prog = self.util.convert_policy_to_msp(rpolicy)
        rnum_cols = self.util.len_longest_row
        lenf = len(bit_fei)
        for j in range(2*len(cct['SW'])*pp['B']):
            if j%len(bit_fei) == 0:
                fei =  self.group.hash(str(fei), ZR)
                fei = str(fei)
                bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
                lenf = len(bit_fei)
            jj = j % lenf
            if bit_fei[jj] == '1':
                ct_ = self.abeswet.EncUni(pp['swe'], cct['opk'], cct['SO'][j]['w'], cct['T'], rpolicy, rmono_span_prog, rnum_cols, cct['SO'][j]['r2'], cct['SO'][j]['r3'], cct['SO'][j]['r4'], cct['SO'][j]['mv'])
                if ct_ != cct['ct_'][j]:
                    ret31 = False
                else:
                    ret31 = True          
            else:
                i = j % len(cct['SW'])
                CW = pp['g'] ** cct['SH'][j]['cw']
                if CW != cct['SW'][i] * cct['W'][j]:
                    ret32 = False
                else:
                    ret32 = True
                #verify zkp cct
                c = self.group.hash(str(cct['SH'][j]['ct']['ct0']),ZR) * self.group.hash(str(cct['ct_'][j]['ct0']),ZR) * self.group.hash(str(cct['opk_list'][i]),ZR) * self.group.hash(str(cct['opk']),ZR)
                R2 = {}
                R3 = {}
                l = 0
                gt = self.group.hash(str(cct['T']),G1)
                for attr, row in rmono_span_prog.items():
                    attr_stripped = self.util.strip_index(attr)
                    attrHash = self.group.hash(attr_stripped, G1)
                    len_row = len(row)
                    Mivtop1 = sum(k[0] * k[1] for k in zip(row, cct['SH'][j]['pi']['s'][:len_row]))
                    R2[l] = (gt ** Mivtop1) * (attrHash ** cct['SH'][j]['pi']['s_r']) *  cct['ct_'][j]['ct3'][attr] **  cct['SH'][j]['pi']['c']                 
                    c = c * self.group.hash(str(R2[l]),ZR)    
                    l = l + 1               
                
                gt = self.group.hash(cct['T_vec'][i],G1)
                policy = self.util.createPolicy(cct['F_e_list'][i])
                mono_span_prog = self.util.convert_policy_to_msp(policy)
                num_cols = self.util.len_longest_row
                l = 0
                for attr, row in mono_span_prog.items():
                    attr_stripped = self.util.strip_index(attr)
                    attrHash = self.group.hash(attr_stripped, G1)
                    len_row = len(row)
                    Mivtop1 = sum(k[0] * k[1] for k in zip(row, cct['SH'][j]['pi']['s'][:len_row])) 
                    R3[l] = (gt ** Mivtop1) * (attrHash ** cct['SH'][j]['pi']['s_r']) * cct['SH'][j]['ct']['ct3'][attr] ** cct['SH'][j]['pi']['c']                   
                    c = c * self.group.hash(str(R3[l]),ZR)
                    l = l + 1
                if c == cct['SH'][j]['pi']['c']:
                    ret4 = True
                else:
                    ret4 = False 
                                     
        
        return ret11, ret12, ret13, ret21, ret22, ret31, ret32 
    
    def Sign(self, pp, osk, opk, T, et_vec):
        """
        Generates the signature for the tag and the event vector.
        """

        if debug:
            print('\n Sign algorithm:\n')

        dlt = self.abeswet.Sign(pp['swe'], osk, opk, T, et_vec)
        return dlt

    
    def DecCred(self, pp, ipk, usk, upk, cct, opk_list, T_vec, et_vec_list, dlt_list):
        
        """
        Decrypts the encrypted credentials.
        """

        if debug:
            print('\n DecCred algorithm:\n')
        
        # Fo
        policy = self.util.createPolicy(cct['F_o'])
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row
        nodes = self.util.prune(policy, T_vec)
        if not nodes:
            print ("DecCred Fo Policy not satisfied{}.".format(self.name))
            ret31 = False
        else:
            ret31 = True
        
        #Fe
        sel = {}
        k = 0
        for node in nodes:
            attr = node.getAttributeAndIndex()
            j = cct['index'][attr]
            (ret11, ret12) = self.abeswet.Vfy(pp['swe'], opk_list[j], dlt_list[j])
            sel[k] = j
            k = k + 1 
        #print("DecCred sel= {}".format(sel))
        if ret11 != True:
            print("DecCred failed for {}: eq1!".format(self.abeswet.name))
        if ret12 != True:
            print("DecCred failed for {}: eq2!".format(self.abeswet.name))
        
        # compute fei
        fei = 1
        for j in range(2*len(cct['SW'])*pp['B']):
            fei = fei * self.group.hash(str(cct['W'][j]), ZR) * self.group.hash(str(cct['ct_'][j]), ZR)
        fei = fei * self.group.hash(str(cct['pcred']), ZR) * self.group.hash(str(cct['opk']), ZR) * self.group.hash(str(cct['T']), ZR) * self.group.hash(str(cct['Fe']), ZR)
        fei = str(fei)
        bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
        w = {}
        sw = {}
        lenf = len(bit_fei)
        for j in range(2*len(cct['SW'])*pp['B']):
            if j%len(bit_fei) == 0:
                fei =  self.group.hash(str(fei), ZR)
                fei = str(fei)
                bit_fei = [bit for char in fei for bit in format(ord(char), '08b')]
                lenf = len(bit_fei)
            jj = j % lenf
            if bit_fei[jj] == '0':
                i = j % len(cct['SW'])
                for k in range(len(sel)): 
                    if i ==  sel[k]:                     
                        (w[i], ret21) = self.abeswet.Dec(pp['swe'], cct['SH'][j]['ct'], dlt_list[i])
                        sw[i] = cct['SH'][j]['cw'] - w[i]
        
        if ret21 != True:
            print("DecCred failed for {}: Policy not satisfied!".format(self.abeswet.name))
               
        wit = 0
        for i in range(len(sel)):            
             wit = wit + sw[sel[i]]  
        #for i in range(len(sw)):            
        #    wit = wit + sw[i]    
        cred = self.aac.Adaptor( pp['aac'], cct['pcred'], wit)
        
        (ret41, ret42) = self.aac.CredVfy(pp['aac'], ipk, usk, upk, cred)
        if ret41 != True:
            print("DecCred failed for {}: verify pair eq1!".format(self.aac.name))
        if ret42 != True:
            print("DecCred failed for {}: verify pair eq2!".format(self.aac.name))
    
        return cred, ret11, ret12, ret21, ret31, ret41, ret42
    
    def Show(self, pp, ipk, usk, upk, cred):
        """
        Generating a user access token.

        """

        if debug:
            print('\n Show algorithm:\n')
        
        (tok, ctx) = self.aac.Show(pp['aac'], ipk, usk, upk, cred)

        return tok, ctx
    
    def TokVfy(self, pp, ipk, tok, ctx):
        """
        Verifies the correctness of the user access token.

        """

        if debug:
            print('\n TokVfy algorithm:\n')

        (ret1, ret2) = self.aac.TokVfy(pp['aac'], ipk, tok, ctx)
        if ret1 != True:
            print("TokVfy failed for {}: verify zkp tok!".format(self.name))
        if ret2 != True:
            print("TokVfy failed for {}: verify pair eq!".format(self.name))
        return  ret1, ret2   
    
