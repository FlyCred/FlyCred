'''

| From: "AbeSWET"
| Published in: 2025

|
| type:           AbeSWET: CP-ABE-based Signature Witness Encryption with Tags
| setting:        Pairing

:Authors:         Anonymous Authors
:Date:            01/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class AbeSWET(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "AbeSWET: CP-ABE-based Signature Witness Encryption with Tags"
        self.group = group_obj
        self.util = MSP(self.group, verbose) 

    def Setup(self):
        """
        Generates the public parameters .
        """

        if debug:
            print('\nSetup algorithm:\n')

        
        g = self.group.random(G1)
        g_ = self.group.random(G2)
        e_gg_ = pair(g, g_)
        Z = self.group.random(G1)       
        pp = {'g': g, 'g_': g_, 'e_gg_': e_gg_, 'Z': Z }
        
        return pp
    
    def KeyGen(self, pp):
        """
        Generates the signing private/public key pair.
        """

        if debug:
            print('\n KeyGen algorithm:\n')

        
        ssk = self.group.random(ZR)        
        R_ = pp['g_'] ** ssk        
        spk = pair(pp['Z'], R_)

        return ssk, spk
    
    def Sign(self, pp, ssk, spk, T, attr_vect):
        """
        Generates the signature for the tag and the attribute vector.
        """

        if debug:
            print('\n Sign algorithm:\n')

        r1 = self.group.random(ZR)     
        
        dlt1 = pp['Z'] ** ssk * self.group.hash(T,G1) ** r1
        dlt2 = pp['g_'] ** r1
        dlt3 = {}
        
        for attr in attr_vect:
            attrHash = self.group.hash(attr, G1)
            dlt3[attr] = attrHash ** r1
        
        dlt = {'T': T, 'attr_vect': attr_vect, 'dlt1': dlt1, 'dlt2': dlt2, 'dlt3': dlt3}
        return dlt

    
    def Vfy(self, pp, spk, dlt):
        """
        Verifies the correctness of the signature.
        """

        if debug:
            print('\n Vfy algorithm:\n')

        e1 = pair(dlt['dlt1'], pp['g_'])
        e2 = spk * pair(self.group.hash(dlt['T'],G1), dlt['dlt2'])
        
        if e1 == e2:
            ret1 = True
        else:
            ret1 = False 
        
        for attr in dlt['attr_vect']:
            attrHash = self.group.hash(attr, G1)
            e1 = pair(attrHash, dlt['dlt2'])
            e2 = pair(dlt['dlt3'][attr], pp['g_'])
        
        if e1 == e2:
            ret2 = True
        else:
            ret2 = False 
        
        return ret1, ret2
    
    def Enc(self, pp, spk, m, T, policy_str):
        
        """
        Encrypts a message with the tag and the access structure.
        """

        if debug:
            print('\n Enc algorithm:\n')

        policy = self.util.createPolicy(policy_str)
        mono_span_prog = self.util.convert_policy_to_msp(policy)
        num_cols = self.util.len_longest_row

        # pick randomness
        r2 = self.group.random(ZR)
        r3 = self.group.random(ZR)
        r4 = self.group.random(GT)
        
        # pick random shares
        mu = [r2]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            mu.append(rand)
        ct0 = spk ** r2 * r4  
        ct1 = pp['g_'] ** r2
        ct2 = pp['g_'] ** r3
        gt = self.group.hash(T,G1)
        ct3 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop1 = sum(i[0] * i[1] for i in zip(row, mu[:len_row]))
            ct3[attr] = (gt ** Mivtop1) * (attrHash ** r3)
            
        ct4 = self.group.hash(str(r4), ZR) + m
        ct = {'policy': policy, 'T': T, 'ct0': ct0, 'ct1': ct1, 'ct2': ct2, 'ct3': ct3, 'ct4': ct4}
        return ct

    def EncUni(self, pp, spk, m, T, policy, mono_span_prog, num_cols, r2, r3, r4, mu):
        
        """
        Encrypts a message with the tag and the access structure.
        """

        if debug:
            print('\n Enc algorithm:\n')

        ct0 = spk ** r2 * r4  
        ct1 = pp['g_'] ** r2
        ct2 = pp['g_'] ** r3
        gt = self.group.hash(T,G1)
        ct3 = {}
        for attr, row in mono_span_prog.items():
            attr_stripped = self.util.strip_index(attr)
            attrHash = self.group.hash(attr_stripped, G1)
            len_row = len(row)
            Mivtop1 = sum(i[0] * i[1] for i in zip(row, mu[:len_row]))
            ct3[attr] = (gt ** Mivtop1) * (attrHash ** r3)
            
        ct4 = self.group.hash(str(r4), ZR) + m
        ct = {'policy': policy, 'T': T, 'ct0': ct0, 'ct1': ct1, 'ct2': ct2, 'ct3': ct3, 'ct4': ct4}
        return ct
    
    def Dec(self, pp, ct, dlt):
        
        """
        Decrypts the ciphertext.
        """

        if debug:
            print('\n Dec algorithm:\n')
        nodes = self.util.prune(ct['policy'], dlt['attr_vect'])
        if not nodes:
            print ("Policy not satisfied.")
            ret = False
        else:
            ret = True
        
        e1 = pair(dlt['dlt1'], ct['ct1'])    
         
        prod_ct3 = 1
        prod_dlt3 = 1
        for node in nodes:
            attr = node.getAttributeAndIndex()
            attr_stripped = self.util.strip_index(attr)  
            prod_ct3 *= ct['ct3'][attr]            
            prod_dlt3 *= dlt['dlt3'][attr_stripped]
        e2 = pair(prod_ct3, dlt['dlt2'])
        e3 = pair(prod_dlt3, ct['ct2'])      

        r4 = ct['ct0'] * e2 / (e1 * e3)       

        m = ct['ct4'] - self.group.hash(str(r4), ZR)
    
        return m, ret

    
