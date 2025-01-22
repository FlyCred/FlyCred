'''
| From: "AAC"
| Published in: 2025

|
| type:           AAC: Adaptor Anonymous Credentials
| setting:        Pairing

:Authors:         Anonymous Authors
:Date:            01/2025
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP

debug = False

class AAC(ABEnc):
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "AAC: Adaptor Anonymous Credentials"
        self.group = group_obj
        self.util = MSP(self.group, verbose) 

    def Setup(self, n):
        """
        Generates public parameters.

        """

        if debug:
            print('\nSetup algorithm:\n')

        # pick a random element from the two source groups and pair them
        g = self.group.random(G1)

        g_ = self.group.random(G2)

        e_gg_ = pair(g, g_)
        
        ord = self.group.order()
     
        # the public parameters
        pp = {'g': g, 'g_': g_, 'e_gg_': e_gg_, 'n': n}
        return pp
    
    def IKeyGen(self, pp):
        """
        Generates the issuer’s private/public key pair.

        """

        if debug:
            print('\nIKeyGen algorithm:\n')
        
        x = self.group.random(ZR)        
        X_ = pp['g_'] ** x
        
        y = {}
        Y_ = {}

        for i in range(0, pp['n']):
            y[i] = self.group.random(ZR)
            Y_[i] = pp['g_'] ** y[i]
        
        isk = {'x': x, 'y': y}
        ipk = {'X_': X_, 'Y_': Y_}
        
        return isk, ipk
    
    def CredReq(self, pp, attr_list):
        """
        Generates the user credential request.

        """

        if debug:
            print('\nCredReq algorithm:\n')
        
        usk = self.group.random(ZR)        
        upk = pp['g'] ** usk
        
        #zkp
        r = self.group.random(ZR) 
        R = pp['g'] ** r
         
        if pp['n'] == len(attr_list):
            ret = True
        else:
            ret = False
        #hash
        c = self.group.hash(str(R), ZR)
        for i in range(1, pp['n']):
            attrHash = self.group.hash(attr_list[i-1], ZR)
            c = c * attrHash
        c = c * self.group.hash(str(upk), ZR)     
        q = self.group.order()
        s = r - (c * usk)
        
        pi = {'c': c, 's': s}
        req = {'upk': upk, 'attr_list': attr_list, 'pi': pi}
        return usk, upk, req, ret
    
    def WSGen(self, pp):
        """
        Generates a witness-statement pair.

        """

        if debug:
            print('\nWSGen algorithm:\n')
        
        wit = self.group.random(ZR)        
        W = pp['g'] ** wit
        W_ = pp['g_'] ** wit
        
        #zkp
        r = self.group.random(ZR) 
        R = pp['g'] ** r        
        R_ = pp['g_'] ** r    
            
        #hash
        c = self.group.hash(str(W), ZR) * self.group.hash(str(W_), ZR) * self.group.hash(str(R), ZR) * self.group.hash(str(R), ZR)        
        s = r - c * wit  

        pi = {'c': c, 's': s}
        stm = {'W': W, 'W_': W_, 'pi': pi}

        return wit, stm
    
    def pIssue(self, pp, isk, ipk, stm, req):
        """
        Generates a user pre-credential.

        """

        if debug:
            print('\npIssue algorithm:\n')
         
        #verify zkp req
        R = pp['g'] ** req['pi']['s'] * req['upk'] ** req['pi']['c']
        c = self.group.hash(str(R), ZR)
        for i in range(1, pp['n']):
            attrHash = self.group.hash(req['attr_list'][i-1], ZR)
            c = c * attrHash
        c = c * self.group.hash(str(req['upk']), ZR)    
        if c == req['pi']['c']:
            ret1 = True
        else:
            ret1 = False
        
         #verify zkp stm
        R = (pp['g'] ** stm['pi']['s']) * (stm['W'] ** stm['pi']['c'])
        R_ = (pp['g_'] ** stm['pi']['s']) * (stm['W_'] ** stm['pi']['c'])

        c = self.group.hash(str(stm['W']), ZR) * self.group.hash(str(stm['W_']), ZR) * self.group.hash(str(R), ZR) * self.group.hash(str(R), ZR)   
        if c == stm['pi']['c']:
            ret2 = True
        else:
            ret2 = False 
        
        #issue PS
        k1 = self.group.random(ZR)
        k2 = self.group.random(ZR)
        
        sgm1 =  stm['W'] ** k1
        sum = isk['x']
        for i in range(1, pp['n']):
            attrHash = self.group.hash(req['attr_list'][i-1], ZR)
            sum = sum + attrHash * isk['y'][i]
        psgm2 = pp['g'] ** (k1 * sum) * req['upk'] ** (k1 * isk['y'][0])
        
        #issue Schnoor
        R_ = pp['g_'] ** k2 * stm['W_']
        sgm3 = self.group.hash(str(ipk['X_']), ZR) * self.group.hash(str(stm['W']), ZR) * self.group.hash(str(req['upk']), ZR)
        
        psgm4 = k2 - (isk['x'] * sgm3)       
        
        pcred = {'attr_list': req['attr_list'], 'stm': stm, 'sgm1': sgm1, 'psgm2': psgm2, 'sgm3': sgm3, 'psgm4': psgm4}

        return pcred, ret1, ret2
    
    def pCredVfy(self, pp, ipk, usk, upk, pcred):
        """
        Verifies the correctness of the pre-credential.

        """

        if debug:
            print('\npCredVfy algorithm:\n')
        
        #verify zkp stm
        R = pp['g'] ** pcred['stm']['pi']['s'] * pcred['stm']['W'] ** pcred['stm']['pi']['c']
        R_ = pp['g_'] ** pcred['stm']['pi']['s'] * pcred['stm']['W_'] ** pcred['stm']['pi']['c']
        c = self.group.hash(str(pcred['stm']['W']), ZR) * self.group.hash(str(pcred['stm']['W_']), ZR) * self.group.hash(str(R), ZR) * self.group.hash(str(R), ZR)   
        if c == pcred['stm']['pi']['c']:
            ret1 = True
        else:
            ret1 = False 
        # verify pairing 
        
        e1 = pair(pcred['psgm2'], pcred['stm']['W_'])
        
        g_= ipk['X_'] * ipk['Y_'][0] ** usk
        for i in range(1, pp['n']):
            attrHash = self.group.hash(pcred['attr_list'][i-1], ZR)
            g_ = g_ * ipk['Y_'][i] ** attrHash
        e2 = pair(pcred['sgm1'], g_)
        
        if e1 == e2:
            ret2 = True
        else:
            ret2 = False 
            
        g_ = pp['g_'] ** pcred['psgm4'] * ipk['X_'] ** pcred['sgm3'] * pcred['stm']['W_']
        
        sgm3 = self.group.hash(str(ipk['X_']), ZR) * self.group.hash(str(pcred['stm']['W']), ZR) * self.group.hash(str(upk), ZR)

        if sgm3 == pcred['sgm3']:
            ret3 = True
        else:
            ret3 = False 
        
        return ret1, ret2, ret3 
    
    def Adaptor(self, pp, pcred, wit):
        """
        Transforms the user pre-credential into the adapted credential.

        """

        if debug:
            print('\n Adaptor algorithm:\n')
            
            
        sgm2 = pcred['psgm2'] ** wit
        sgm4 = pcred['psgm4'] + wit
        
        cred = {'attr_list': pcred['attr_list'], 'stm': pcred['stm'], 'sgm1': pcred['sgm1'], 'sgm2': sgm2, 'sgm3': pcred['sgm3'], 'sgm4': sgm4}
        
        return  cred     
    
    def Ext(self, pp, pcred, cred):
        """
         Extracts the witness of the statement from the user pre-credential and the final valid credential.

        """

        if debug:
            print('\n Ext algorithm:\n')
        
        wit = cred['sgm4'] - pcred['psgm4']
        
        if pp['g'] ** wit == cred['stm']['W'] and pp['g_'] ** wit == cred['stm']['W_']:
            ret = True
        else:
            ret = True

        return  wit, ret  
    
    def CredVfy(self, pp, ipk, usk, upk, cred):
        """
        Verifies the correctness of the user adapted credential.

        """

        if debug:
            print('\n CredVfy algorithm:\n')
        # verify pairing 
        
        e1 = pair(cred['sgm2'], pp['g_'])
        
        g_= ipk['X_'] * ipk['Y_'][0] ** usk
        for i in range(1, pp['n']):
            attrHash = self.group.hash(cred['attr_list'][i-1], ZR)
            g_ = g_ * ipk['Y_'][i] ** attrHash
        e2 = pair(cred['sgm1'], g_)
        
        if e1 == e2:
            ret1 = True
        else:
            ret1 = False 
            
        g_ = pp['g_'] ** cred['sgm4'] * ipk['X_'] ** cred['sgm3']
        
        sgm3 = self.group.hash(str(ipk['X_']), ZR) * self.group.hash(str(cred['stm']['W']), ZR)  * self.group.hash(str(upk), ZR)

        if sgm3 == cred['sgm3']:
            ret2 = True
        else:
            ret2 = False 
        
        return ret1, ret2 
    
    def Show(self, pp, ipk, usk, upk, cred):
        """
        Generating a user access token.

        """

        if debug:
            print('\n Show algorithm:\n')
        
        ctx = self.group.random(ZR)   
        
        k3 = self.group.random(ZR)   
        k4 = self.group.random(ZR)   
        
        sgm1 = cred['sgm1'] ** k3
        sgm2 = cred['sgm2'] ** k3
        alpha = ipk['X_'] * ipk['Y_'][0] ** usk
        for i in range(1, pp['n']):
            attrHash = self.group.hash(cred['attr_list'][i-1], ZR)
            alpha = alpha * ipk['Y_'][i] ** attrHash
        alpha = alpha * pp['g_'] ** k4
        beta = sgm1 ** k4
        
        
        #zkp tok
        k = self.group.random(ZR) 
        r = {}
        for i in range(0, pp['n']):
            r[i] = self.group.random(ZR) 
        R1 = pp['g_'] ** k
        for i in range(0, pp['n']):
            R1 = R1 * ipk['Y_'][i] ** r[i]
        R2 = sgm1 ** k
        
        c= self.group.hash(str(alpha), ZR) * self.group.hash(str(beta), ZR) * self.group.hash(str(sgm1), ZR) *  self.group.hash(str(R2), ZR) * self.group.hash(str(ctx), ZR)
        
        sk = k - c * k4
        s = {}
        s[0] = r[0] - c * usk
        
        for i in range(1, pp['n']):
            attrHash = self.group.hash(cred['attr_list'][i-1], ZR)
            s[i] = r[i] - c * attrHash
        
        pi = {'c': c, 'sk': sk, 's': s}
        tok = {'sgm1': sgm1, 'sgm2': sgm2, 'alpha': alpha, 'beta': beta, 'pi': pi}

        return tok, ctx
    
    def TokVfy(self, pp, ipk, tok, ctx):
        """
        Verifies the correctness of the user access token.

        """

        if debug:
            print('\n TokVfy algorithm:\n')
        R1 = pp['g_'] ** tok['pi']['sk']
        
        for i in range(1, pp['n']):            
            R1 = R1 * ipk['Y_'][i] ** tok['pi']['s'][i]
        R1 = R1 * (tok['alpha']/ipk['X_']) ** tok['pi']['c']
        
        R2 = tok['sgm1'] ** tok['pi']['sk'] * tok['beta'] ** tok['pi']['c']
        
        c= self.group.hash(str(tok['alpha']), ZR) * self.group.hash(str(tok['beta']), ZR) * self.group.hash(str(tok['sgm1']), ZR) *  self.group.hash(str(R2), ZR) * self.group.hash(str(ctx), ZR)
        
        if c == tok['pi']['c']:
            ret1 = True
        else:
            ret1 = False
        
        e1 = pair(tok['sgm1'], tok['alpha'])
        e2 = pair(tok['sgm2'] * tok['beta'], pp['g_'])
        
        if e1 == e2:
            ret2 = True
        else:
            ret2 = False
        
        return  ret1, ret2   
    
