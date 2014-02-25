/*
 This is a simple class just to store an instance of pair of keys.
 
 Author: *** Name anonymized to allow blind review ***
 Date:   *** Removed ***
 */

package cryptoDSE;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;

public class InstanceKeys
{
    

    ECPublicKey   pubKey; 
    ECPrivateKey privKey;
    short         id;
       
    protected InstanceKeys(short ident)
    {
  
        KeyPair kp;
       short keyLen = (short)(0x8000 | CryptoDSE.LENGTH_EC_FP_256);
        kp = new KeyPair(KeyPair.ALG_EC_FP , keyLen);
        kp.genKeyPair();
        pubKey  = (ECPublicKey)  kp.getPublic();  
        privKey = (ECPrivateKey) kp.getPrivate();
        
        id = ident;
                
    }   
    //overwrite keys with a new random set of keys
    //this is performed immediately before deletion
    //so that the object does not still hold the
    //private key between unlinking and garbage collection
    
    public void cleanKeys()
    {
      privKey.clearKey();
    }
    
    public ECPublicKey getPublicKey() {
        return pubKey;
    }

    public ECPrivateKey getPrivateKey() 
    {
        return privKey;
    }
    
    public short getKeySize() {  
    
    
        return pubKey.getSize();
    }
    
    public short getId() {
        return id;
    }

}

