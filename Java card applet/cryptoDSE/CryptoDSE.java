/*

	This is a prototype implementation to demonstrate the practical feasibility
	of the Secure Storage and Erasure (SSE) protocol. The source code is provided 
	for free without warranty or liability.

	This Java card applet is installed in a Javacard 2.2.2. To install the applet,
	you can use a free "gpj" program. 
 
   It implements several operations, but the base ones are:
   - KeyGen: creates an instance for a client. It creates two keys:
             a private and a public key. It returns the instance
             id and the public key. At the moment it can store up to
             32 pairs of keys. Keys are not reused.
             APDU: 8010000000 (CLA INS 00 00 00)
   - Encrypt: This will encrypt a message sent by the host. The message
              will be encrypted based on the private key of an instance
              that was generated in KeyGen. The encryption follows a 
              4-step-protocol:
              - Beginning: starts the encryption. Receives an instance
                id, creates an ephemeral public key, a random IV, mac key
                and an encryption (session) key (as described in DHIES).
                Returns: the size of the ephemeral public key, the ephemeral
                public key and the random IV.
                APDU: 8020010002XXYY - CLA INS P1 00 02 [2 bytes instance id]
                the instance id is the one returned by KeyGen
              - Encryption: uses 3DES to encrypt the message. This step is
                called until there is still part of the message to be encrypted.
                This is done due to the limitation of the APDU load, which can
                have at most 255 bytes.
                Encrypts and sign the message as in DHIES.
                Returns the encrypted data.
                APDU 80200200LC[Data] - CLA INS P1 00 [Size of part of msg] [part of msg]
              - Ending: receives the last piece of data from the message and
                finalises the encryption. Sign the the final piece of the encrypted message
                Returns the last piece of encrypted data.
                APDU: 80200300LC[Data] - CLA INS P1 00 [Size of part of msg] [part of msg]
              - Returns the MAC for the encrypted message.
                APDU: 8020040000
  - Decrypt: This will decrypt the message based on the instance (private key) and the
             ephemeral public key. This operation can only decrypt messages of at most
             DECRYPTED_DATA_SIZE at a time, since it can only return the plaintext
             if a calculated MAC matches the MAC that the host has. It generates the MAC 
             for the received ciphertext and if it receives a valid MAC from the host, ie, 
             one that matches the received ciphertext MAC. All ciphertext is decrypted but
             not returned to the host until the MAC is confirmed to be a valid one.
             This operation has 5 steps:
             - Beginning: receives the instance id, the ephemeral public key and IV used 
               during encryption. Creates a symmetric key  (session key) and the MAC key 
               based on DHIES.
               Returns nothing.
               APDU: 80300100LCXXYY[Ephemeral public key][IV]  
               LC = size of ephemeral + 4 (instance id size) + 8 (size of IV)
             - Decrypt: decrypt the message using the symmetric key generated in step one. Stores the 
               plaintext in a vector. Calculates the MAC for the received ciphertext.
               Throws an exception if the size of the ciphertext is bigger than DECRYPTED_DATA_SIZE
               APDU: 80300200LC[part of the ciphertext]
               Returns nothing.
             - Ending: ends the decryption.
               Receives the last part of the ciphertext to be decrypted. Calculates the MAC
               for the whole ciphertext.
               Throws an exception if the size of the ciphertext is bigger than DECRYPTED_DATA_SIZE
               APDU: 80300300LC[last part of the ciphertext]
               Returns nothing.
             - Check MAC: receives a MAC and check against the MAC that was produced by
               the ciphertext that was decrypted.
               Returns nothing if ok, or throws an exception (INVALID_DECRYPTION_MAC)
               APDU: 80300400LC[MAC]
             - Returns plaintext: if MAC in step 4 was correct, then can return the plaintext
               This step is called while there is data to be returned to the host.
               Returns part of the plaintext and 9000 if there is still plaintext to return or
               0001 if there is not.
               APDU: 8030040000

 
   - Delete: Receives an instance (Ci), remove it, and return SIG("Deleted"+Ci) and Card Public Key.
 
   - Audit: This will generate a public and private ephemeral keys for the auditing process, and
            also generates a secret (Qns) based on the private auditing ephemeral key (s) and the 
            public ephemeral key (Qn) that was used during the encryption process. Returns the 
            value of the ephemeral auditing public key (Gs) and the secret (Qns), ie, DH key agreement
            between the ephemeral auditing private key (s) and the ephemeral public key (Qn), resulting
            in Qns. Furthermore, this routine calculates a Hash value based on G, Gs, Qns and Qn, 
            generating a value c. This c is used to calculate t = s + dc.c  mod n, ie, sum of the
            ephemeral auditing private key with the multiplication of the private key for an instance
            (Ci - used during encryption of the ciphertext) and the calculated value c, usign modulus
            of the elliptic curve.
          
 
	Author: *** Name anonymized to allow blind review ***
	Date:   *** Removed ***
*/

package cryptoDSE;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;                          
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacardx.crypto.Cipher;  

import javacard.security.Signature;
import javacard.security.KeyAgreement;                     
import javacard.security.MessageDigest;
import javacard.framework.Util;
import javacard.framework.JCSystem;               
import javacard.security.RandomData;  
import javacard.security.CryptoException;

//import com.nxp.id.jcopx.KeyAgreementX;

public class CryptoDSE extends Applet
{
    //Constants for APDU codes 
    final static byte KEYGEN  = (byte)0x10;
    final static byte ENCRYPT = (byte)0x20;
    final static byte DECRYPT = (byte)0x30;
    final static byte AUDIT   = (byte)0x40;
    final static byte DELETE  = (byte)0x50;
    final static byte GETECDATA  = (byte)0x60;
    final static byte NOPE  = (byte)0x70;
    
    // Constant for Athena Javacard algorithms
    final static byte ALG_EC_SVDP_DH_PLAIN = (byte)0x03;
    final static byte ALG_AES_CMAC8                = (byte) 0x93;
	  final static short LENGTH_EC_FP_256 = (short)256;
    
    //error state codes
    final static short INVALID_INSTANCE_ID          = (short)0x0AF1;
    final static short SIGNATURE_DOES_NOT_MATCH     = (short)0x0AF2;
    final static short INVALID_ENCRYPTION_STATE     = (short)0x0AF3;
    final static short INVALID_DECRYPTION_STATE     = (short)0x0AF4;
    final static short INVALID_ENCRYPTION_PARAMETER = (short)0x0AF5;
    final static short INVALID_DECRYPTION_PARAMETER = (short)0x0AF6;
    final static short INVALID_AUDITING_STATE       = (short)0x0AF7;
    final static short INVALID_DECRYPTION_MAC       = (short)0x0AF8;
    final static short INVALID_DECRYPTION_SIZE      = (short)0x0AF9;
    final static short INVALID_HASH_SESSION_KEY     = (short)0x0AF0;


    final static short TEMPORARY_DATA_SIZE = (short)256;
    final static short DECRYPTED_DATA_SIZE = (short)512;

    ListInstances   li;        // list of instances - each instance has a public and a private key
    Cipher          cipher;    // used to encrypt and decrypt data
    Signature sig;             // used to sign something using a key - from an instance or from the card
    
    
    ECPrivateKey  cardPrivateKey; // card key - used to sign something that was deleted - proof of deletion
    ECPublicKey   cardPublicKey;  // card key - send to anyone that wants to verify if something was signed by this card

    byte stateAuditing = 1; // used during the auditing protocol
    ECPrivateKey  auditPrivateKey; // keys used for auditing - s
    ECPublicKey   auditPublicKey;  // Gs
    ECPublicKey   ephemeralPublicKey; // Qn
    KeyPair kp;
    KeyAgreement ka;

    byte stateEncryption = (byte)1; // used during the encryption protocol
    byte stateDecryption = (byte)1; // used during the decryption protocol
    AESKey desKey;

    AESKey  macKey; // used to sign an encrypted message
    Signature macSig;
    short macDataLen;
      
    byte[] temporaryData; // used during encryption and decryption
    byte[] publicData;
    byte[] macData;
    byte[] secret; 
    
    // audit values
    byte[] qn, g, gs, s, c, dc, modN, t;
    
    RandomData rd ;
    
    byte[] iv ;
      
    short sizeEphemeralPublicKey;
    short sizeSecret;
    short sizeAuditPublicKey;
    short sizeAuditPrivateKey;
    
    byte[] h;
    byte[] encKey;
    byte[] hashEncKey;
    byte[] macH;
    
    byte[] decryptedData;
    short sizeDecryptedData;
    short decryptedBytesReturned;
    
    MessageDigest md; // used as a SHA hash function during generation of
                      // ephemeral public key for encryption and decryption
                      // and also for auditing
    
    // used in the auxiliary functions - basically to multiply or sum byte arrays (modular operations)
    
    static final short MAXSIZE = (short)50;
    byte[] sumResult;
    byte[] sumModResult;
    byte[] multiplyModResult;
    byte[] one;
    byte[] shift;
    
    byte[] modulus;
    byte[] minusModulus;
    short sizeModulus;
    
    byte[] shortArray;


    //-----------------------------------------------------------------------
    protected CryptoDSE()
    {
        /* creates the public and private keys for the card
           they will be used for signing the deletion of a file
       */  
      short keyLen = (short)(0x8000 | CryptoDSE.LENGTH_EC_FP_256);
	
        kp = new KeyPair(KeyPair.ALG_EC_FP , keyLen);  
   
        kp.genKeyPair();
     
             
        cardPublicKey  = (ECPublicKey)  kp.getPublic();
        cardPrivateKey = (ECPrivateKey) kp.getPrivate();
             
        
        //key agreement is used to efficiently perform elliptic curve multiplications
        //for audit proofs	
        ka = KeyAgreement.getInstance(ALG_EC_SVDP_DH_PLAIN, false);
    	
        // creates the list of instances 
        li = new ListInstances();
        
        // creates a DES key that will be used during encryption and decryption
        desKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        
        // creates values for creating the encryption/decryption key and also a mac
        // for the encrypted message
        h      = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        encKey = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        macH   = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);
        hashEncKey   = JCSystem.makeTransientByteArray((short)64, JCSystem.CLEAR_ON_DESELECT);

        // creates the cipher for encryting/decrypting data based on DHIES
        cipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD  , false);
        
        // used for creating mac and for sign the encrypted message
        macSig = Signature.getInstance((byte)ALG_AES_CMAC8,false);
        macKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        
        // creates a signatures for signing a proof of deletion - used during the delete operation
        sig = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        
        rd = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        
        iv = JCSystem.makeTransientByteArray((short)16, JCSystem.CLEAR_ON_DESELECT);
        
        // create a temporary byte array to be used during encryption and decryption and auditing
        // these byte arrays should be smaller, but for the test they can be a bit longer
        // in a real product these should be changed
        temporaryData = JCSystem.makeTransientByteArray(TEMPORARY_DATA_SIZE, JCSystem.CLEAR_ON_DESELECT);
        publicData    = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT);
        macData       = JCSystem.makeTransientByteArray((short)20, JCSystem.CLEAR_ON_DESELECT);
        qn            = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        g             = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        c             = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        dc            = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        s             = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        gs            = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        modN          = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        t             = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        secret        = JCSystem.makeTransientByteArray((short)128, JCSystem.CLEAR_ON_DESELECT); // used in auditing
        
        decryptedData     = JCSystem.makeTransientByteArray(DECRYPTED_DATA_SIZE, JCSystem.CLEAR_ON_DESELECT);

        // creates a message digest used in encryption/decryption and auditing
        md = MessageDigest.getInstance(MessageDigest.ALG_SHA,false);

        // used in the auxiliary functions - basically to multiply or sum byte arrays (modular operations)
        
        sumResult          = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        sumModResult       = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        multiplyModResult  = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        one        = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        shift      = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        
        modulus      = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        minusModulus = JCSystem.makeTransientByteArray((short)MAXSIZE, JCSystem.CLEAR_ON_DESELECT);
        
        shortArray = JCSystem.makeTransientByteArray((short)2, JCSystem.CLEAR_ON_DESELECT);;


        //register();
        
    }
    
    //-----------------------------------------------------------------------
    public static void install(byte bArray[], short bOffset, byte bLength)
    {
        new CryptoDSE().register();
    }
    
    //-----------------------------------------------------------------------
    public void process(APDU apdu)
    {
        byte[] buffer = apdu.getBuffer();
                
        buffer[ISO7816.OFFSET_CLA] = (byte)(buffer[ISO7816.OFFSET_CLA] & (byte)0xFC);
        
        if ((buffer[ISO7816.OFFSET_CLA] == 0) &&
            (buffer[ISO7816.OFFSET_INS] == (byte)(0xA4)) )
            return;
      
        if (buffer[ISO7816.OFFSET_CLA] != (byte) 0x80) ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        
        switch (buffer[ISO7816.OFFSET_INS])
        {
            case (byte) KEYGEN:
                keyGen(apdu);
                return;
            
            case (byte) ENCRYPT:
                encrypt(apdu);
                return;
        
            case (byte) DECRYPT:
                decrypt(apdu);
                return;

            case (byte) AUDIT:
                audit(apdu);
                return;
 
            case (byte) DELETE:
                delete(apdu);
                return;

            case (byte) GETECDATA:
                getECData(apdu);
                return;

            case (byte) NOPE:
                nope(apdu);
                return;

            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ----------------------------------------------------------------------
    // Get public data used in the Elliptic Curve algorithms.
    // APDU Format: 80 60 00 00 00
    // Returns sizes of (g,r,a,b,p), k, g, r, a, b and p
    private void getECData(APDU apdu)
    {
        byte buffer[] = apdu.getBuffer();
        short bytesRead = (short) (apdu.setIncomingAndReceive());
        
        byte[] a = new byte[64];
        byte[] b = new byte[64];
        byte[] p = new byte[64];
        
        short sizeG = cardPublicKey.getG(g,(short)0);
        
        // insert a zero in front of values to avoid negative numbers
        
        modN[0] = 0;
        short sizeN = cardPublicKey.getR(modN,(short)1);
        sizeN++;
        
        a[0] = 0;
        short sizeA = cardPublicKey.getA(a, (short)1);
        sizeA++;
        
        b[0] = 0;
        short sizeB = cardPublicKey.getB(b, (short)1);
        sizeB++;

        p[0] = 0;
        short sizeP = cardPublicKey.getField(p, (short)1);
        sizeP++;

        short k = 0x00;
        k = cardPublicKey.getK(); // should return 1
        
        // size of G is sent back
        buffer[0] = (byte)(sizeG & 0xFF);
        
        // size of the modulus is sent back
        buffer[1] = (byte)(sizeN & 0xFF);
        
        // size of A is sent back
        buffer[2] = (byte)(sizeA & 0xFF);
        
        // size of B is sent back
        buffer[3] = (byte)(sizeB & 0xFF);

        // size of P is sent back
        buffer[4] = (byte)(sizeP & 0xFF);
        
        // K is sent back
        buffer[5] = (byte)((k & (short)0xFF00)<<(short)8);
        buffer[6] = (byte)((k & (short)0x00FF));
        
        short i = 7;
        for(short j=0; j<sizeG; j++, i++) buffer[i] = g[j];
        for(short j=0; j<sizeN; j++, i++) buffer[i] = modN[j];
        for(short j=0; j<sizeA; j++, i++) buffer[i] = a[j];
        for(short j=0; j<sizeB; j++, i++) buffer[i] = b[j];
        for(short j=0; j<sizeP; j++, i++) buffer[i] = p[j];

        short sizeBuffer = (short) (sizeG+sizeN+sizeA+sizeB+sizeP +7);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (sizeBuffer));
        apdu.sendBytesLong(buffer, (short) 0, (short) (sizeBuffer));
        
        return;
        
    }

    // ----------------------------------------------------------------------
    // Does nothing - no operation.
    // APDU Format: 80 70 00 00 00
    private void nope(APDU apdu)
    {  
        byte buffer[] = apdu.getBuffer();  
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (2));
        short x = JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        buffer[1] = (byte)(x & 0xff);
        buffer[0] = (byte)((x >> 8) & 0xff);


        
        apdu.sendBytesLong(buffer, (short) 0, (short) (2));
       // short size = (short) (buffer[ISO7816.OFFSET_LC]); // size of the ephemeral public key Qn (ie, Gdn)
        
       // Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA),publicData,(short)0, size); // get Qn (Gdn)
       // ka.init(li.getInstance((short)0).getPrivateKey()); // init using "dc" 
      //  size = ka.generateSecret(publicData,(short)0,size,secret, (short)0);
    }

    // ----------------------------------------------------------------------
    // Delete an instance
    // APDU Format: 80 50 00 00 LS [instance - 2 bytes]
    // Returns: "Deleted"[Ci] message signed using the card private key and
    //           card public key
    private void delete(APDU apdu)
    {    	
        byte buffer[] = apdu.getBuffer();
        short bytesRead = (short) (apdu.setIncomingAndReceive());
        
        // get the instance used to encrypt the message - to get private key "dc"
        short id = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) + buffer[ISO7816.OFFSET_CDATA+1]);
        
        if (!li.isValid(id)) ISOException.throwIt(INVALID_INSTANCE_ID);
       	short ksize = li.getInstance(id).getPublicKey().getW(buffer, (byte)0); 
        li.removeInstance(id);
        
        sig.init(cardPrivateKey, Signature.MODE_SIGN);     

		// sign message Deleted concatenated with the instance public key, ie, DeletedPKi

        byte[] deleted = new byte[(short)(ksize+7)];
		for (short i=0; i<ksize; i++) deleted[(short)(i+7)] = buffer[i];
		
		deleted[(short)0] = (byte)0x44;
		deleted[(short)1]= (byte)0x65;
		deleted[(short)2]= (byte)0x6C;
		deleted[(short)3]= (byte)0x65;
		deleted[(short)4]= (byte)0x74;
		deleted[(short)5]= (byte)0x65;
		deleted[(short)6]= (byte)0x64;
		
		byte[] signature = new byte[128];
        	
		
        short sizeSignature = sig.sign(deleted, (short)0, (short)deleted.length, signature, (short)0);
        
        buffer[0] = (byte) (sizeSignature & (short)0x00FF);
        
        // send the signature
        short pos=1;
        for (short i=0; i<sizeSignature; i++, pos++) buffer[pos] = signature[i];
        
        // and also the public key
        
        byte[] pk = new byte[128];
        
        short sizePK = cardPublicKey.getW(pk, (short)0);
        
        for (short i=0; i<sizePK; i++, pos++) buffer[pos] = pk[i];
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (pos));
        apdu.sendBytesLong(buffer, (short) 0, (short) (pos));
        
        return;
        
    }
    
    // ----------------------------------------------------------------------
    // Audit
    // APDU Format: 80 40 00 00 LS [instance - 2 bytes] [ephemeral public key - Qn][hash of the session key]
    private void audit(APDU apdu)
    {    	
        byte buffer[] = apdu.getBuffer();
        short bytesRead = (short) (apdu.setIncomingAndReceive());
  
        // used to generate secrets,i.e. Qns and Qndc
        byte qns[] = new byte[128], qndc[] = new byte[128];
        short sizeQNS;
        
        // get the instance used to encrypt the message - to get private key "dc"
        short id = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) + buffer[ISO7816.OFFSET_CDATA+1]);
        
        if (!li.isValid(id)) ISOException.throwIt(INVALID_INSTANCE_ID);

       
              
        // -----------------
        // check whether the sent hash session key is valid
        
        short size = (short) (buffer[ISO7816.OFFSET_LC] - 22); // size of the ephemeral public key Qn (ie, Gdn)
        
        Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA+2),publicData,(short)0, size); // get Qn (Gdn)
                   
        ka.init(li.getInstance(id).getPrivateKey()); // init using "dc" 
        size = ka.generateSecret(publicData,(short)0,size,secret, (short)0); // set secret = Qn.dc
         
          
        // generate the hash for the session key the same way it was created in the encryption
        
        Util.arrayCopy(secret,(short)(0),h,(short)0, (short)size);

        md.reset();
        h[size] = (byte) 0x11; // add another byte to generate the hash of the session key
        md.doFinal(h,(short)0,(short)(size+1),hashEncKey,(short)0);
        
        md.reset();
        md.doFinal(hashEncKey,(short)(0),(short)20,hashEncKey,(short)0);
          
        // check to see if the sent hash of the session key is the same as the new
        // hash of the session key just generated
        
        if (Util.arrayCompare(hashEncKey, (short) 0,
                              buffer, (short)(ISO7816.OFFSET_CDATA+buffer[ISO7816.OFFSET_LC] - 20),
                              (short)20) != (short)0) {
            ISOException.throwIt(INVALID_HASH_SESSION_KEY);
        }
        
        // if hash of session key is valid then continue with the auditing
        // -----------------

        // creates ephemeral public and private keys for auditing         
        
        
        kp.genKeyPair();
    
         
        
        auditPublicKey  = (ECPublicKey)  kp.getPublic();  // Gs
        auditPrivateKey = (ECPrivateKey) kp.getPrivate(); // s
        s[0] = 0; // to be sure it is a positive number.
        
        sizeAuditPrivateKey = auditPrivateKey.getS(s,(short)1); // s as byte array
        sizeAuditPrivateKey++;
        sizeAuditPublicKey  = auditPublicKey.getW(gs,(short)0); // Gs as byte array   

         
  
        
        // generate a secret, i.e. Qns (Qn is in the buffer - public key used during encryption)
        ka.init(auditPrivateKey); // init using "s"
        // Qns
        sizeQNS = ka.generateSecret(buffer,(short) (ISO7816.OFFSET_CDATA+2),(short)(bytesRead-22),qns, (short)0);
        
        // G
        short sizeG = auditPublicKey.getG(g,(short)0);
        
        // modulus
        modN[0] = 0; // to avoid negative Modulus
        short sizeN = auditPublicKey.getR(modN,(short)1); 
        sizeN++;
        
        // generate c = H(G,Gs,Qns)
        
        md.reset();
        md.update(g,      (short)0, (short) sizeG);
        md.update(gs,     (short)0, (short) sizeAuditPublicKey);
        md.update(qns,    (short)0, (short) sizeQNS);         // Qn.s

       
  
        short sizeC = md.doFinal(buffer,(short) (ISO7816.OFFSET_CDATA+2),(short)(bytesRead-22),c,(short)0); // Qn


        
        // get dc
        dc[0] = 0; // just to guarantee that dc is a positive number and has the same size as ModN
        short sizeDC = li.getInstance(id).getPrivateKey().getS(dc,(short)1);
        sizeDC++;   
   
                       
        // generate a secret, i.e. Qn.dc (Qn is in the buffer - public key used during encryption)
        ka.init(li.getInstance(id).getPrivateKey()); // init using "dc"   

         
        
        // fill the correct number of bytes of C so that C and DC are the same size
        byte[] c1 = new byte[sizeDC];
        short offset = (short)(sizeDC-sizeC);
        for (short i=(short)0; i<offset; i++) c1[i] = (byte) 0x00;
        for (short i=(short)0; i<(short)sizeC; i++) c1[(short)(i+offset)] = c[i];
  
        
        setModulus(modN, sizeN);
        t = multiplyModByteArrays(c1, dc);  
        t = sumModByteArrays(t, s);



        // size of the Gs
        buffer[0] = (byte)(sizeAuditPublicKey & 0xFF);
         
        // size of the secret Qn.s
        buffer[1] = (byte)(sizeQNS & 0xFF);
        
        // size of t
        buffer[2] = (byte)(sizeModulus & 0xFF);

        // size of Qndc
        buffer[3] = (byte)(size & 0xFF);
        
        // return new audit public key (Gs),  Qns, and t = s + dc.c mod n, and Qndc
        short i = 4;
        for(short j=0; j<sizeAuditPublicKey; j++, i++) buffer[i] = gs[j];
        for(short j=0; j<sizeQNS; j++, i++) buffer[i] = qns[j];
        for(short j=0; j<sizeModulus; j++, i++) buffer[i] = t[j];     //changed as t seems too big for some reason
        for(short j=0; j<size; j++, i++) buffer[i] = secret[j]; 
       
        //value 4 is the number of bytes used for size information
        short sizeBuffer = (short) (sizeAuditPublicKey+sizeQNS+sizeModulus+size+4); 
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (sizeBuffer));
        apdu.sendBytesLong(buffer, (short) 0, (short) (sizeBuffer));
                
        return;
        
    }
 
    // ----------------------------------------------------------------------
    // Generates a public and a private key for a new instance
    // Returns the instance number (2 bytes) and the public key for that instance
    // APDU Format: 80 10 00 00 00
    private void keyGen(APDU apdu)
    {
    	
        byte  buffer[] = apdu.getBuffer();
        
        short id = li.createInstance();
        
        buffer[0] = (byte)(id >> 8);
        buffer[1] = (byte)(id & 0xFF);
        
        short ksize = li.getInstance(id).getPublicKey().getW(buffer, (byte)2);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (ksize+2));
        apdu.sendBytesLong(buffer, (short) 0, (short) (ksize+2));
       
        
    }
    
    // ----------------------------------------------------------------------
    // Receives a message and encrypts it using the instance key.
    // APDU Format: 80 20 P1 00 LC ... - P1 is one of the steps in the encryption process
    private void encrypt(APDU apdu)
    {
    	
        byte  buffer[] = apdu.getBuffer();
        short bytesRead = (short) (apdu.setIncomingAndReceive());
                
        short sizeReturn = 0;
        
        byte P1 = buffer[ISO7816.OFFSET_P1];
        
        if (P1 == 0x01) {
            // begin encryption protocol - return Qn = dn.G - ephemeral public key
            // APDU - 80 40 01 00 02 [instance]
            
            if (stateEncryption != 1) ISOException.throwIt(INVALID_ENCRYPTION_STATE);

            // get the instance for encryting the message - to get private key "dc"
            short id = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) + buffer[ISO7816.OFFSET_CDATA+1]);
            
            if (!li.isValid(id)) { stateEncryption = 1; ISOException.throwIt(INVALID_INSTANCE_ID); }
            
            // create the ephemeral public key "Qn = Gdn"
            kp.genKeyPair();
       
            ephemeralPublicKey  = (ECPublicKey)  kp.getPublic(); // Qn = Gdn
             
             
            // generate a secret, i.e. Qndc
            
            ka.init(li.getInstance(id).getPrivateKey()); // init using "dc"
                     
            short sizePublicKey = ephemeralPublicKey.getW(publicData,(short)0); // get byte array of Gdn
       
            
            short sizeSecret = ka.generateSecret(publicData,(short)0,sizePublicKey,secret, (short)0); // do Qndc (or dc.(Gdn))
             
            // create a symmetric key (kn) for encryption and another for a MAC kn using a hash function
            // due to the size of MAC created by SHA, we will add an extra byte to the
            // first MAC to generate the key (we apply SHA again). The same is done (with a different byte)
            // to create a key for MAC of the encrypted message.
            // h = SHA(secret); encKey = SHA(h+[new byte]); macKey = SHA(h+[another byte])
            
            //md.reset();
            //md.doFinal(secret,(short)0,sizeSecret,h,(short)0);
           
            Util.arrayCopy(secret,(short)(0),h,(short)0, (short)sizeSecret);
         
           
            md.reset(); 
            h[sizeSecret] = (byte) 0x01; // add another byte to generate the encryption key
            md.doFinal(h,(short)0,(short)(sizeSecret+1),encKey,(short)0);

            md.reset();
            h[sizeSecret] = (byte) 0x10; // add another byte to generate the mac key
            md.doFinal(h,(short)0,(short)(sizeSecret+1),macH,(short)0);

            md.reset();
            h[sizeSecret] = (byte) 0x11; // add another byte to generate the hash of the session (encryption) key
            md.doFinal(h,(short)0,(short)(sizeSecret+1),hashEncKey,(short)0);
            
            md.reset();
            md.doFinal(hashEncKey,(short)(0),(short)(20),hashEncKey,(short)0);

           
          
            // use the symmetric key to encrypt the incoming message using DES
            desKey.setKey(encKey, (short) 16); // get only the last 16 bytes from the MAC
            macKey.setKey(macH,(short)4);     // get only the last 16 bytes from the MAC
            
             
            // initialise the IV with random data 
            
            rd.generateData(iv, (short)0, (short)16);
      
            // initialize the cipher and macSig to encryption and signing
            cipher.init(desKey, Cipher.MODE_ENCRYPT, iv, (short) 0, (short)16); // AES expect a 16 byte array for IV
     
            macSig.init(macKey,Signature.MODE_SIGN);

            // now go to the state in which the message will be sent to be encrypted
            stateEncryption = 2;
            
            // return the public key Qn, i.e Gdn, IV and hash of the session key
            Util.arrayCopy(publicData,(short)(0),buffer,(short)0, sizePublicKey);
            Util.arrayCopy(iv,(short)0, buffer, sizePublicKey, (short)16);
            Util.arrayCopy(hashEncKey,(short)0, buffer, (short)(sizePublicKey+16), (short)20);
            sizeReturn = (short)(sizePublicKey+16+20);      
               
             
        } else if (P1 == 0x02) {  
          
            // main part of the encryption protocol - receives blocks and return them encrypted
            // APDU - 80 40 02 00 LC [data]

            if (stateEncryption != 2) ISOException.throwIt(INVALID_ENCRYPTION_STATE);

            // encrypt the block (part of the message)
            short cipherLen = cipher.update(buffer, (short) (ISO7816.OFFSET_CDATA), (short)(bytesRead),
                                             temporaryData, (short) 0);
                        
            // sign the ciphertext (block - part of the message)
            macSig.update(temporaryData,(short)0,cipherLen);

            // set the return value (encrypted message) and the return size
            Util.arrayCopy(temporaryData,(short)(0),buffer,(short)0, cipherLen);
            
            sizeReturn = cipherLen;

        } else if (P1 == 0x03) {
            // end of main part of the encryption protocol - return the last part of the encrypted message
            // APDU - 80 40 03 00 LC [data]
            
            if (stateEncryption != 2) ISOException.throwIt(INVALID_ENCRYPTION_STATE);
            
            // finalizes encryption
            short cipherLen = cipher.doFinal(buffer, (short) (ISO7816.OFFSET_CDATA), (short)(bytesRead),
                                             temporaryData, (short) 0);
            
            // finalizes signing
            macDataLen = macSig.sign(temporaryData,(short) 0, cipherLen, macData, (short) 0);
            
            // set the return value (last part of the encrypted message) and the size of the return value
            Util.arrayCopy(temporaryData,(short)(0),buffer,(short)0, cipherLen);
            
            sizeReturn = cipherLen;    
          
 
            // set the state to return the mac of the encrypted message
            stateEncryption = 3;
            
        } else if (P1 == 0x04) {
            // return the mac for the encrypted message
            // APDU - 80 40 04 00 00 
            
            if (stateEncryption != 3) ISOException.throwIt(INVALID_ENCRYPTION_STATE);
            
            // set the return value, i.e. the mac for the encrypted message, and its size
            Util.arrayCopy(macData,(short)(0),buffer,(short)0, macDataLen);

            sizeReturn = macDataLen;
            
            // set encryption state to its initial state, so new encryption can start again
            stateEncryption = 1;
              
        } else {
            // state of encryption not allowed
            ISOException.throwIt(INVALID_ENCRYPTION_PARAMETER);
        }     
            
        // send the return APDU with the set values   
        
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (sizeReturn));
        apdu.sendBytesLong(buffer, (short) 0, (short) (sizeReturn));

    	
        return;
        
    } // end encrypt
    
    // ---------------------------------------------------------------------------------
    // receives a message and decrypts it using the instance key and public ephemeral key.
    // APDU Format: 80 30 P1 00 LC ... - P1 is one of the steps in the decryption process
    private void decrypt(APDU apdu)
    {
    	
        byte buffer[] = apdu.getBuffer();
        short bytesRead = (short) (apdu.setIncomingAndReceive());
        short textLen = (short) 0;
        
        byte P1 = buffer[ISO7816.OFFSET_P1];

        if (P1 == 0x01) {
            // begin decryption protocol - receives Qn = Gdn - ephemeral public key - and IV used during encryption
            // APDU - 80 50 01 00 LC [instance id] [ephemeral public key] [iv - 8 bytes][hash of the session key]

            if (stateDecryption != 1) ISOException.throwIt(INVALID_DECRYPTION_STATE);
           
           
            // get the instance for encryting the message - to get private key "dc"
            short id = (short) ((buffer[ISO7816.OFFSET_CDATA] << 8) + buffer[ISO7816.OFFSET_CDATA+1]);
            
            if (!li.isValid(id)) { stateDecryption = 1; ISOException.throwIt(INVALID_INSTANCE_ID); }
            
            // generate a secret, i.e. Qn.dc            
            short size = (short) (buffer[ISO7816.OFFSET_LC] - 38); // size of the ephemeral public key Qn (ie, Gdn)
            
            Util.arrayCopy(buffer,(short)(ISO7816.OFFSET_CDATA+2),publicData,(short)0, size); // get Qn (Gdn)
             
          
            ka.init(li.getInstance(id).getPrivateKey()); // init using "dc"
            size = ka.generateSecret(publicData,(short)0,size,secret, (short)0); // set secret = Qn.dc
            
            // create a symmetric key (kn) for decryption using a hash function - same as
            // the one that was created during encryption.       
            Util.arrayCopy(secret,(short)(0),h,(short)0, (short)size);

            md.reset();
            h[size] = (byte) 0x01; // add another byte to generate the decryption key
            md.doFinal(h,(short)0,(short)(size+1),encKey,(short)0);

            md.reset();
            h[size] = (byte) 0x10; // add another byte to generate the mac key
            md.doFinal(h,(short)0,(short)(size+1),macH,(short)0);

            md.reset();
            h[size] = (byte) 0x11; // add another byte to generate the hash of the session key
            md.doFinal(h,(short)0,(short)(size+1),hashEncKey,(short)0);
            
            md.reset();
            md.doFinal(hashEncKey,(short)(0),(short)20,hashEncKey,(short)0);

            // check to see if the sent hash of the session key is the same as the new
            // hash of the session key just generated
            
            if (Util.arrayCompare(hashEncKey, (short) 0,
                                  buffer, (short)(ISO7816.OFFSET_CDATA+buffer[ISO7816.OFFSET_LC] - 20),
                                  (short)20) != (short)0) {
                
                ISOException.throwIt(INVALID_HASH_SESSION_KEY);
            }
            
            // use the symmetric key to encrypt the incoming message using AES
            
            desKey.setKey(encKey, (short)16); // get only the last 16 bytes from the MAC
            macKey.setKey(macH,(short)4);     // get only the last 16 bytes from the MAC
            
            
            
            // set cipher with desKey and IV that was received as a parameter in the APDU
            cipher.init(desKey, Cipher.MODE_DECRYPT, buffer, (short) (short)(ISO7816.OFFSET_CDATA+buffer[ISO7816.OFFSET_LC] - 36), (short)16);

            macSig.init(macKey,Signature.MODE_SIGN);

            sizeDecryptedData = 0;
            decryptedBytesReturned = 0;
            
            // now set state to decryption main part
            stateDecryption = 2;
            
           return;
           
        } else if (P1 == 0x02) {

            // do the decryption
            // APDU - 80 50 02 00 LC [ciphertext]
            
            if (stateDecryption != 2) ISOException.throwIt(INVALID_DECRYPTION_STATE);
            
            if ((short)(buffer[ISO7816.OFFSET_LC]+sizeDecryptedData) > DECRYPTED_DATA_SIZE)
                ISOException.throwIt(INVALID_DECRYPTION_SIZE);
            
            textLen = cipher.update(buffer, (short) (ISO7816.OFFSET_CDATA),
                                           (short)(bytesRead), temporaryData, (short) 0);
            

            // sign the ciphertext (block - part of the message)
            macSig.update(buffer,(short) (ISO7816.OFFSET_CDATA),bytesRead);
            
            // stores plaintext to be sent if the mac is correct
            Util.arrayCopy(temporaryData,(short)(0),decryptedData,(short)sizeDecryptedData, textLen);
            
            sizeDecryptedData += textLen;
            
            // return - plaintext is only returned when mac is checked
            
            return;

            
        } else if (P1 == 0x03) {
            // end decryption protocol
            // APDU - 80 50 03 00 LC [last piece of the ciphertex]
            
            if (stateDecryption != 2) ISOException.throwIt(INVALID_DECRYPTION_STATE);
            
            if ((short)(buffer[ISO7816.OFFSET_LC]+sizeDecryptedData) > DECRYPTED_DATA_SIZE)
                ISOException.throwIt(INVALID_DECRYPTION_SIZE);

            textLen = cipher.doFinal(buffer, (short) (ISO7816.OFFSET_CDATA),
                                          (short)(bytesRead), temporaryData, (short) 0);
                        
 
            // finalizes signing - this MAC will be tested against the one the host holds
            macDataLen = macSig.sign(buffer,(short) (ISO7816.OFFSET_CDATA), bytesRead, macData, (short) 0);

            // stores plaintext to be sent if the mac is correct
            Util.arrayCopy(temporaryData,(short)(0),decryptedData,(short)sizeDecryptedData, textLen);
            
            sizeDecryptedData += textLen;
            
            // return - plaintext is only returned when mac is checked
            
            stateDecryption = (short)3;

            return;
        
        } else if (P1 == 0x04) {
            // check mac
            // APDU - 80 50 04 00 LC [MAC]
        
            if (stateDecryption != 3) ISOException.throwIt(INVALID_DECRYPTION_STATE);
            
            for (short j = (short)0; j<(short)bytesRead; j++)
                if (macData[j] != buffer[(short)(ISO7816.OFFSET_CDATA+j)])
                    ISOException.throwIt(INVALID_DECRYPTION_MAC);
            
            // the received Mac and the calculated mac are equal
 
            stateDecryption = (short) 4;
            
            return;
        
        
        } else if (P1 == 0x005) {
            // return bytes of the plaintext
            // APDU - 80 50 04 00 00
            
            if (stateDecryption != 4) ISOException.throwIt(INVALID_DECRYPTION_STATE);
            
            short bytesToReturn = (sizeDecryptedData <= 224 ? sizeDecryptedData : 224);
            
            sizeDecryptedData -= bytesToReturn;
            
            Util.arrayCopy(decryptedData,(short) decryptedBytesReturned ,buffer,(short)0, bytesToReturn);
            
            decryptedBytesReturned += bytesToReturn;
            
            // Send results
            apdu.setOutgoing();
            apdu.setOutgoingLength((short) bytesToReturn );
            apdu.sendBytesLong(buffer, (short) 0, (short) bytesToReturn );
            
            // check to see if every byte was returned
            if (sizeDecryptedData <= 0){
                stateDecryption = 1;
                
                // signal the host that there is no more bytes in the plaintext

                ISOException.throwIt((short)0x0001);
            }
            
        }
      
    }
        
    
     // =============================================================================
    // Auxiliary functions
    // =============================================================================
    
    
    // -----------------------------------------------------------------------------
    // Return true if a is greater of equal to b
    // It does not consider the most significative bit, ie it considers both
    // arrays as being positive. Arrays have to have the Modulus size.
    // Set Modulus has to be called prior to this function.
    // YES - CAN BE DONE IN A DIFFERENT WAY :-)
   private boolean compareByteArrays(byte[] a, byte[] b) {
        
        for (short j = (short)0; j<(short)sizeModulus; j++) 
            if ((short)((short)a[j]&(short)0x00FF) > (short)((short)b[j]&(short)0x00FF))
                return true; // a is greater than b
            else if ((short)((short)b[j]&(short)0x00FF) > (short)((short)a[j]&(short)0x00FF))
                return false; // be is greater than a
        
        return true; // they are equal

    }
    
    // -----------------------------------------------------------------------------
    // Sum two byte arrays of same Modulus size.
    // The result is stored in sumResult - this is just for performance reasons and
    // could be changed to return a byte array. setModulus has to be called prior to
    // calling this function
    // YES - CAN BE DONE IN A DIFFERENT WAY :-)
    private void sumByteArrays(byte[] a, byte b[]) 
    {
        short v1,v2;
        byte carry;

        carry = (byte)0x00;
        
        for (short i = (short)(sizeModulus - 1); i >=(short) 0; i--) 
        {
            v1 = (short) ((short)a[i] & (short)0x00FF);
            v2 = (short) ((short)b[(short)i] & (short)0x00FF);
            Util.setShort(shortArray,(short)0,(short) (v1 + v2 + (short)carry));
            sumResult[i] = shortArray[1];
            if ((short)shortArray[0] != (short)0) carry = (byte)0x01;
            else carry = (byte)0x00;
        }
        
    }

    // -----------------------------------------------------------------------------
    // Sum two byte arrays of same Modulus size. setModulus have to be called before.
    private byte[] sumModByteArrays(byte[] a, byte b[]) {
        
        boolean on;
        
        sumByteArrays(a,b);
        Util.arrayCopy(sumResult,(short)(0),sumModResult,(short)0, (short)sizeModulus);
                
        if (compareByteArrays(sumModResult, modulus)) { // calculate the modular operation
            
            // sumModResult = sumModResult + (-modulus)
            // now sum the complement with sumModResult
            
            sumByteArrays(sumModResult, minusModulus);
            Util.arrayCopy(sumResult,(short)(0),sumModResult,(short)0, (short)sizeModulus);
        }
        
        return sumModResult;
    }
    
    // -----------------------------------------------------------------------------
    // Set modulus and sizeModulus that will be used in other operations
    // This routine has to be called prior to multiplyModByteArrays and sumModByteArrays
    private void setModulus(byte[] mod,  short len) {
        // set modulus and sizeModulus variables
        Util.arrayCopy(mod, (short)0, modulus, (short)0, len);
        sizeModulus = len;
        
        // get (- modulus): complement modulus
        for (short i=(short)0; i<(short)sizeModulus; i++) minusModulus[i] = (byte) ((short)modulus[i] ^ (short)0x00FF);
        Util.arrayFillNonAtomic(one,(short)0,(short)(sizeModulus-1), (byte) 0x00 );
        one[(short)(sizeModulus-1)] = (byte) 0x01;
        sumByteArrays(minusModulus, one);  // 2's complement, ie, (not modulus) + 00..01
        Util.arrayCopy(sumResult,(short)(0),minusModulus,(short)0, (short)sizeModulus);
        
    }
    
    // -----------------------------------------------------------------------------
    // Muliply two byte arrays. Byte arrays have to be the same size of sizeModulus.
    // before calling this routine, setModulus has to be called.
    // It won't work if these two requirements are not met.
    private byte[] multiplyModByteArrays(byte[] a, byte b[]) {
        
        boolean on;
        byte tmp;
        short i, j;
        short indexArray; // right to left
        short indexByte;
        
        short rightShifts, leftShifts;
        short previousByte;
        
        
        Util.arrayCopy(a,(short)(0),shift,(short)0, (short)sizeModulus);
        Util.arrayFillNonAtomic(multiplyModResult,(short)0,sizeModulus, (byte) 0x00 );
        
        
        // for every bit in b
        short nbits = (short) (sizeModulus*8);
        for (i=(short)0; i<(short)nbits; i++) {
            
            indexArray = (short) (sizeModulus - (i / (short)8) - (short)1); // right to left
            indexByte  = (short) (i % (short)8);
            
            on = (b[indexArray] & (short)((short)0x0001 << indexByte)) != (short)0;
            
            if (on) {
                
                // modular sum begins - I did it here to avoid another function call
                // sumModResult = multiplyModResult + shift
                
                sumByteArrays(multiplyModResult, shift);
                Util.arrayCopy(sumResult,(short)(0),sumModResult,(short)0, (short)sizeModulus);
                
                // if sumModResult >= modulus
                if (compareByteArrays(sumModResult,modulus)) { // calculate the modular operation
                    // sumModResult = sumModResult + (-modulus)
                    // now sum the complement with sumModResult
                    
                    sumByteArrays(sumModResult, minusModulus);
                    Util.arrayCopy(sumResult,(short)(0),sumModResult,(short)0, (short)sizeModulus);
                }
                
                Util.arrayCopy(sumModResult,(short)(0),multiplyModResult,(short)0, (short)sizeModulus);
                // end modular sum 
            }
            // 
            previousByte = shift[(short)(sizeModulus-1)]; // keep the byte before modification
            shift[(short)(sizeModulus-1)] = (byte) ((shift[(short)(sizeModulus-1)] & (short)0xff) << (short)1);
            for (j = (short)(sizeModulus-2); j >= (short)0; j--) {
                tmp = shift[j];
                shift[j] = (byte) (((shift[j] & (short)0xff) << (short)1) | ((previousByte &(short) 0xff)>> (short)7));
                previousByte = tmp;
            }
            
            // if sumModResult >= modulus
            if (compareByteArrays(shift,modulus)) { // calculate the modular operation
                // sumModResult = sumModResult + (-modulus)
                // now sum the complement with sumModResult
                
                sumByteArrays(shift, minusModulus);
                Util.arrayCopy(sumResult,(short)(0),shift,(short)0, (short)sizeModulus);
            }
            
        }
        return multiplyModResult;
    } // end multiply byte arrays using modulus


}












