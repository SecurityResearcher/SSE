/*
A series of experiments to assess the perfomance of a JavaCard based secure deletion system. 
Each experiment conists of creating a file of the required size, encrypting the file, decrypting it, checking that the two files match, and then securely deleting the file.
End to end measurements are provided for the time taken to encrypt, decrypt and receive confirmation of deletion for each file. 
The communication parts of this code are based on test code written by *** name anonymized to allow blind reviewing  ***

 Author: *** name anonymized to allow blind reviewing  ***
 Date:   *** Removed ***
 */

import java.io.*;
import java.util.List;
import java.util.ListIterator;
import java.util.Scanner;
import java.math.BigInteger;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.util.Date;

import java.security.MessageDigest;

import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import java.math.BigInteger;
import org.bouncycastle.math.ec.*;

import javax.smartcardio.*;


public class SecureDeletionExperiment 
{

	//EXPERIMENT CONSTANTS
	//file size in bytes, must be multiple of 128
	final static int[] FILE_SIZES = {128,256,512,1024}; // experiments will be performed for these file sizes.
	final static int MAX_FILE_SIZE = 10000; // size in bits
	final static int EXPERIMENTS = 30;  //number of experiments to be performed for each file size
	final static String CSV_FILENAME = "deletionresults.csv"; //filename to use for results file
	final static String PLAINTEXT_FILENAME = "plaintext.txt"; //filename to use for plaintext
	final static String CIPHERTEXT_FILENAME = "encrypted.enc"; //filename to use for ciphertext
	final static String DECRYPTED_FILENAME = "decrypted.dec"; //filename to use for decrypted text
	
	//JAVACARD COMMUNICATION CONSTANTS
	private byte[] atr = null;
    private String protocol = null;
    private byte[] historical = null;

    final static String SELECTAPDU       = "00A40400050102030409";
    final static String KEYGENAPDU       = "8010000000";
    
    final static String BEGINENCRYPTAPDU = "8020010002";
    final static String ENCRYPTAPDU      = "80200200";
	final static String AUDITAPDU      = "80400000";
    final static String ENDENCRYPTAPDU   = "8020030000";
    final static String MACENCRYPTAPDU   = "8020040000";
    final static String BEGINDECRYPTAPDU = "80300100";
    final static String DECRYPTAPDU      = "80300200";
    final static String ENDDECRYPTAPDU   = "8030030000";
    final static String CHECKMACDECRYPTAPDU   = "80300400";
    final static String GETDECRYPTEDAPDU      = "8030050000";
    final static String GETECDATAAPDU      = "8060000000";
    final static String DELETEAPDU        = "8050000002";
    final static String TIMEOUTAPDU      = "FF00417F00"; // set to 7F sec - this is necessary if any operation
                                                         // in the javacard take a long time. Otherwise you can
                                                         // get a response code, like 6300.
    
    final static int    APDUBLOCKSIZE    = 224; // max to send is 255, but it is better to send multiples of 32
                                                // considering the way memory is allocated in the javacard
    final static String HEXBLOCKSIZE     = "E0";
    final static int    BLOCKSIZE        = 384; // it can be 512 - 8 extra bytes for padding
    byte[] epk; // ephemeral public key
	
	//governs whether debugging output is sent to console
	final static boolean DEBUG = false;
	
	//constants for auditing
	byte[] ecA ;
    byte[] ecB ;
    byte[] ecG ;
    byte[] ecP ;
    byte[] ecMod;
    short ecK;
    int sizeECG, sizeECMod, sizeECA, sizeEC, sizeECB, sizeECP;
	
	
    public static void main(String[] args) 
	{
	
		//initialize a variable for timing 
		long timeElapsed;
		try
		{
			//create csv file
			FileWriter csv = new FileWriter(CSV_FILENAME,true);
			//inset column names
			csv.write("Size(bytes),Encryption Time(ms),Decryption Time(ms),Audit Time(ms),Deletion Time(ms)\n");
			csv.close();
			//File variables for reading in plaintext
			FileInputStream fis;
			int nread=0;
			byte[] plainTextBytes = new byte[MAX_FILE_SIZE+1]; /* used to read bytes from the file */
			byte[] cipherTextBytes = new byte[MAX_FILE_SIZE+1]; /* used to read bytes from the file */		
			
			//connect to card
			SecureDeletionExperiment jcr = new SecureDeletionExperiment();
            ResponseAPDU r = new ResponseAPDU(new byte[3]);
            byte[] apdu;
            
			CardTerminal ct = jcr.getCardTerminal();
                
            Card c = null;
                
            if(ct != null)
            {
                c = jcr.connectToCard(ct);
                        
                if (c != null) 
				{ /** there is a card on the reader **/
					CardChannel cc = c.getBasicChannel();
                       
					/* Connect to card - select application */
					apdu = jcr.hexStringToByteArray(SELECTAPDU);
					System.out.println("TRANSMIT: "+jcr.byteArrayToHexString(apdu));
					r = cc.transmit(new CommandAPDU(apdu));
					System.out.println("RESPONSE: "+jcr.byteArrayToHexString(r.getBytes()));
                        
					// set timeout
                    apdu = jcr.hexStringToByteArray(TIMEOUTAPDU);
                    System.out.println("TRANSMIT selec: "+jcr.byteArrayToHexString(apdu));
                    r = cc.transmit(new CommandAPDU(apdu));
                    System.out.println("RESPONSE: "+jcr.byteArrayToHexString(r.getBytes()));
		
					//loop through file sizes
					for (int i=0; i<FILE_SIZES.length;i++)
					{
						//loop through number of experiments
						for (int j=0; j<EXPERIMENTS;j++)
						{
							csv = new FileWriter(CSV_FILENAME,true);
						
							//create file of correct length
							FileWriter plainText = new FileWriter(PLAINTEXT_FILENAME,false);
							for (int k=0;k<FILE_SIZES[i];k++)
							{
								plainText.write("a");
							}
							plainText.close();
							
							//open csv file and add file size
							csv.write(FILE_SIZES[i]+",");
							
							//get plaintext
							fis = new FileInputStream(PLAINTEXT_FILENAME);            /* File to analyse */
							nread = fis.read(plainTextBytes);
							fis.close();
							//start timer
							timeElapsed = new Date().getTime();
							
							//encrypt file
							jcr.encryptData(nread, plainTextBytes, cc);
							
							//measure time
							timeElapsed = (new Date().getTime() - timeElapsed);
							
							//open csv file and add encryption time
							csv.write(timeElapsed+",");
							
							//get ciphertext
							fis = new FileInputStream(CIPHERTEXT_FILENAME);            /* File to analyse */
							nread = fis.read(cipherTextBytes);
							fis.close();
							
							//start timer
							timeElapsed = new Date().getTime();
						
							//decrypt file
							jcr.decryptData(nread,cipherTextBytes, cc);
							
							//measure time
							timeElapsed = (new Date().getTime() - timeElapsed);
							
							//open csv file and add decryption time
							csv.write(timeElapsed+",");
							
							//start timer
							timeElapsed = new Date().getTime();
									
							//audit data
							jcr.getECValues(cc);
							jcr.auditData(nread,cipherTextBytes, cc);
							
							//measure time
							timeElapsed = (new Date().getTime() - timeElapsed);
							
							//open csv file and add audit time
							csv.write(timeElapsed+",");
							
							//start timer
							timeElapsed = new Date().getTime();
							
							//secure delete file
							jcr.delete(nread,cipherTextBytes, cc);
							
							//measure time
							timeElapsed = (new Date().getTime() - timeElapsed);
							
							//open csv file and add deletion time and carriage return
							csv.write(timeElapsed+"\n");
							
							//delete encrypted and decrypted files
							File a = new File(PLAINTEXT_FILENAME);
							a.delete();
							a = new File (CIPHERTEXT_FILENAME);
							a.delete();
							a = new File (DECRYPTED_FILENAME);
							a.delete();							
							csv.close();
						}
					}
				}
			}
					
					

		}
		catch (Exception e)
		{
            System.out.println("Exiting with an error.");
			System.out.println(e);
		}
		
	
	}
	
	  // ==========================================================================
    // Auxiliary functions - conversion from byte arrays to string and vice-versa
    // ==========================================================================

    public String byteArrayToHexString(byte[] b)
    {
        StringBuffer sb = new StringBuffer(b.length * 2);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xff;
            if (v < 16) {
               sb.append('0');
            }
            sb.append(Integer.toHexString(v));
        }
        return sb.toString().toUpperCase();
    }

    public static byte[] hexStringToByteArray(String s)
    {
            int len = s.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2)
            {
                data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
            }
            return data;
    }
	
	
     // ==========================================================================
    // Auxiliary functions - to connect to card terminal and terminal
    // ==========================================================================
  
    public CardTerminal getCardTerminal()
    {
        CardTerminal terminal = null;
        try
        {
                // show the list of available terminals
                TerminalFactory factory = TerminalFactory.getDefault();
                        
                List<CardTerminal> terminals = factory.terminals().list();
                                                                        
                terminal = terminals.get(0);
                        
                if (terminal != null) {
                     System.out.println("Selected: "+terminal.getName());
                }

        } catch(Exception e)
        {
            // System.err.println("Error occured:");
        }
        return terminal;
    }

 
    public Card connectToCard(CardTerminal ct)
    {
      
        Card card = null;
        String p = "T=0"; /* type of protocol to be established with the card */
                          /*   T=0 block oriented t=1 byte oriented           */

        try
        {
            card = ct.connect(p);
        }
        catch (CardException e)
        {
            System.err.println("Got an exception:"+e);
            return null;
        }
        ATR atr = card.getATR();
        System.out.println("Connected to :");
        System.out.println(" - ATR:  "+ byteArrayToHexString(atr.getBytes()));
        System.out.println(" - Historical: "+ byteArrayToHexString(atr.getHistoricalBytes()));
        System.out.println(" - Protocol: "+card.getProtocol());
        
        this.atr = atr.getBytes();
        this.historical = atr.getHistoricalBytes();
        this.protocol = card.getProtocol();
        
        return card;
                
    }
    
    // ==========================================================================
    // Functions to encrypt/decrypt/audit/delete
    // ==========================================================================

    // ------------------------------------------------------------------------------------------
    // receives the size of data to be encrypted, data to be encrypted and channel to javacard
    // The encrypted file format will be as follows:
    // 2 Bytes that contains the instance number | 1 byte for the size of the public key of this
    // instance | public key for this instance | [Blocks]
    // Each block has the following format:
    // 1 byte for the ephemeral public key of the block | ephemeral public key | 8 bytes to store the IV |
    // 20 bytes of the hash of the session key |
    // 2 bytes to store the size of the ciphertext | ciphertext | 1 byte for the size of MAC | MAC
    // ------------------------------------------------------------------------------------------
    public void encryptData(int nread, byte[] dataBytes, CardChannel cc)
    {
        ResponseAPDU r = new ResponseAPDU(new byte[3]);
        byte[] apdu;
        byte[] resp;
        FileOutputStream fos = null;
        byte[] buffer = new byte[BLOCKSIZE+8]; // sometimes there is a padding of at most 8 bytes
        int posBuffer = 0;

        try 
		{      
            apdu = this.hexStringToByteArray(KEYGENAPDU);
            r = cc.transmit(new CommandAPDU(apdu));
            resp = r.getBytes();
            if (DEBUG) System.err.println("encryptData: RESPONSE - from keygen: "+this.byteArrayToHexString(resp));
            // two first bytes have the instance number - other bytes are the public key for that
            // instance - not using it at the moment
            byte[] instance = {resp[0], resp[1]};
            
            // other bytes have the public key
            byte[] pubkey = new byte[resp.length-4]; // minus 2 first bytes and last 2 (response code)
            int sizePublicKey = pubkey.length;
            for (int i=0; i<sizePublicKey; i++) pubkey[i] = resp[i+2];
                       
            try {
                /* File to store encrypted data - file name contains the instance of the file in the javacard */
                fos = new FileOutputStream(CIPHERTEXT_FILENAME);
            } catch (Exception e) {
                System.out.println("Error openning file during encryption.");
                System.exit(1);
            }
            
            fos.write(instance[0]);            // write the instance code
            fos.write(instance[1]);            // to the file
            fos.write(sizePublicKey);          // write the size of the public key
            fos.write(pubkey,0,pubkey.length);          // write the public key to the file

            // encrypts in blocks of BLOCKSIZE - this is done, for a posterior AUDIT Operation
            // BLOCKSIZE is the size of a transient array in the javacard
            
            int total = nread;
            int nBytesRound = (total < BLOCKSIZE ? total : BLOCKSIZE);
            int pos = 0;
            if (DEBUG) System.out.println("encryptData: Total = "+total+" nBytesRound = "+nBytesRound);
            int bytesRound = nBytesRound;
            int count = 0;
            while (total > 0) {
                // Start encryption protocol
                apdu = this.hexStringToByteArray(BEGINENCRYPTAPDU+this.byteArrayToHexString(instance));
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("encryptData: RESPONSE - from start encryption: "+this.byteArrayToHexString(resp));
                
                if (DEBUG) {
                    System.err.print("encrypt: HASH ENC KEY = ");
                    for (int i=resp.length-22;i<resp.length-2;i++) System.err.format("%02X",resp[i]);
                    System.err.println();
                }

            
                int sizeEphemeralPublicKey = resp.length-38; // 2 for the response code and 16 for IV and 20 for the hash of the session key
            
                fos.write(sizeEphemeralPublicKey);         // write the size of the ephemeral public key
                fos.write(resp,0,resp.length-30);          // write the ephemeral public key to the file
                fos.write(resp,(resp.length-30), 8);       // write IV to the file
                fos.write(resp,(resp.length-22), 20);      // write hash of the session key to the file
                
                if (DEBUG) System.out.println("encryptData: bytesRound = "+bytesRound+" "+(((bytesRound+28) & 0xFF00)>>8)+" "+(((bytesRound+28) & 0x00FF)));
                

                posBuffer = 0;
                while (bytesRound >= APDUBLOCKSIZE) {
                    byte[] temp = new byte[APDUBLOCKSIZE];
                    for (int i=0; i<APDUBLOCKSIZE; i++) temp[i] = dataBytes[pos+i];
            
                    apdu = this.hexStringToByteArray(ENCRYPTAPDU+HEXBLOCKSIZE+this.byteArrayToHexString(temp));
                    if (DEBUG) System.err.println("encryptData: TRANSMIT: "+this.byteArrayToHexString(apdu));
                    long start = System.currentTimeMillis();
                    
                    r = cc.transmit(new CommandAPDU(apdu));
                    
                    long end = System.currentTimeMillis();
                   // System.out.println(count+";"+(end-start));
                    count++;
                    
                    resp = r.getBytes();
                    if (DEBUG) System.err.println("encryptData: RESPONSE encryption: "+this.byteArrayToHexString(resp));
             
                    // store received bytes in buffer
                    for (int i=0; i<resp.length-2; i++) buffer[posBuffer++] = resp[i];
                    
                    pos += APDUBLOCKSIZE;
                    bytesRound -= APDUBLOCKSIZE;
                }
                // now encrypt the last bytes of the block
                if (bytesRound > 0) {
                    byte[] temp = new byte[bytesRound];
                    byte[] size = {(byte) bytesRound};
                
                    for (int i=0; i<bytesRound; i++) temp[i] = dataBytes[pos+i];
                
                    apdu = this.hexStringToByteArray(ENCRYPTAPDU+this.byteArrayToHexString(size)+this.byteArrayToHexString(temp));
                    if (DEBUG) System.err.println("encryptData: TRANSMIT: "+this.byteArrayToHexString(apdu));
                    r = cc.transmit(new CommandAPDU(apdu));
                    resp = r.getBytes();
                    if (DEBUG) System.err.println("encryptData: RESPONSE encryption last: "+this.byteArrayToHexString(resp));
                    
                    // store received bytes in buffer
                    for (int i=0; i<resp.length-2; i++) buffer[posBuffer++] = resp[i];
                   
                    pos += bytesRound;
                }
            
                // End encryption protocol
                apdu = this.hexStringToByteArray(ENDENCRYPTAPDU);
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("encryptData: RESPONSE end encryption: "+this.byteArrayToHexString(resp));
                            
                // store received bytes in buffer
                for (int i=0; i<resp.length-2; i++) buffer[posBuffer++] = resp[i];

                // write all encrypted bytes to the file - first the number of encrypted bytes
                fos.write((posBuffer & 0xFF00)>>8);
                fos.write((posBuffer & 0x00FF));
                fos.write(buffer,0,posBuffer);
                
                // get the mac for the encrypted block
                apdu = this.hexStringToByteArray(MACENCRYPTAPDU);
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("encryptData: RESPONSE mac encryption: "+this.byteArrayToHexString(resp));

                fos.write(resp.length-2);
                fos.write(resp,0,resp.length-2);
                
                // do the next block if there is still bytes to encrypt
                total -= nBytesRound;
                bytesRound = (total < BLOCKSIZE ? total : BLOCKSIZE);
                
            }
            
        } catch (Exception e) {
            System.err.println("encryptData: Error while transmiting data to javacard."+e);
        }
    }
	
	  // ------------------------------------------------------------------------------------------
    // receives the size of data to be decrypted, data to be decrypted and channel to javacard
    // Decrypts file according to the structure that was created in the encryption routine
    // Remember that the CryptoDSE, only allows access to the plaintext, once all ciphertext
    // of block was sent to the card, so it can calculate the MAC for the ciphertext again, and then
    // this routine sends the stored MAC to the javacard to check whether the MAC is correct
    // ------------------------------------------------------------------------------------------
    public void decryptData(int nread, byte[] dataBytes, CardChannel cc)
    {
        ResponseAPDU r = new ResponseAPDU(new byte[3]);
        byte[] apdu;
        byte[] resp;
        byte[] instance = {dataBytes[0], dataBytes[1]};
        FileOutputStream fos = null;
        int skip;        
        
        try {
            /* File to store decrypted data - file name contains the instance of the file in the javacard */
            fos = new FileOutputStream(DECRYPTED_FILENAME);
        } catch (Exception e) {
            System.err.println("decryptData: Error openning file.");
            System.exit(1);
        }

        // 3rd byte in the encrypted file contains
        // the size of the public key
        
        int sizePublicKey = (int) dataBytes[2];

        byte[] pubkey = new byte[sizePublicKey];
        
        // gets the public key from file
        for (int i=0; i<sizePublicKey; i++) pubkey[i] = dataBytes[i+3];

        // do the following for as many blocks there are in the file
        
        int  pos = 3+sizePublicKey;
        int total = nread - 3 - sizePublicKey;
        int sizeOfMac=8, sizeOfBlock=512;
        int count =0;
        while (total > 0) { // is there a block to be decrypted?
            
            // now get the size of ephemeral public key
            int sizeEphemeralPublicKey = (int) dataBytes[pos];
 
            byte[] epubkey = new byte[sizeEphemeralPublicKey];
        
            // gets the ephemeral public key from file
            pos +=1; // skips the size of the ephemeral public key
            for (int i=0; i<sizeEphemeralPublicKey; i++) epubkey[i] = dataBytes[i+pos];
        
            // gets the IV from the file
            pos += sizeEphemeralPublicKey; // skip the bytes of the ephemeral public key
        
            byte[] iv = new byte[16];
        
            for (int i=0; i<16; i++) iv[i] = dataBytes[i+pos];

            // gets the hash of the session key from the file
            pos += 16; // skip the bytes of the iv
            
            byte[] hashEncKey = new byte[20];
            
            for (int i=0; i<20; i++) hashEncKey[i] = dataBytes[i+pos];
            
            if (DEBUG) {
                System.err.print("decrypt: HASH ENC KEY = ");
                for (int i=0;i<20;i++) System.err.format("%02X",hashEncKey[i]);
                System.err.println();
            }

            pos += 20; // skip the bytes of the hash of the session key
        
            byte[] lc = {(byte)(18+sizeEphemeralPublicKey+20)}; // set the number of bytes to send
                                                                // 2 bytes for the instance plus 16 bytes for the iv
                                                                // plus the size of the ephemeral public key
                                                                // plus the size of the hash of the session key
        
            try {
            
                // Start decryption protocol
                apdu = this.hexStringToByteArray(BEGINDECRYPTAPDU+this.byteArrayToHexString(lc)+
                                             this.byteArrayToHexString(instance)+this.byteArrayToHexString(epubkey)+
                                             this.byteArrayToHexString(iv)+this.byteArrayToHexString(hashEncKey));
                if (DEBUG) System.err.println("decryptData: TRANSMIT begin decription: "+this.byteArrayToHexString(apdu));
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("decryptData: RESPONSE begin decryption: "+this.byteArrayToHexString(resp));
                
                int codeResp = ((resp[resp.length-2]&0x00FF)<<8) + (resp[resp.length-1] & 0x00FF);
                if (codeResp == 0xAF1) {
                    System.out.println("Instance does not exist - it has already been deleted!");
                    System.exit(1);
                }
            
                nread = (dataBytes[pos] << 8) + (dataBytes[pos+1] & 0x00FF); // number of bytes in the block - skip that byte
                pos += 2; // skip the size of the block
                
                sizeOfBlock = nread;  // store the size of block for later
                            
                while (nread >= APDUBLOCKSIZE) {
                    byte[] temp = new byte[APDUBLOCKSIZE];
                    for (int i=0; i<APDUBLOCKSIZE; i++) temp[i] = dataBytes[pos+i];
                
                    apdu = this.hexStringToByteArray(DECRYPTAPDU+HEXBLOCKSIZE+this.byteArrayToHexString(temp));
                    if (DEBUG) System.out.println("decryptData: TRANSMIT: "+this.byteArrayToHexString(apdu));
                    long start = System.currentTimeMillis();

                    r = cc.transmit(new CommandAPDU(apdu));
                   
                    long end = System.currentTimeMillis();
                    count++;

                    resp = r.getBytes();
                    if (DEBUG) System.out.println("decryptData: RESPONSE: "+this.byteArrayToHexString(temp));
                                
                    pos += APDUBLOCKSIZE;
                    nread -= APDUBLOCKSIZE;
                }
                // now decrypt the last bytes, but the last MACSIZE
                if (nread > 0) {
                    byte[] temp = new byte[nread];
                    byte[] size = {(byte) nread};
                
                    for (int i=0; i<nread; i++) temp[i] = dataBytes[pos+i];
                
                    apdu = this.hexStringToByteArray(DECRYPTAPDU+this.byteArrayToHexString(size)+this.byteArrayToHexString(temp));
                    if (DEBUG) System.err.println("decryptData: TRANSMIT decryption last: "+this.byteArrayToHexString(apdu));
                    r = cc.transmit(new CommandAPDU(apdu));
                    resp = r.getBytes();
                    if (DEBUG) System.err.println("decryptData: RESPONSE decryption last: "+this.byteArrayToHexString(resp));
                
                    pos += nread;
                    nread -= nread;
                }
                
                // End decryption protocol
                apdu = this.hexStringToByteArray(ENDDECRYPTAPDU);
                if (DEBUG) System.err.println("decryptData: TRANSMIT end decryption: "+this.byteArrayToHexString(apdu));
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("decryptData: RESPONSE end decryption: "+this.byteArrayToHexString(resp));
                
                sizeOfMac = dataBytes[pos];
                
                pos += 1; // skip size of mac
                
                byte[] mac = new byte[sizeOfMac];
                for (int i=0; i<sizeOfMac; i++) mac[i] = dataBytes[pos+i];
                
                lc[0] = (byte) (sizeOfMac & 0x00FF);

                // send MAC stored in the file for that block, so the javacard can check whether the
                // MAC corresponds to the block that was just decrypted
                apdu = this.hexStringToByteArray(CHECKMACDECRYPTAPDU+this.byteArrayToHexString(lc)+this.byteArrayToHexString(mac));
                if (DEBUG) System.err.println("decryptData: TRANSMIT check mac: "+this.byteArrayToHexString(apdu));
                r = cc.transmit(new CommandAPDU(apdu));
                resp = r.getBytes();
                if (DEBUG) System.err.println("decryptData: RESPONSE check mac: "+this.byteArrayToHexString(resp));
                
                pos += sizeOfMac; // skip  mac
                
                // now get plaintext
                
                boolean hasBytes = true;
                while (hasBytes) {
                    apdu = this.hexStringToByteArray(GETDECRYPTEDAPDU);
                    if (DEBUG) System.err.println("decryptData: TRANSMIT receive data: "+this.byteArrayToHexString(apdu));
                    r = cc.transmit(new CommandAPDU(apdu));
                    resp = r.getBytes();
                    if (DEBUG) System.err.println("decryptData: RESPONSE receive data: "+this.byteArrayToHexString(resp));
                   
                    fos.write(resp, 0, resp.length-2);
                    
                    hasBytes = (resp[resp.length-1] != 0x01);
                    
                }

            } catch (Exception e) {
                System.err.println("decryptData: Error while transmiting data to javacard."+e);
            }
            
            // minus control values: 1:byte of sizeofephemeralkey; 8:bytes of IV; 20: hash session key 2:bytes of sizeofblock; 1: byte of sizeofmac
            total = total - sizeEphemeralPublicKey - 1 - 16 - 20 - 2 - 1 - sizeOfMac;
            
            total -= sizeOfBlock; // reduces the size of the block to see if there is still bytes to be read
            
            
        } 
        
    }
    
    // ------------------------------------------------------------------------------------------
    // get values for the elliptic curve
    // ------------------------------------------------------------------------------------------
    public void getECValues(CardChannel cc) {
        ResponseAPDU r = new ResponseAPDU(new byte[3]);
        byte[] apdu;
        byte[] resp;
        
        try 
		{
        
        apdu = this.hexStringToByteArray(GETECDATAAPDU);
        if (DEBUG) System.err.println("getECValues: TRANSMIT: "+this.byteArrayToHexString(apdu));
        r = cc.transmit(new CommandAPDU(apdu));
        resp = r.getBytes();
        if (DEBUG) System.err.println("getECValues: RESPONSE: "+this.byteArrayToHexString(resp));
            
        sizeECG = (resp[0]&0x00FF);
        sizeECMod= (resp[1]&0x00FF);
        sizeECA  = (resp[2]&0x00FF);
        sizeECB  = (resp[3]&0x00FF);
        sizeECP  = (resp[4]&0x00FF);
        
        ecK = (short) (((resp[5] & 0x00FF) << 8) + (resp[6] & 0x00FF));
            
        if (DEBUG) System.err.println("getECValues: sizeECG = "+sizeECG+" sizeECMod = "+sizeECMod+
                                    " sizeECA = "+sizeECA+" sizeECB = "+sizeECB+"K = "+ecK);
            
        int pos = 7; // skip 6 first bytes that contains the sizes
        ecG = new byte[sizeECG];
        for (int i=0; i<sizeECG;i++) ecG[i] = resp[i+pos];
        if (DEBUG) {
            System.err.print("getECValues: ecG  =");
            for (int i=0; i<sizeECG;i++) System.err.format("%02X",ecG[i]);
            System.err.println();
        }
            
        pos += sizeECG; // skip also G
        ecMod = new byte[sizeECMod];
        for (int i=0; i<sizeECMod;i++) ecMod[i] = resp[i+pos];
        if (DEBUG) {
            System.err.print("getECValues: ecMod =");
            for (int i=0; i<sizeECMod;i++) System.err.format("%02X",ecMod[i]);
            System.err.println();
        }
            
        pos += sizeECMod; // skip also ec Mod
        ecA = new byte[sizeECA];
        for (int i=0; i<sizeECA;i++) ecA[i] = resp[i+pos];
        if (DEBUG) {
            System.err.print("getECValues: ecA   =");
            for (int i=0; i<sizeECA;i++) System.err.format("%02X",ecA[i]);
            System.err.println();
        }
            
        pos += sizeECA; // skip also ec Mod
        ecB = new byte[sizeECB];
        for (int i=0; i<sizeECB;i++) ecB[i] = resp[i+pos];
        if (DEBUG) {
            System.err.print("getECValues: ecB   =");
            for (int i=0; i<sizeECB;i++) System.err.format("%02X",ecB[i]);
            System.err.println();
        }
            
        pos += sizeECB; // skip also ec Mod
        ecP = new byte[sizeECP];
        for (int i=0; i<sizeECP;i++) ecP[i] = resp[i+pos];
        if (DEBUG) {
            System.err.print("getECValues: ecP   =");
            for (int i=0; i<sizeECP;i++) System.err.format("%02X",ecP[i]);
            System.err.println();
        }
            
        } catch (Exception e) {
            System.err.println("getECValues: Error while transmiting data to javacard."+e);
        }
        
    }


    // ------------------------------------------------------------------------------------------
    // Audit the data stored in the file.
    // THE PART TO TEST THE EQUATIONS: G.t == Gs + Gdc.c (this has been tested)
    // Qn.t == Qns + Qndc.c IS NOT READY - it won't work with javacard 2.2.2 since the DH keyagreement
    // returns a hashed value and not a plain value.
    // ------------------------------------------------------------------------------------------
    public void auditData(int nread, byte[] dataBytes, CardChannel cc)
    {
        ResponseAPDU r = new ResponseAPDU(new byte[3]);
        byte[] apdu;
        byte[] resp;
        byte[] instance = {dataBytes[0], dataBytes[1]};
        byte[] hashEncKey = new byte[20];
        
        // 3rd byte in the encrypted file contains
        // the size of the public key
        
        int sizePublicKey = (int) dataBytes[2];
        
        byte[] pubkey = new byte[sizePublicKey];
        
        // gets the public key from file - G.dc
        for (int i=0; i<sizePublicKey; i++) pubkey[i] = dataBytes[i+3];
        if (DEBUG) {
            System.err.print("auditData: gdc  =");
            for (int i=0; i<sizePublicKey;i++) System.err.format("%02X",pubkey[i]);
            System.err.println();
        }
        
        // now get the size of ephemeral public key
        int sizeEphemeralPublicKey = (int) dataBytes[3+sizePublicKey];
        
        byte[] epubkey = new byte[sizeEphemeralPublicKey];
        
        // gets the ephemeral public key from file - Qn, ie Gdn
        for (int i=0; i<sizeEphemeralPublicKey; i++) epubkey[i] = dataBytes[i+4+sizePublicKey];
        if (DEBUG) {
            System.err.println("auditData: Size ephemeral public key = "+sizeEphemeralPublicKey);
            System.err.print("auditData: epubkey  =");
            for (int i=0; i<sizeEphemeralPublicKey;i++) System.err.format("%02X",epubkey[i]);
            System.err.println();
        }
        
        // gets the hash for the session key
        for (int i=0; i<20; i++) hashEncKey[i] = dataBytes[i+4+sizePublicKey+sizeEphemeralPublicKey+16];
                
        if (DEBUG) {
            System.err.print("auditData: HASH ENC KEY  =");
            for (int i=0; i<20;i++) System.err.format("%02X",hashEncKey[i]);
            System.err.println();
        }
        
        
        try 
		{    
            // begin auditing
			 byte[] lc = {(byte)(2+sizeEphemeralPublicKey+20)}; // set the number os bytes to send
                                                                // 2 bytes for the instance
                                                                // plus the size of the ephemeral public key
                                                                // plus the size of the hash of the session key
            apdu = this.hexStringToByteArray(AUDITAPDU+this.byteArrayToHexString(lc)+this.byteArrayToHexString(instance)+this.byteArrayToHexString(epubkey)+
                                            this.byteArrayToHexString(hashEncKey));
            if (DEBUG) System.err.println("auditData: TRANSMIT: "+this.byteArrayToHexString(apdu));
            long start = System.currentTimeMillis();
			r = cc.transmit(new CommandAPDU(apdu));
            long end = System.currentTimeMillis();
            //System.out.println("Audit time (ms): "+(end-start));
            resp = r.getBytes();
            if (DEBUG) System.err.println("auditData: RESPONSE: "+this.byteArrayToHexString(resp));
            
            int codeResp = ((resp[resp.length-2]&0x00FF)<<8) + (resp[resp.length-1] & 0x00FF);
            if (codeResp == 0xAF1) {
                System.out.println("Instance does not exist - it has already been deleted!");
                System.exit(1);
            }

            // expecting as response: sizeGS, sizeQNS, sizeT and sizeQNDC - 1 byte each
            
            int
            sizeGS = (resp[0]&0x00FF),
            sizeQNS= (resp[1]&0x00FF),
            sizeT  = (resp[2]&0x00FF),
            sizeQNDC = (resp[3]&0x00FF);

            byte[] gs, qns, t, qndc; 
            
            if (DEBUG) System.err.println("auditData:  sizeGS = "+sizeGS+" sizeQNS = "+sizeQNS+" sizeT = "+sizeT+" sizeQNDC = "+sizeQNDC);
            
            int pos = 4; // skip 7 first bytes that contains the sizes
            gs = new byte[sizeGS];
            for (int i=0; i<gs.length;i++) gs[i] = resp[i+pos];
            if (DEBUG) {
                System.err.print("auditData: GS  =");
                for (int i=0; i<sizeGS;i++) System.err.format("%02X",gs[i]);
                System.err.println();
            }
            
            pos += sizeGS; // skip also GS
            qns = new byte[sizeQNS];
            for (int i=0; i<sizeQNS;i++) qns[i] = resp[i+pos];
            if (DEBUG) {
                System.err.print("auditData: QNS =");
                for (int i=0; i<sizeQNS;i++) System.err.format("%02X",qns[i]);
                System.err.println();
            }
            
            pos += sizeQNS; // skip also QNS
            t = new byte[sizeT];
            for (int i=0; i<sizeT;i++) t[i] = resp[i+pos];
            if (DEBUG) {
                System.err.print("auditData: T   =");
                for (int i=0; i<sizeT;i++) System.err.format("%02X",t[i]);
                System.err.println();
            }
            
            pos += sizeT; // skip also T
            qndc = new byte[sizeQNDC];
            for (int i=0; i<sizeQNDC;i++) qndc[i] = resp[i+pos];
            if (DEBUG) {
                System.err.print("auditData: QNDC   =");
                for (int i=0; i<sizeQNDC;i++) System.err.format("%02X",qndc[i]);
                System.err.println();
            }
			           
             // generate c

             MessageDigest md = MessageDigest.getInstance("SHA");

             md.reset();
             md.update(ecG,    (short)0, (short) sizeECG);

             md.update(gs,     (short)0, (short) sizeGS);

             md.update(qns,    (short)0, (short) sizeQNS);

             
             byte[] c  = md.digest(epubkey);
            
             if (DEBUG) System.out.println("auditData: C in the host = "+byteArrayToHexString(c));
            
             byte[] c1 = new byte[c.length+5]; // just in case the left most bit is 1, include 0x00 bytes at front
             
             for(int i=0; i<c.length; i++) c1[i+5] = c[i];
             for (int i=0; i<5; i++) c1[i] = 0x00;
            
            // Check that both equations hold
			
			//equation one G.t == Gs + Gdc . c
            
            BigInteger ecPBI = new BigInteger(ecP), ecABI = new BigInteger(ecA),
                       ecBBI = new BigInteger(ecB), cBI = new BigInteger(c1),
                       tBI = new BigInteger(t);
           
            ECCurve myCurve = new ECCurve.Fp(ecPBI,ecABI,ecBBI);
            
			ECPoint eGs = myCurve.decodePoint(gs);
			ECPoint eG = myCurve.decodePoint(ecG);
			ECPoint eGdc = myCurve.decodePoint(pubkey); //gdc

			ECPoint qn = myCurve.decodePoint(epubkey);

			ECPoint rhs = eGs.add(eGdc.multiply(cBI));  // Gs + Gdc . c
            
			ECPoint lhs = eG.multiply(tBI);             // G . t
            
            
            if (lhs.equals(rhs))
            {
				//equation two
			
				//we only get the x-coords from the javacard for qns and qndc as we have to use the ecdh routine for speed
				//hence we have two possible points for each 
				//so there are four comparisons we need to try, and the audit succeeds if one of them is true
				byte[] realQNS = new byte[sizeQNS+1];
				byte[] realQNDC = new byte[sizeQNDC+1];
				
				for (int i=0; i<sizeQNDC;i++) 
				{
					realQNDC[i+1] = qndc[i];				
				}
				realQNDC[0] = (byte) 2;
				ECPoint QNDC1 = myCurve.decodePoint(realQNDC);
				
				realQNDC[0] = (byte) 3;	
				ECPoint QNDC2 = myCurve.decodePoint(realQNDC);			
				for (int i=0; i<sizeQNS;i++) 
				{
					realQNS[i+1] = qns[i];			
				}
				realQNS[0] = (byte) 2;
				ECPoint QNS1 = myCurve.decodePoint(realQNS);
				realQNS[0] = (byte) 3;	
				ECPoint QNS2 = myCurve.decodePoint(realQNS);
				
		
				//equation 2
				
				ECPoint rhs2 =   QNS1.add(QNDC1.multiply(cBI)); // qns + qndc.multiply(c)
				ECPoint lhs2 = qn.multiply(tBI);
				
				if (lhs2.equals(rhs2))
				{
					//System.out.println("Audit succeeded");
				}
				else
				{
					rhs2 =   QNS1.add(QNDC2.multiply(cBI)); // qns + qndc.multiply(c)
					if (lhs2.equals(rhs2))
					{
						//System.out.println("Audit succeeded");
					}
					else
					{
						rhs2 =   QNS2.add(QNDC1.multiply(cBI)); // qns + qndc.multiply(c)
						if (lhs2.equals(rhs2))
						{
							//System.out.println("Audit succeeded");
						}
						else
						{
							rhs2 =   QNS2.add(QNDC2.multiply(cBI)); // qns + qndc.multiply(c)
						}
						if (lhs2.equals(rhs2))
						{
							//System.out.println("Audit succeeded");
						}
						else
						{
							System.out.println("Audit failed");
						}
					}
				}
            }
            else
            {
                System.out.println("Audit failed.");
            }
            
        } catch (Exception e) {
            System.err.println("auditData: "+e);
        }
    }
    // ------------------------------------------------------------------------------------------
    // ------------------------------------------------------------------------------------------
    public void delete(int nread, byte[] dataBytes, CardChannel cc)
    {
        ResponseAPDU r = new ResponseAPDU(new byte[3]);
        byte[] apdu;
        byte[] resp;
        byte[] instance = {dataBytes[0], dataBytes[1]};
                
        try 
		{
            apdu = this.hexStringToByteArray(DELETEAPDU+this.byteArrayToHexString(instance));
            if (DEBUG) System.err.println("delete: TRANSMIT: "+this.byteArrayToHexString(apdu));
            r = cc.transmit(new CommandAPDU(apdu));
            resp = r.getBytes();
            if (DEBUG) System.err.println("delete: RESPONSE: "+this.byteArrayToHexString(resp));
        } catch (Exception e) 
		{
            System.err.println("delete: Error while transmiting data to javacard."+e);
        }
    }
	
}