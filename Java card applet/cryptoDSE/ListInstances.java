/*
 This is a simple class just to store a list of instances of keys.
 
 This class can store at most MAXINSTANCES of pair of keys. The 
 MAXINSTANCES constant depends on the size of the javacard that is being used.
 
 This class uses the variable "available" to control the id of instances that
 are in use in the javacard, so instances can be reused. Each bit in the "available" 
 array represents one instance. If the bit is on (1) then the instance is being used, 
 otherwise the instance is available to be used. 
 
 This class can throw two exceptions: MAX_INSTANCES_REACHED or INVALID_INSTANCE_ID.
 
 Author: *** Name anonymized to allow blind review ***
 Date:   *** Removed ***
*/

package cryptoDSE;

import javacard.framework.ISOException;

public class ListInstances
{
    final static short MAXINSTANCES = 512;
    final static short MAX_INSTANCES_REACHED   = 0x0AF0;
    final static short INVALID_INSTANCE_ID     = 0x0AF1;
    
    InstanceKeys[] clients;
    
    // Used to control the used instances - it contains MAXINSTANCES bits
    // Each bit represents one instance
    byte[] available = new byte[(short)(MAXINSTANCES / 8)];
    
    // Creates a list of instances
    protected ListInstances()
    {
        clients = new InstanceKeys[MAXINSTANCES];
    }
    
    // Returns the next available instance. It uses the available array to
    // set an instance as consumed.
    public short consumeNextInstance() {
        
        short i = (short)0; // index in available
        short b = (short)0; // index in the byte
        boolean found = false;
        
        while (!found && i<(short)(MAXINSTANCES/8)) {
            short mask = (short)0x0080;
            b = (short)0;
            while (!found && b < 8) {
                if ((available[i] & mask) == 0) {
                    found = true;
                    available[i] = (byte)(available[i] ^ mask); // set as consumed
                }
                else b++;
                mask = (byte) (mask >> 1);
            }
            if (!found) i++;
        }
        
        if (!found) ISOException.throwIt(MAX_INSTANCES_REACHED);
        
        return (short)(i*8+b);
    }
    
    // Creates a pair of keys - uses the InstanceKeys class.
    public short createInstance() {
        
        short nextInstance = consumeNextInstance();
        
        clients[nextInstance] = new InstanceKeys(nextInstance);
        
        return nextInstance;
    }

    // Removes an instance and set the corresponding bit in the available array
    // as 0 (representing that this id is available to be used again). A new
    // pair of keys is created and used.
    public void removeInstance(short id) {
        
        if (id <0 || id >= MAXINSTANCES) ISOException.throwIt(INVALID_INSTANCE_ID);

        if (clients[id] == null) ISOException.throwIt(INVALID_INSTANCE_ID);
        
        // get bit position in the available array
        short i = (short)(id / 8);
        short b = (short)(id % 8);
        
        // make it available again
        short mask = (short) (0x0080 >> b);
        available[i] = (byte) (available[i] ^ mask);
        
        // clean client[id]
        // clients[id].cleanPrivateKey();
        clients[id] = null;
        
    }

    // Returns the instance keys if it exists. Throws an excption otherwise.
    public InstanceKeys getInstance(short id) {
        
        if (id <0 || id >= MAXINSTANCES) ISOException.throwIt(INVALID_INSTANCE_ID);
        
        if (clients[id] == null) ISOException.throwIt(INVALID_INSTANCE_ID);
        
        return clients[id];
    }
    
    // Returns true if the instance exists. False otherwise.
    public boolean isValid(short id) {
        if (id <0 || id >= MAXINSTANCES) return false;
        
        if (clients[id] == null) return false;
        
        return true;
    }

}

