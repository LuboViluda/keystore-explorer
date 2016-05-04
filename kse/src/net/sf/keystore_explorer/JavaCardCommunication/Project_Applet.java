/*
 * PACKAGEID: 4C 61 62 61 6B
 * APPLETID: 4C 61 62 61 6B 41 70 70 6C 65 74
 */
package net.sf.keystore_explorer.JavaCardCommunication;

/*
 * Imported packages
 */
// specific import for Javacard API access
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;


import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;



public class Project_Applet extends javacard.framework.Applet
{
    // MAIN INSTRUCTION CLASS
    final static byte CLA_AUTHAPPLET                    = (byte) 0xB0;
    // INSTRUCTIONS
    final static byte INS_VERIFYPIN                     = (byte) 0x55;
    final static byte INS_SETPIN                        = (byte) 0x56;
    final static byte INS_GEN_RET_KEY                   = (byte) 0x57;
    final static byte INS_INIT_SEC_CHANNEL              = (byte) 0x58;
    final static byte INS_SET_PASSWD                    = (byte) 0x60;


    public final static byte INS_TEST = (byte) 0x20;
    final static short SW_BAD_PIN                    = (short) 0x6900;
    final static short SW_PIN_NOT_VERIFIED           = (short) 0x6982;
    final static short SW_CARD_BLOCKED               = (short) 0x6983;

    private   OwnerPIN       m_pin = null;
    private   RandomData     m_secureRandom = null;
    private   byte           m_pinArray[] = null; // EEPROM storage for PIN
    private   byte           m_keyArray[] = null; // EEPROM storage for key
    private   byte           m_password[] = null; // EEPROM storage for key


    //Variables
    private final AESKey encKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.LENGTH_AES_128, false);
    public final byte[] buffer = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_RESET);
    private final Cipher aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
    MessageDigest m_sha1 = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
    byte[] randomY = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
    byte[] sharedKey = JCSystem.makeTransientByteArray((short) 20, JCSystem.CLEAR_ON_RESET);
    private   byte[] toHash = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    private byte[] key = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);

    private   byte           m_ramArray[] = null;  // TEMPORARRY ARRAY IN RAM
    private   AESKey         m_aesKey = null;
    private   Cipher         m_encryptCipher_CBC = null;
    private   Cipher         m_decryptCipher_CBC = null;


    public final byte[] reply = {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c,
            (byte) 0x6f, (byte) 0x20, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61,
            (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e};

    /**
     *
     * Only this class's install method should create the applet object.
     * @param buffer
     * @param offset
     * @param length
     */
    protected Project_Applet(byte[] buffer, short offset, byte length)
    {
        short dataOffset = offset;
        m_pin = new OwnerPIN((byte) 20, (byte) 4);
        m_password = new byte[32];
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        m_password = new byte[32];

        // CREATE AES KEY OBJECT
        m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        // CREATE OBJECTS FOR CBC CIPHERING
        m_encryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
        m_decryptCipher_CBC = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);


        //  TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
        m_ramArray = new byte[260];
        m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);
        // SET KEY VALUE
        m_aesKey.setKey(m_ramArray, (short) 0);

        // INIT CIPHERS WITH NEW KEY
        //CBC
        m_encryptCipher_CBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
        m_decryptCipher_CBC.init(m_aesKey, Cipher.MODE_DECRYPT);
        register();

    }

    /**
     * Method installing the applet.
     * @param bArray the array constaining installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException
    {
        // applet  instance creation 
        new Project_Applet (bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     * @return boolean status of selection.
     */
    public boolean select()
    {
      return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect()
    {
        return;
    }

    /**
     * Method processing an incoming APDU.
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
     public void process(APDU apdu) throws ISOException {

        byte[] apduBuffer = apdu.getBuffer();

        if (selectingApplet()) {
            return;
        }

        // APDU instruction parser
        if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_AUTHAPPLET) {
            switch ( apduBuffer[ISO7816.OFFSET_INS] )
            {
                case INS_VERIFYPIN: VerifyPIN(apdu); break;
                case INS_SETPIN:    SetPIN(apdu); break;
                case INS_GEN_RET_KEY: Gen_Retr_Key(apdu); break;
                case INS_INIT_SEC_CHANNEL:
                    establishSecureChannel(apdu); break;
                case INS_SET_PASSWD: setPassword(apdu);
                case INS_TEST:
                    aesCipher.init(encKey, Cipher.MODE_ENCRYPT);
                    aesCipher.doFinal(reply, (short) 0, (short) reply.length, buffer, (short) 0);
                    apdu.setOutgoing();
                    apdu.setOutgoingLength((short) reply.length);
                    apdu.sendBytesLong(buffer, (short) 0, (short) reply.length);
                    return;

                default :
                    // The INS code is not supported by the dispatcher
                    ISOException.throwIt( ISO7816.SW_INS_NOT_SUPPORTED ) ;
                break ;
            }
        }
        else ISOException.throwIt( ISO7816.SW_CLA_NOT_SUPPORTED);
    }

    // SET PIN  should be performed in trusted environment
    void SetPIN(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();

        //store PIN in EEPROM m_pinArray
        m_pinArray = new byte[dataLen];
        Util.arrayFillNonAtomic(m_pinArray, (short) 0, dataLen, (byte) 0);
        Util.arrayCopyNonAtomic(apdubuf, ISO7816.OFFSET_CDATA, m_pinArray, (short) 0,dataLen);

        m_pin.update(m_pinArray, (short) 0, (byte) dataLen);    // SET NEW PIN

    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
        byte[]    apdubuf = apdu.getBuffer();
        short     dataLen = apdu.setIncomingAndReceive();
        if (m_pin.getTriesRemaining() > (byte)0){    /// Check if card is blocked
            ///Enc decrypt//////////////////////////////
            m_aesKey.setKey(key, (short) 0);

            m_decryptCipher_CBC.init(m_aesKey, Cipher.MODE_DECRYPT);

            m_decryptCipher_CBC.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
            Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

            if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) 4) == false) // VERIFY PIN
                ISOException.throwIt(SW_BAD_PIN);
        }
        else
            ISOException.throwIt(SW_CARD_BLOCKED);
    }

    //To generate and retrieve key
    void Gen_Retr_Key(APDU apdu) {
        /// Validate if a user has been authenticated
        if (m_pin.getTriesRemaining() > (byte)0){    /// Check if card is blocked
            if (m_pin.isValidated() == true){
                byte[]    apdubuf = apdu.getBuffer();
                short     dataLen = apdu.setIncomingAndReceive();
                // NEW KEY****If it is first time generate new keys
                if(apdubuf[ISO7816.OFFSET_P2] == (byte) 0){
                    m_keyArray = new byte[apdubuf[ISO7816.OFFSET_P1]];                  //store key in EEPROM m_keyArray
                    Util.arrayFillNonAtomic(m_keyArray, (short) 0, ISO7816.OFFSET_P1, (byte) 0);
                    m_secureRandom.generateData(m_keyArray, (short) 0, apdubuf[ISO7816.OFFSET_P1]);  // GENERATE Random DATA
                }
                /// RETRIEVAL *****If key retrieval send previous stored key
                m_aesKey.setKey(key, (short) 0);
                m_encryptCipher_CBC.init(m_aesKey, Cipher.MODE_ENCRYPT);
                m_encryptCipher_CBC.doFinal(m_keyArray, (short) 0, apdubuf[ISO7816.OFFSET_P1], apdubuf, ISO7816.OFFSET_CDATA);

                // Util.arrayCopyNonAtomic(m_keyArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
                // SEND OUTGOING BUFFER
                apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, apdubuf[ISO7816.OFFSET_P1]);
            }
            else
                ISOException.throwIt(SW_PIN_NOT_VERIFIED);

        }
        else
            ISOException.throwIt(SW_CARD_BLOCKED);
    }

    /**
     *  Establishing secure channel with card with DH, random number (a) from PC is handled
     *  and
     *
     */
    void establishSecureChannel(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();

        m_sha1.reset();

        m_secureRandom.generateData(randomY, (short) 0, (short) 32);
        Util.arrayCopy(randomY, (short) 0, toHash, (short) 0, (short) 32);
        Util.arrayCopy(m_password, (short) 0, toHash, (short) 32, (short) 32);


        m_sha1.doFinal(toHash, (short) 0, (short) 64, sharedKey, (short) 0);

        Util.arrayCopy(randomY, (short) 0, apduBuffer, ISO7816.OFFSET_CDATA, (short) 32);
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, (short) 32);

        //only 16 bytes from SHA will be used in key
        Util.arrayCopy(sharedKey, (short) 0, key, (short) 0, (short) 16);
    }

    // setPassword is done in trusted enviroment
    void setPassword(APDU apdu) {
        byte[]  apdubuf = apdu.getBuffer();
        Util.arrayCopy(apdubuf, ISO7816.OFFSET_CDATA, m_password, (short) 0, (short) 32);
    }


}


