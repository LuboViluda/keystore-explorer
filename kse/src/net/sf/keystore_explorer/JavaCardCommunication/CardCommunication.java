package net.sf.keystore_explorer.JavaCardCommunication;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import net.sf.keystore_explorer.crypto.Password;

import javax.crypto.*;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import net.sf.keystore_explorer.JavaCardCommunication.CardMngr;
import sun.misc.BASE64Encoder;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;


/**
 * Created by lubomir.viluda on 30.4.2016.
 */
public class CardCommunication {

    static private CardMngr cardManager = null;


    private static byte APPLET_AID[] = {(byte) 0x4C, (byte) 0x61, (byte) 0x62, (byte) 0x61, (byte) 0x6B,
            (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6C, (byte) 0x65, (byte) 0x74};

    public static final byte[] reply = {(byte) 0x48, (byte) 0x65, (byte) 0x6c, (byte) 0x6c,
            (byte) 0x6f, (byte) 0x20, (byte) 0x4a, (byte) 0x61, (byte) 0x76, (byte) 0x61,
            (byte) 0x20, (byte) 0x43, (byte) 0x61, (byte) 0x72, (byte) 0x64, (byte) 0x2e};

    private static byte[] keyValue = new byte[16];

    final static byte CLA_AUTHAPPLET                  = (byte) 0xB0;
    final static byte INS_VERIFYPIN                     = (byte) 0x55;
    final static byte INS_SETPIN                        = (byte) 0x56;
    final static byte INS_GEN_RET_KEY                   = (byte) 0x57;
    final static byte KEY_LEN                           = (byte) 0x10;
    final static byte NEW_KEY                           = (byte) 0x00;
    final static byte KEY_RETR                          = (byte) 0x01;

    // encryption
    private static byte[] encrypt(byte[] plainText, byte[] encKey) throws Exception
    {
        Key key = new SecretKeySpec(encKey, "AES");
        Cipher chiper = Cipher.getInstance("AES/ECB/NoPadding");
        chiper.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = chiper.doFinal(plainText);
        return encVal;
    }

    // decryption
    private static byte[] decrypt(byte[] encryptedText, byte[] decKey) throws Exception
    {
        Key key = new SecretKeySpec(decKey, "AES");
        Cipher chiper = Cipher.getInstance("AES/ECB/NoPadding");
        chiper.init(Cipher.DECRYPT_MODE, key);
        byte[] decValue = chiper.doFinal(encryptedText);
        return decValue;
    }

    /**
     *
     * Prepare card manager, singleton pattern used
     */
    static private void prepareCardManager() {
        if (cardManager == null) {
            cardManager = new CardMngr();
            byte[] installData = new byte[10];
            cardManager.prepareLocalSimulatorApplet(APPLET_AID, installData, Project_Applet.class);
        }
    }


    /**
     *
     * Initialize card with PIN
     * @param pin pin supplied by user
     *
     * @return
     */
    static public void initializeCard(Password pin) {
        prepareCardManager();
        int additionalDataLen = pin.toCharArray().length;

        if(additionalDataLen != 4) {
            // TO DO show error message
            // error too short or too long PIN
            // nothing to do
            return;
        }

        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        System.arraycopy(pin.toByteArray(), 0, apdu, ISO7816.OFFSET_CDATA, 4);

        apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu[CardMngr.OFFSET_INS] = (byte) 0x56;
        apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        try {
            byte[] response = cardManager.sendAPDUSimulator(apdu);
            if(checkResponse(response)){
                // success
            } else {
                //fail
            }
        } catch (Exception ex) {
            System.err.println("sendAPDUSimulator Error");
        }
    }

    /**
     * Try login into card
     *
     * @param pin supplied by user
     *
     * @return true if succesfull, otherwise false
     */
    static public void logIntoCard(Password pin) {
        prepareCardManager();

        //Prepare Verify PIN apdu, send apdu to card and analyze response
        byte [] PIN = new byte[16];
        //Encrypt PIN
        Util.arrayCopy(pin.toByteArray(), (short) 0, PIN, (short) 0, (short) 4);
        byte[] encPIN = new byte[0];
        try {
            encPIN = encrypt(PIN, keyValue);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte apdu_header[]={(byte) 0xB0, (byte) 0x55,(byte) 0x00,(byte) 0x00,(byte) 0x10};

        byte apdu_VerifyPIN[] =  new byte[apdu_header.length + encPIN.length];
        System.arraycopy(apdu_header, 0, apdu_VerifyPIN, 0, apdu_header.length);
        System.arraycopy(encPIN, 0, apdu_VerifyPIN, apdu_header.length, encPIN.length);

        byte[] resp2 = new byte[0];
        try {
            resp2 = cardManager.sendAPDUSimulator(apdu_VerifyPIN);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ////  Process and print APDU Responce
        if((resp2[(resp2.length)-2])== (byte) 0x90)
            System.out.println("***Authentication success***");
        else if((resp2[(resp2.length)-2])== (byte) 0x69 && (resp2[(resp2.length)-1])== (byte) 0x00)
            System.out.println("***Authentication Failed***\n!!! Wrong PIN, Authentication failed");
        else if((resp2[(resp2.length)-2])== (byte) 0x69 && (resp2[(resp2.length)-1])== (byte) 0x83)
            System.out.println("!!! CARD Blocked");
        else
            System.out.println("!!!PIN authentication failed with error code "+ cardManager.bytesToHex(resp2));
    }


    /**
     * set preshared password to the card, it should be done in TRUSTED enviroment
     *
     *
     * @param password preshared password
     * @param pin pin, should be same as pin setted in card, otherwise mechanism doesn't work
     */

    static public void setPasswordToCard(String password, byte[] pin) {
        prepareCardManager();

        // decrypt with PIN
        byte[] pin4 = new byte[16];
        System.arraycopy(pin, 0, pin4, 0, 4);
        System.arraycopy(pin, 0, pin4, 4, 4);
        System.arraycopy(pin, 0, pin4, 8, 4);
        System.arraycopy(pin, 0, pin4, 12, 4);

        byte[] bytes = null;
        byte[] temp = null;
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(pin4, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

            bytes = password.getBytes();
            temp = cipher.doFinal(bytes);

            String s =  new String(Base64.getEncoder().encode(temp));
            FileWriter fileWriter = new FileWriter("credentials.txt");
            fileWriter.write(s);
            fileWriter.close();

            FileReader fileReader = new FileReader("credentials.txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            String line = bufferedReader.readLine();
            bytes = Base64.getDecoder().decode(line.getBytes());
            fileReader.close();

            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            temp = cipher.doFinal(bytes);

        } catch (Exception ex) {
            ex = ex;
        }

        short additionalDataLen = 32;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];

        System.arraycopy(temp, 0, apdu, ISO7816.OFFSET_CDATA, 32);
        apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu[CardMngr.OFFSET_INS] = (byte) 0x60;
        apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        try {
            byte[] response = cardManager.sendAPDUSimulator(apdu);
            if (response[response.length - 2] == (byte) 0x90 &&
                    response[response.length - 1] == (byte) 0x00) {
            }
        } catch (Exception ex) {
            System.err.println("sendAPDUSimulator Error");
        }
    }

    /**
     * Get password from card, successful only if user is correctly logged
     *
     * @param
     *
     * @return Password stored in card
     */
    static public char[] getPassword() {
        prepareCardManager();

        // generation key
        byte[] apdu_genNewKey={CLA_AUTHAPPLET,INS_GEN_RET_KEY,KEY_LEN,NEW_KEY,(byte) 0x00};

        byte[] resp3 = new byte[0];
        try {
            resp3 = cardManager.sendAPDUSimulator(apdu_genNewKey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ////  Process and print APDU Responce
        if((resp3[(resp3.length)-2])== (byte) 0x90){
            System.out.println("***key generation success***");
            //Decrypt the key
            byte encryptedKey[] =  new byte[(resp3.length)-2];
            System.arraycopy(resp3, 0, encryptedKey, 0, (resp3.length)-2);
            byte[] decryptedKey = new byte[0];
            try {
                decryptedKey = decrypt(encryptedKey, keyValue);
            } catch (Exception e) {
                e.printStackTrace();
            }
            for(short i=0; i< (decryptedKey.length); i++)
                System.out.print(cardManager.byteToHex(decryptedKey[i]) + " ");
            System.out.print("\n");
        }

        // obtaining key
        byte apdu_retkey[] ={CLA_AUTHAPPLET,INS_GEN_RET_KEY,KEY_LEN,KEY_RETR,(byte) 0x00};

        byte[] resp4 = new byte[0];
        try {
            resp4 = cardManager.sendAPDUSimulator(apdu_retkey);
        } catch (Exception e) {
            e.printStackTrace();
        }

        ////  Process and print APDU Responce
        if((resp4[(resp4.length)-2])== (byte) 0x90){
            System.out.println("***key retreval success***");

            //Decrypt the key
            byte encryptedKey[] =  new byte[(resp4.length)-2];
            System.arraycopy(resp4, 0, encryptedKey, 0, (resp4.length)-2);
            char[] charKey = new char[16];
            byte[] decryptedKey = null;
            try {
                decryptedKey = decrypt(encryptedKey, keyValue);
                return bytesToStringUTFCustom(decryptedKey).toCharArray();
            } catch (Exception e) {
                e.printStackTrace();
            }
            for(short i=0; i< (decryptedKey.length); i++)
                System.out.print(cardManager.byteToHex(decryptedKey[i]) + " ");
            System.out.print("\n");
        }
        else
            System.out.println("***key reteval Failed***\n!!!key reteval failed with error code "+ cardManager.bytesToHex(resp4));

    return null;
    }

    public static String bytesToStringUTFCustom(byte[] bytes) {
        char[] buffer = new char[bytes.length >> 1];
        for(int i = 0; i < buffer.length; i++) {
            int bpos = i << 1;
            char c = (char)(((bytes[bpos]&0x00FF)<<8) + (bytes[bpos+1]&0x00FF));
            buffer[i] = c;
        }
        return new String(buffer);
    }

    /**
     * Establish secure channel between App and card
     *
     * @return established password
     */
    static public byte[] establishSecureChannel(byte[] pin) {
        prepareCardManager();

        //read preshared key from file
        String line = null;
        byte[] password = null;
        byte[] randomX = new byte[32];

        // decrypt with PIN
        byte[] pin4 = new byte[16];
        System.arraycopy(pin, 0, pin4, 0, 4);
        System.arraycopy(pin, 0, pin4, 4, 4);
        System.arraycopy(pin, 0, pin4, 8, 4);
        System.arraycopy(pin, 0, pin4, 12, 4);

        try {
            FileReader fileReader = new FileReader("credentials.txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            line = bufferedReader.readLine();
            fileReader.close();
        } catch (IOException ex) {

        }

        byte[] bytes = null;
        byte[] temp = null;
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(pin4, "AES");

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

            FileReader fileReader = new FileReader("credentials.txt");
            BufferedReader bufferedReader = new BufferedReader(fileReader);
            line = bufferedReader.readLine();
            bytes = Base64.getDecoder().decode(line.getBytes());
            fileReader.close();

            cipher.init(Cipher.DECRYPT_MODE, skeySpec);
            password = cipher.doFinal(bytes);
        } catch (NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException ex ) {
            System.err.print("error");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        int additionalDataLen = 34;
        byte apdu[] = new byte[CardMngr.HEADER_LENGTH + additionalDataLen];
        System.arraycopy(randomX, 0, apdu, CardMngr.OFFSET_DATA, randomX.length);
        apdu[CardMngr.OFFSET_CLA] = (byte) 0xB0;
        apdu[CardMngr.OFFSET_INS] = (byte) 0x58;
        apdu[CardMngr.OFFSET_P1] = (byte) 0x00;
        apdu[CardMngr.OFFSET_P2] = (byte) 0x00;
        apdu[CardMngr.OFFSET_LC] = (byte) additionalDataLen;

        // secure channel session password = SHA1( password || Y)
        byte[] response = null;
        try {
            response = cardManager.sendAPDUSimulator(apdu);
        } catch (Exception ex) {
            System.err.println("sendAPDUSimulator Error");
        }

        byte[] joined = new byte[64];

        Util.arrayCopy(response, (short) 0, joined, (short) 0, (short) 32);
        Util.arrayCopy(password, (short) 0, joined, (short) 32, (short) 32);

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA");
            sha.update(joined);
            byte[] sharedKey = sha.digest();
            Util.arrayCopy(sharedKey, (short) 0, keyValue, (short) 0, (short) 16);
            return sharedKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return  null;
    }

    /**
     * check response from card
     *
     * @param response, response from card
     * @return true if response ends with OK code 0x0900
     */
    static private boolean checkResponse(byte[] response) {
        return response[response.length - 2] == (byte) 0x90 && response[response.length - 1] == (byte) 0x00;
    }
}
