/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.util;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.UUID;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author dczech
 */
public class Utils {

    /**
     * Given a string of hexadecimal characters, convert to a byte array. No checks are performed to ensure that the string is all valid hexidecimal characters
     * (0-9, a-f, A-F) or that there is an even number of characters.
     *
     * @param s The hexadecimal string
     * @return A byte array
     */
    public static byte[] hexStringToByteArray(String s) {
        int sizeInt = s.length() / 2;
        byte[] returnArray = new byte[sizeInt];
        String byteVal;
        for (int i = 0; i < sizeInt; i++) {
            int index = 2 * i;
            byteVal = s.substring(index, index + 2);
            returnArray[i] = (byte) (Integer.parseInt(byteVal, 16));
        }
        return returnArray;
    }

    /**
     * Convert a byte array to a hexidecimal character string. The string will have no delimeter between hexidecimal duples, and has no line breaks.
     *
     * @param b Byte array to convert
     * @return A string of hexidecimal characters
     */
    public static String byteArrayToHexString(byte[] b) {
        StringBuilder sb = new StringBuilder();
        String returnStr = "";
        for (int i = 0; i < b.length; i++) {
            String singleByte = Integer.toHexString(b[i] & 0xff);
            if (singleByte.length() != 2) {
                singleByte = "0" + singleByte;
            }
            returnStr = sb.append(singleByte).toString();
        }
        return returnStr;
    }

    /**
     * Creates a byte buffer of random bytes
     *
     * @param numBytes how many random bytes to return
     * @return a byte buffer of size <code>howMany</code> containing random bytes.
     */
    public static byte[] randomBytes(int numBytes) {
        SecureRandom r = new SecureRandom();
        byte buf[] = new byte[numBytes];
        r.nextBytes(buf);
        return buf;
    }

    /**
     * Exception that indicates a failure with Decryption
     */
    public static class SymCaDecryptionException extends Exception {

        /**
         *
         * @param ex
         */
        public SymCaDecryptionException(Exception ex) {
            super(ex);
        }

    }

    /**
     * Fixes a TPM 2.0 makeCredential Output 
     * @param in
     * @return
     * @throws IOException 
     */
    public static byte[] fixMakeCredentialBlobForWindows(byte[] in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        DataOutputStream out = new DataOutputStream(bos);
        final int SECRET_SIZE = 134;
        ByteBuffer buf = ByteBuffer.wrap(in);
        int secretLength = buf.order(ByteOrder.LITTLE_ENDIAN).getShort();
        out.writeShort((short) secretLength);
        byte[] b = new byte[secretLength];
        buf.get(b);
        out.write(b);
        buf.position(SECRET_SIZE);
        int asymLength = buf.order(ByteOrder.LITTLE_ENDIAN).getShort();
        out.writeShort((short) asymLength);
        byte[] c = new byte[asymLength];
        buf.get(c);
        out.write(c);
        return bos.toByteArray();
    }

    /**
     *
     * @param key
     * @param symCaAttestation
     * @return
     * @throws BufferUnderflowException
     * @throws SymCaDecryptionException
     */
    public static byte[] decryptSymCaAttestation(byte[] key, byte[] symCaAttestation) throws BufferUnderflowException, SymCaDecryptionException {
        try {
            ByteBuffer buf = ByteBuffer.wrap(symCaAttestation);
            int credSize = buf.getInt();
            buf.getInt(); // algorithmid
            buf.getShort(); // encScheme
            buf.getShort(); //
            int subParamSize = buf.getInt();
            buf.position(buf.position() + subParamSize);
            byte[] iv = new byte[16];
            buf.get(iv);
            byte[] cipherText = new byte[credSize - 16];
            buf.get(cipherText);
            //decrypt the cipher text
            Cipher symCipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            symCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), ivSpec);
            return symCipher.doFinal(cipherText);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException ex) {
            throw new SymCaDecryptionException(ex);
        }
    }

    /**
     *
     * @param value
     * @return
     */
    public static byte[] intToByteArray(int value) {
        return ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN).putInt(value).array();
    }

    /**
     *
     * @param prefix
     * @param suffix
     * @return
     */
    public static File getTempFile(String prefix, String suffix) {
        return Paths.get(System.getProperty("java.io.tmpdir"), prefix + UUID.randomUUID().toString() + suffix).toFile();
    }
}
