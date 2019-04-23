/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm.integration;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonParseException;
import com.intel.mtwilson.core.tpm.Tpm;
import com.intel.mtwilson.core.tpm.Tpm.CredentialType;
import com.intel.mtwilson.core.tpm.Tpm.PcrBank;
import com.intel.mtwilson.core.tpm.Tpm.NVAttribute;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Set;
import com.intel.kunit.annotations.*;
import com.intel.kunit.annotations.Integration.*;
import com.intel.mtwilson.core.tpm.util.Utils;
import gov.niarl.his.privacyca.TpmUtils;
import java.lang.reflect.Type;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.security.cert.CertificateException;
import static com.google.common.truth.Truth.assertThat;
import com.intel.mtwilson.core.privacyca.PrivacyCA;
import com.intel.mtwilson.core.tpm.Tpm.Pcr;
import com.intel.mtwilson.core.tpm.model.CertifiedKey;
import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Calendar;
import java.util.EnumSet;
import javax.security.auth.x500.X500Principal;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
/**
 *
 * @author dczech
 */
@Deserializer(TpmIntegrationTest.X509Deserializer.class)
public class TpmIntegrationTest {

    final private static String NULL_AUTH = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]";
    final private static byte[] NULL_AUTH_BYTES = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * Deserializes a String to an X509Certificate
     */
    public static class X509Deserializer implements JsonDeserializer<X509Certificate> {

        @Override
        public X509Certificate deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            try {
                return TpmUtils.certFromBytes(json.getAsString().getBytes());
            } catch (CertificateException | java.security.cert.CertificateException ex) {
                Logger.getLogger(TpmIntegrationTest.class.getName()).log(Level.SEVERE, null, ex);
                throw new JsonParseException(ex);
            }
        }
    }

    private static Tpm tpm;

    /**
     * Default Constructor
     */
    public TpmIntegrationTest() {
    }

    /**
     * Setup method that runs once before running Integration Tests
     *
     * @throws IOException
     */
    @BeforeAll
    public static void setup() throws IOException {
        String binFolder = System.getenv("TPM_TOOLS_PATH");
        if (binFolder == null || !Files.exists(Paths.get(binFolder))) {
            throw new IOException("Folder specified by Environment Variable TPM_TOOLS_PATH does not exist");
        }
        tpm = Tpm.open(binFolder);
        assertThat(tpm).isNotNull();
    }

    private static Path extractAllBinaries() throws IOException {
        Path dir = Files.createTempDirectory("tpm-tools");
        extractBinary("tpm2_nvlist", dir);
        extractBinary("tpm2_nvread", dir);
        extractBinary("tpm2_nvwrite", dir);
        extractBinary("tpm2_nvdefine", dir);
        extractBinary("tpm2_nvrelease", dir);
        extractBinary("tpm2_load", dir);
        extractBinary("tpm2_listpcrs", dir);
        extractBinary("tpm2_evictcontrol", dir);
        extractBinary("tpm2_activatecredential", dir);
        extractBinary("tpm2_create", dir);
        extractBinary("tpm2_certify", dir);
        extractBinary("tpm2_takeownership", dir);
        extractBinary("tpm2_listpersistent", dir);
        extractBinary("tpm2_getpubek", dir);
        extractBinary("tpm2_getpubak", dir);
        extractBinary("tpm2_readpublic", dir);
        // 1.2
        extractBinary("NIARL_TPM_Module", dir);
        extractBinary("tpm_nvdefine", dir);
        extractBinary("tpm_nvinfo", dir);
        extractBinary("tpm_nvread", dir);
        extractBinary("tpm_nvrelease", dir);
        extractBinary("tpm_nvdefine", dir);
        // windows
        extractBinary("TPMTool.exe", dir);
        extractBinary("TpmAtt.dll", dir);
        return dir;
    }

    private static void extractBinary(String file, Path folder) throws IOException {
        InputStream is = TpmIntegrationTest.class.getClassLoader().getResourceAsStream(file);
        File binary = folder.resolve(file).toFile();
        FileUtils.copyInputStreamToFile(is, binary);
        binary.setExecutable(true, false);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#takeOwnership(byte[])
     * @param newOwnerAuth byte array for the owner auth
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(platform = OS.LINUX, tpm = TPM.ANY, parameters = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]")
    public void takeOwnership(byte[] newOwnerAuth) throws IOException, Tpm.TpmException {
        tpm.takeOwnership(newOwnerAuth);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#isOwnedWithAuth(byte[])
     * @param ownerAuth
     * @return
     * @throws IOException
     */
    @Integration(platform = OS.LINUX, parameters = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]")
    public boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException {
        return tpm.isOwnedWithAuth(ownerAuth);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#getCredential(byte[], com.intel.mtwilson.core.tpm.Tpm.CredentialType)
     * @param ownerAuth
     * @param credentialType
     * @return
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(parameters = {
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "EC"
    })
    public byte[] getCredential(byte[] ownerAuth, CredentialType credentialType) throws IOException, Tpm.TpmException {
        return tpm.getCredential(ownerAuth, credentialType);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#setCredential(byte[], com.intel.mtwilson.core.tpm.Tpm.CredentialType, byte[])
     * @param ownerAuth
     * @param credentialType
     * @param credentialBlob
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(platform = OS.LINUX, parameters = {
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "EC",
        "[0,1,2,3]"
    })
    public void setCredential(byte[] ownerAuth, CredentialType credentialType, byte[] credentialBlob) throws IOException, Tpm.TpmException {
        tpm.setCredential(ownerAuth, credentialType, credentialBlob);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#getEndorsementKeyModulus(byte[])
     * @param ownerAuth
     * @return
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(platform = OS.LINUX, parameters = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]")
    public byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        return tpm.getEndorsementKeyModulus(ownerAuth);
    }

    /**
     * Deserializer for PublicKey (RSA modulus)
     */
    public class PublicKeyDeserializer implements JsonDeserializer<PublicKey> {

        @Override
        public PublicKey deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
            BigInteger bigInt = new BigInteger(json.getAsString());
            try {
                return TpmUtils.makePubKey(bigInt.toByteArray(), TpmUtils.intToByteArray(65537));
            } catch (TpmUtils.TpmUnsignedConversionException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
                Logger.getLogger(TpmIntegrationTest.class.getName()).log(Level.SEVERE, null, ex);
                throw new JsonParseException(ex);
            }
        }
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#setAssetTag(byte[], byte[])
     * @param ownerAuth
     * @param assetTagHash
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(parameters = {
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "[1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2]" // 32
    })
    public void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, Tpm.TpmException {
        tpm.setAssetTag(ownerAuth, assetTagHash);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#readAssetTag(byte[])
     * @param ownerAuth
     * @return
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(parameters = "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]")
    public byte[] readAssetTag(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        return tpm.readAssetTag(ownerAuth);
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#getAssetTagIndex()
     * @return
     */
    @Integration
    public int getAssetTagIndex() {
        return tpm.getAssetTagIndex();
    }

    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#getPcrBanks()
     * @return @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration
    public Set<PcrBank> getPcrBanks() throws IOException, Tpm.TpmException {
        return tpm.getPcrBanks();
    }
    
    /**
     * @see com.intel.mtwilson.core.tpm.Tpm#nvDefine(byte[], byte[], int, int, java.util.Set)
     * @see com.intel.mtwilson.core.tpm.Tpm#nvWrite(byte[], int, byte[])
     * @see com.intel.mtwilson.core.tpm.Tpm#nvRead(byte[], int, int)
     * @see com.intel.mtwilson.core.tpm.Tpm#nvRelease(byte[], int)
     * @param ownerAuth - Owner password
     * @param indexPassword - NVRAM area password
     * @param index - Index of the NVRAM area
     * @param size - Size of the NVRAM area
     * @param attributes - Permissions of the NVRAM area
     * @param authPassword - password to read from/write to the NVRAM index
     * @param writeData - the data which to write to the NVRAM index. Must not exceed
     * the size defined by the NVRAM index.
     * @throws IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    @Integration(parameters = {
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "12345678", // base 10 only
        "20", // size
        "[AUTHWRITE]", // set in JSON is [] array
        "[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]",
        "[1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0]"
    })
    public void testNvFunctionalities(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes, byte[] authPassword, byte[] writeData) throws IOException, Tpm.TpmException {
        System.out.println("--------------------------------------------------------------------------------------------------------------");
        System.out.println("Testing NvRAM Functionalities(nvDefine, nvWrite, nvRead and nvRelease)...");
        System.out.println("NvRAM Index " + index  + "exists? " + tpm.nvIndexExists(index));
        System.out.println("Defining NvRAM Index " + index  + "...");
        tpm.nvDefine(ownerAuth, indexPassword, index, size, attributes);
        System.out.println("Writing data " + Arrays.toString(writeData) + " to NvRAM Index " + index  + "...");
        tpm.nvWrite(authPassword, index, writeData);
        System.out.println("Reading data from NvRAM Index " + index  + "...\n" + Arrays.toString(tpm.nvRead(authPassword, index, size)));
        System.out.println("Releasing NvRAM Index " + index  + "...");
        tpm.nvRelease(ownerAuth, index);
        System.out.println("--------------------------------------------------------------------------------------------------------------");
    }

    /**
     *
     * @return
     */
    @Integration
    public String getTpmVersion() {
        return tpm.getTpmVersion();
    }

    private X509Certificate makeAikCert(PublicKey aik, String sanLabel, RSAPrivateKey privKey, X509Certificate caCert, int validityDays) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(caCert.getSubjectX500Principal());
        certGen.setNotBefore(new java.sql.Time(System.currentTimeMillis()));
        Calendar expiry = Calendar.getInstance();
        expiry.add(Calendar.DAY_OF_YEAR, validityDays);
        certGen.setNotAfter(expiry.getTime());
        certGen.setSubjectDN(new X500Principal(""));
        certGen.setPublicKey(aik);
        certGen.setSignatureAlgorithm("SHA256withRSA");
        certGen.addExtension(org.bouncycastle.asn1.x509.X509Extension.subjectAlternativeName /*org.bouncycastle.asn1.x509.X509Extensions.SubjectAlternativeName*/, true, new GeneralNames(new GeneralName(GeneralName.rfc822Name, sanLabel)));
        X509Certificate cert = certGen.generate(privKey, "BC");
        return cert;
    }

    RSAPublicKey makeRSAPubKey(byte[] modulus) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchAlgorithmException {
        BigInteger modI = new BigInteger(1, modulus);
        BigInteger expI = BigInteger.valueOf(65537);
        RSAPublicKeySpec newKeySpec = new RSAPublicKeySpec(modI, expI);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey newKey = (RSAPublicKey) keyFactory.generatePublic(newKeySpec);
        return newKey;
    }

    /**
     * Tests full flow of provisioning AIK and fetching a quote on Linux. It does these operations in order:
     * <br>
     * <pre>
     * Tpm.takeOwnership()
     * Tpm.isOwnedWithAuth()
     * Tpm.getEndorsementKeyModulus()
     * Tpm.getCredential()
     * Tpm.setCredential()
     * Tpm.collateIdentityRequest()
     * PrivacyCA.processIdentityRequest()
     * Tpm.activateIdentity()
     * Tpm.getQuote
     * </pre>
     * You should test getModuleLog() and set/getAssetTag() separately, but onlY AFTER running this test.
     * @param ownerAuth
     * @throws Exception
     */
    @Integration(parameters = NULL_AUTH, platform = OS.LINUX)
    public void testSetupFlowLinux(byte[] ownerAuth) throws Exception {
        System.out.println("Taking ownership...");
        try {
            tpm.takeOwnership(ownerAuth);
        } catch(Tpm.TpmOwnershipAlreadyTakenException ex) {
            // this is ok
        }
        assertThat(tpm.isOwnedWithAuth(ownerAuth)).isTrue();
        byte[] ekMod = tpm.getEndorsementKeyModulus(ownerAuth);
        assertThat(ekMod).isNotEmpty();
        System.out.println("Creating Endorsement Certificate and KeyPair...");
        new File("endorsement.p12").delete();
        new File("privacy.p12").delete();
        TpmUtils.createCaP12(2048, "Endorsement", "password", "endorsement.p12", 2);
        X509Certificate endorsementCaCert = TpmUtils.certFromP12("endorsement.p12", "password");
        RSAPrivateKey endorsementPrivKey = TpmUtils.privKeyFromP12("endorsement.p12", "password");
        X509Certificate ec = TpmUtils.makeEkCert(ekMod, endorsementPrivKey, endorsementCaCert, 2);
        System.out.println("Creating Privacy Certificates and KeyPair...");
        TpmUtils.createCaP12(2048, "Privacy", "password", "privacy.p12", 2);
        X509Certificate pcaCert = TpmUtils.certFromP12("privacy.p12", "password");
        RSAPrivateKey pcaPriv = TpmUtils.privKeyFromP12("privacy.p12", "password");
        assertThat(pcaPriv.getModulus()).isEqualTo(((RSAPublicKey)pcaCert.getPublicKey()).getModulus());
        byte[] ecTpm;
        try {
            ecTpm = tpm.getCredential(ownerAuth, CredentialType.EC);
            assertThat(ecTpm).isNotNull();
            System.out.println("EC already present");
        } catch(Tpm.TpmException ex) {
            System.out.println("EC not prsent, deploying a self signed one...");
            tpm.setCredential(ownerAuth, CredentialType.EC, ec.getEncoded());
            ecTpm = tpm.getCredential(ownerAuth, CredentialType.EC);
            assertThat(ecTpm).isEqualTo(ec.getEncoded());
            System.out.println("EC deployed");
        }
        ec = TpmUtils.certFromBytes(ecTpm);
        byte[] aikSecret = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] keyAuth = aikSecret;
        System.out.println("TPM: Collating Identity Request...");
        IdentityRequest idreq = tpm.collateIdentityRequest(ownerAuth, aikSecret, pcaCert.getPublicKey());
        assertThat(idreq).isNotNull();
        assertThat(idreq.getIdentityRequestBlob()).isNotEmpty();
        assertThat(idreq.getAikBlob()).isNotEmpty();
        assertThat(idreq.getAikModulus()).isNotEmpty();
        assertThat(idreq.getAikName()).isNotEmpty();
        // pretend we are on a different machine as the PrivacyCA
        RSAPublicKey aikPubKey = makeRSAPubKey(idreq.getAikModulus());
        byte[] randomChallenge = TpmUtils.createRandomBytes(32);
        System.out.println("PrivacyCA: Processing Identity Request...");
        IdentityProofRequest step1 = PrivacyCA.processIdentityRequest(idreq, pcaPriv, (RSAPublicKey) pcaCert.getPublicKey(), (RSAPublicKey)ec.getPublicKey(), randomChallenge);
        // pretend we are back on the TPM side
        System.out.println("TPM: Activating Identity Proof Request...");
        byte[] step2 = tpm.activateIdentity(ownerAuth, aikSecret, step1);
        assertThat(step2).isEqualTo(randomChallenge);
        // now, pretend we sent it back
        // we are PCA again, make the cert
        X509Certificate aikCert = makeAikCert(aikPubKey, "HIS_Identity_Key", pcaPriv, pcaCert, 2);
        assertThat(aikCert).isNotNull();
        System.out.println("PrivacyCA: Processing Identity Request part 2...");
        IdentityProofRequest step3 = PrivacyCA.processIdentityRequest(idreq, pcaPriv, (RSAPublicKey) pcaCert.getPublicKey(), (RSAPublicKey)ec.getPublicKey(), aikCert.getEncoded());
        // back to tpm
        System.out.println("TPM: Activating Identity Proof Request part 2...");
        byte[] step4 = tpm.activateIdentity(ownerAuth, aikSecret, step3);
        assertThat(step4).isEqualTo(aikCert.getEncoded());
        byte[] nonce = aikSecret;
        System.out.println("Getting Tpm Quote...");
        TpmQuote quote = tpm.getQuote(tpm.getPcrBanks(), EnumSet.allOf(Pcr.class), idreq.getAikBlob(), aikSecret, nonce);
        assertThat(quote).isNotNull();
        assertThat(quote.getPcrBanks()).isEqualTo(tpm.getPcrBanks());
        assertThat(quote.getQuoteData()).isNotEmpty();
    }

    /**
     * Tests full flow of provisioning AIK and fetching a quote on Windows
     * <br>
     * <pre>
     * Tpm.getCredential()
     * Tpm.collateIdentityRequest()
     * PrivacyCA.processIdentityRequest()
     * Tpm.activateIdentity()
     * Tpm.getQuote
     * </pre>
     * You should set/getAssetTag() separately, but onlY AFTER running this test.
     * @throws Exception
     */
    @Integration(platform = OS.WINDOWS)
    public void testSetupFlowWindows() throws Exception {
        byte[] ec = tpm.getCredential(null, CredentialType.EC);
        assertThat(ec).isNotEmpty();
        byte[] aikSecret = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9};
        byte[] keyAuth = aikSecret;
        System.out.println("Creating Privacy Certificates...");
        TpmUtils.createCaP12(2048, "Privacy", "password", "privacy.p12", 2);
        X509Certificate pca = TpmUtils.certFromP12("privacy.p12", "password");
        RSAPrivateKey caPrivKey = TpmUtils.privKeyFromP12("privacy.p12", "password");
        X509Certificate endorsementCredential = TpmUtils.certFromBytes(ec);
        System.out.println("TPM: Collating Identity Request...");
        IdentityRequest idreq = tpm.collateIdentityRequest(null, aikSecret, pca.getPublicKey());
        assertThat(idreq).isNotNull();
        assertThat(idreq.getAikBlob()).isNotEmpty();
        assertThat(idreq.getAikModulus()).isNotEmpty();
        assertThat(idreq.getAikName()).isNotEmpty();
        RSAPublicKey aikPubKey = makeRSAPubKey(idreq.getAikModulus());
        byte[] randomChallenge = TpmUtils.createRandomBytes(32);
        System.out.println("PrivacyCA: Processing Identity Request...");
        IdentityProofRequest pr1 = PrivacyCA.processIdentityRequest(idreq, caPrivKey, (RSAPublicKey)pca.getPublicKey(), (RSAPublicKey)endorsementCredential.getPublicKey(), randomChallenge);
        System.out.println("TPM: Activating Identity Proof Request...");
        byte[] a1 = tpm.activateIdentity(null, aikSecret, pr1);
        assertThat(a1).isNotNull();
        assertThat(a1).isEqualTo(randomChallenge);
        X509Certificate aikCert = makeAikCert(aikPubKey, "HIS_Identity_Key", caPrivKey, pca, 2);
        assertThat(aikCert).isNotNull();
        System.out.println("PrivacyCA: Processing Identity Request part 2...");
        IdentityProofRequest pr2 = PrivacyCA.processIdentityRequest(idreq, caPrivKey, (RSAPublicKey)pca.getPublicKey(), (RSAPublicKey)endorsementCredential.getPublicKey(), aikCert.getEncoded());
        System.out.println("TPM: Activating Identity Proof Request part 2...");
        byte[] a2 = tpm.activateIdentity(null, aikSecret, pr2);
        assertThat(a2).isNotNull();
        assertThat(a2).isEqualTo(aikCert.getEncoded());
        byte[] nonce = aikSecret;
        System.out.println("Getting quote...");
        TpmQuote quote = tpm.getQuote(tpm.getPcrBanks(), EnumSet.allOf(Pcr.class), idreq.getAikBlob(), aikSecret, nonce);
        assertThat(quote).isNotNull();
        assertThat(quote.getPcrBanks()).isEqualTo(tpm.getPcrBanks());
        assertThat(quote.getQuoteData()).isNotEmpty();
    }
    
    @Integration(platform=OS.LINUX)
    public String getModuleLog() throws IOException, Tpm.TpmException {
        return tpm.getModuleLog();
    }

    /**
     * Test deployment of Asset Tag First writes 32 bytes of random data to NVRAM using nvWrite() @ location specified by getAssetTagIndex() Then it reads 32
     * bytes of data by using nvRead()
     *
     * @param ownerAuth
     * @throws IOException
     * @throws Tpm.TpmException
     */
    @Integration(parameters = NULL_AUTH)
    public void testAssetTagDeployment(byte[] ownerAuth) throws IOException, Tpm.TpmException {
        byte[] assetTag = TpmUtils.createRandomBytes(32);
        tpm.setAssetTag(ownerAuth, assetTag);
        byte[] read = tpm.readAssetTag(ownerAuth);
        assertThat(read).isEqualTo(assetTag);
    }
}
