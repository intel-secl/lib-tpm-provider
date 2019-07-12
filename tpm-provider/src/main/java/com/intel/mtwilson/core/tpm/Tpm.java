/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package com.intel.mtwilson.core.tpm;

import com.intel.mtwilson.core.tpm.model.TpmQuote;
import com.intel.mtwilson.core.tpm.shell.CommandLineResult;
import com.intel.mtwilson.core.tpm.shell.TpmTool;
import com.intel.mtwilson.core.common.tpm.model.IdentityProofRequest;
import com.intel.mtwilson.core.common.tpm.model.IdentityRequest;

import java.io.*;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.CertificateEncodingException;
import java.security.PublicKey;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.SystemUtils;
import tss.TpmDeviceLinux;
import tss.TpmDeviceTbs;

import javax.xml.bind.JAXBException;
import javax.xml.stream.XMLStreamException;

/**
 * <h1>Tpm</h1>
 * The Tpm interface defines a set of trust related commands that can be
 * implemented across any Tpm 1.2 or 2.0 devices on any operating system.
 *
 * @author Zech, David
 * @version 1.0
 * @since 2017-6-26
 */
public abstract class Tpm {

    /**
     *
     */
    private final static org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(Tpm.class);
    protected final static String KEY_NAME = "HIS_Identity_Key";
    private static String MEASUREMENT_FILE_PREFIX = "measurement_";

    /**
     * <p>
     * Returns a String containing an XML Module log of components measured by TXT+Tboot.
     * Data is retrieved by parsing data retrieved from the command line tool `txt-stat` which is included with tboot
     * The module log contains an timeline of crytographic hashes that were extended to each Platform Configuration Register
     * Replying the timeline of extensions by calculating PCR = HASH(PCR | ComponentHash) should yield you the final value
     * that resides within the particular Register.
     * </p>
     * @return
     * @throws IOException 
     * @throws TpmException
     */
    public abstract String getModuleLog() throws IOException, TpmException;

    /**
     * Returns an String containing an XML log of Components measured by Tboot-XM. If Tboot-XM is not configured or installed,
     * a TpmException will be thrown. 
     * @return
     * @throws IOException
     * @throws TpmException
     */
    public abstract List<String> getTcbMeasurements() throws IOException, TpmException;

    protected List<String> getTcbMeasurements(File tcbMeasurementsDir) throws TpmException {
        List<String> tcbMeasurements = new ArrayList<>();
        if (tcbMeasurementsDir.exists() && getMeasurementFiles(tcbMeasurementsDir) != null) {
            for (File tcbMeasurementFile : getMeasurementFiles(tcbMeasurementsDir)) {
                LOG.debug("Processing the TCB measurement XML file @ {}.", tcbMeasurementFile.toString());
                tcbMeasurements.add(getMeasurement(tcbMeasurementFile));
            }
        } else {
            LOG.warn("TCB measurement XML directory does not exist at {}.", tcbMeasurementsDir.getAbsolutePath());
        }
        return tcbMeasurements;
    }

    private File[] getMeasurementFiles(File tcbMeasurementsDir) {
        return tcbMeasurementsDir.listFiles((File dir, String name) ->
                name.startsWith(MEASUREMENT_FILE_PREFIX)
        );
    }

    private String getMeasurement(File tcbMeasurementFile) throws TpmException {
        String tcbMeasurementString;
        try (InputStream in = new FileInputStream(tcbMeasurementFile)) {
            tcbMeasurementString = IOUtils.toString(in, Charset.forName("UTF-8"));
            LOG.info("TCB measurement XML string: {}", tcbMeasurementString);
            MeasurementUtils.parseMeasurementXML(tcbMeasurementString);
        } catch (IOException | JAXBException | XMLStreamException e) {
            LOG.warn("IOException, invalid measurement.xml: {}", e.getMessage());
            throw new TpmException("Invalid measurement.xml file. Cannot unmarshal/marshal object using jaxb.");
        }
        return tcbMeasurementString;
    }

    protected String getModulesFromMeasureLogXml(String xmlInput) {
        // Since the output from the script will have lot of details and we are interested in just the module section, we will
        // strip out the remaining data,
        Pattern PATTERN = Pattern.compile("(<modules>.*</modules>)");
        Matcher m = PATTERN.matcher(xmlInput);
        while (m.find()) {
            xmlInput = m.group(1);
        }
        // removes any white space characters from the xml string
        String moduleInfo = xmlInput.replaceAll(">\\s*<", "><");
        // If we have XML data, we we will have issues mapping the response to the ClientRequestType using JaxB unmarshaller. So,
        // we will encode the string and send it.
        return Base64.encodeBase64String(moduleInfo.getBytes());
    }

    /**
     * <p>
     * Exception that indicates the TPM returned an error</p>
     */
    public static class TpmException extends Exception {

        private static final long serialVersionUID = 0;

        private Integer errorCode = null;

        /**
         * Construct a TpmException with a message
         *
         * @param msg
         */
        public TpmException(String msg) {
            super(msg);
        }

        /**
         * Construct a TpmException with a message and error code
         *
         * @param msg
         * @param errorCode
         */
        public TpmException(String msg, int errorCode) {
            super(String.format("%s (%d)", msg, errorCode));
            this.errorCode = errorCode;
        }

        /**
         *
         * @param t
         */
        public TpmException(Throwable t) {
            super(t);
        }

        /**
         *
         * @param msg
         * @param t
         */
        public TpmException(String msg, Throwable t) {
            super(msg, t);
        }

        /**
         *
         * @return error code if set, or null if it was not set
         */
        public Integer getErrorCode() {
            return errorCode;
        }
    }

    /**
     * Exception that indicates a Tpm is already owned with an unknown password
     */
    public static class TpmOwnershipAlreadyTakenException extends TpmException {

        /**
         *
         * @param msg
         * @param errorCode
         */
        public TpmOwnershipAlreadyTakenException(String msg, int errorCode) {
            super(msg, errorCode);
        }
    }
    
    public static class TpmTcbMeasurementMissingException extends TpmException {
        
        public TpmTcbMeasurementMissingException(String msg) {
            super(msg);
        }
    }

    /**
     * Exception that indicates a Credential requested with getCredential() failed because it does not exist
     */
    public static class TpmCredentialMissingException extends TpmException {

        /**
         *
         * @param msg
         * @param errorCode
         */
        public TpmCredentialMissingException(String msg, int errorCode) {
            super(msg, errorCode);
        }

        /**
         *
         * @param msg
         */
        public TpmCredentialMissingException(String msg) {
            super(msg);
        }
    }

    /**
     * Disk path to a folder containing the required Tpm Tools
     */
    private final String tpmToolsPath;

    /**
     * Default Constructor. Tpm Tools path is defaulted to /usr/sbin
     * Do not use, look at the static method Tpm.open() instead
     */
    protected Tpm() {
        tpmToolsPath = "/usr/local/sbin";
    }

    /**
     * Constructor where the User specified the Tpm Tools Path
     * Do not use, look at the static method Tpm.open() instead
     * @param tpmToolsPath
     */
    protected Tpm(String tpmToolsPath) {
        this.tpmToolsPath = tpmToolsPath;
    }

    /**
     * Get the configured TPM Tools path on the file system
     *
     * @return the TPM Tools Path
     */
    public final String getTpmToolsPath() {
        return tpmToolsPath;
    }

    private static String detectTpmVersionLinux() {
        File caps1 = Paths.get("/sys", "class", "misc", "tpm0", "device", "caps").toFile();
        File caps2 = Paths.get("/sys", "class", "tpm", "tpm0", "device", "caps").toFile();
        if (caps1.exists() || caps2.exists()) {
            return "1.2";
        } else {
            return "2.0";
        }
    }
    
    /**
     * Returns a String indicating what Tpm Version this Host has installed.
     * @return "1.2" or "2.0"
     * @throws java.io.IOException
     */
    public static String detectInstalledTpmVersion() throws IOException {
        if(SystemUtils.IS_OS_LINUX) {
            return detectTpmVersionLinux();
        } else if(SystemUtils.IS_OS_WINDOWS) {
            return detectTpmVersionWindows();
        }
        throw new UnsupportedOperationException("Operating System not Supported");
    }
    
    private static String detectTpmVersionWindows() throws IOException {
        try {
            TpmTool cl = new TpmTool("powershell.exe");
            cl.addArgument("Get-WmiObject");
            cl.addArgument("-class");
            cl.addArgument("Win32_Tpm");
            cl.addArgument("-namespace");
            cl.addArgument("root\\CIMV2\\Security\\MicrosoftTPM");
            cl.addArgument("|");
            cl.addArgument("Select-Object");
            cl.addArgument("-ExpandProperty");
            cl.addArgument("SpecVersion");
            CommandLineResult result = cl.execute();
            if(result.getReturnCode() == 0) {
                return result.getStandardOut().trim().split(", ")[0];
            }
        } catch (IOException ex) {
            throw ex;
        }
        throw new IllegalStateException("Could not automatically detect Windows TPM Version");
    }

    /**
     * <p>
     * Static method to open a new Instance of a Tpm object. 
     * This method will automatically try and locate the Tpm Tools folder by searching 
     * common paths used by Intel Trust Agent.
     * If you are using this library in your own project, consider using {@link #open(java.nio.file.Path) } that lets you specify 
     * the path manually.
     * </p>
     * @return a new Instance of Tpm.
     * @throws java.io.IOException
     */
    public static Tpm open() throws IOException {
        if (SystemUtils.IS_OS_LINUX) {
            if (V12.equals(detectTpmVersionLinux())) {
                throw new IllegalStateException("TPM 1.2 is not supported on Linux");
            } else {
                if (Files.exists(Paths.get("/dev", "tpm0"))) {
                    return new TpmLinuxV20(new TpmDeviceLinux());
                } else {
                    throw new IllegalStateException("TPM driver is not loaded");
                }
            }
        } else if (SystemUtils.IS_OS_WINDOWS) {
            if (V12.equals(detectTpmVersionWindows())) {
                return new TpmWindowsV12(Paths.get("/Program Files (x86)", "Intel", "Trustagent", "bin").toString());
            } else {
                return new TpmWindowsV20(new TpmDeviceTbs());
            }
        }
        throw new IllegalStateException("Unsupported Operating System");
    }
    
    /**
     * <p>
     * Static method to open a new Instance of a Tpm object. 
     * This method lets you specify the location of the Tpm Tools Folder
     * </p>
     * @param tpmToolsPath
     * @return
     * @throws java.io.IOException
     */
    public static Tpm open(Path tpmToolsPath) throws IOException {
        return Tpm.open(tpmToolsPath.toString()); 
    }
    
    /**
     * <p>
     * Static method to open a new Instance of a Tpm object. 
     * This method lets you specify the location of the Tpm Tools Folder
     * </p>
     * @param tpmToolsPath
     * @return
     * @throws java.io.IOException
     */
    public static Tpm open(String tpmToolsPath) throws IOException {
        if (SystemUtils.IS_OS_LINUX) {
            if (V12.equals(detectTpmVersionLinux())) {
                throw new IllegalStateException("TPM 1.2 is not supported on Linux");
            } else {
                if (Files.exists(Paths.get("/dev", "tpm0"))) {
                    return new TpmLinuxV20(new TpmDeviceLinux());
                } else {
                    throw new IllegalStateException("TPM driver is not loaded");
                }
            }
        } else if (SystemUtils.IS_OS_WINDOWS) {
            if (V12.equals(detectTpmVersionWindows())) {
                return new TpmWindowsV12(tpmToolsPath);
            } else {
                return new TpmWindowsV20(new TpmDeviceTbs());
            }
        }
        throw new IllegalStateException("Unsupported Operating System");
    }

    /**
     * <p>
     * Takes ownership of a TPM with a byte array specifying the Owner Authorization Password
     * Ownership of a TPM is required to perform commands that require elevation. Taking ownership
     * is akin to setting the password for commands that require elevation.
     * </p>
     *
     * @param newOwnerAuth <pre>the owner authorization blob to take ownership of the TPM with</pre>
     *
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void takeOwnership(byte[] newOwnerAuth) throws IOException, TpmException;

    /**
     * Helper method that determines if a Tpm is owned with the supplied password
     * @param ownerAuth
     * @return
     * @throws IOException
     */
    public abstract boolean isOwnedWithAuth(byte[] ownerAuth) throws IOException;

    /**
     * Enum that indicates what type of Credential Type to Store/Retrieve from
     * TPM
     */
    public static enum CredentialType {

        /**
         * Endorsement Credential
         */
        EC,
        /**
         * Unsupported
         */
        CC,
        /**
         * Unsupported
         */
        PC,
        /**
         * Unsupported
         */
        PCC
    }

    /**
     * <p>
     * Retrieve a credential from the TPM. A credential is usually an encoded X509 Certificate that is returned in the form of a 
     * byte array. For example, getCredential with CredentialType.EC will give you the Tpm's Endorsement Credential.
     * 
     * Not all TPM's come preinstalled with Credentials, so it may be necessary to deploy one using {@link #setCredential(byte[], com.intel.mtwilson.core.tpm.Tpm.CredentialType, byte[]) }
     * first using an encoded certificate issued by a trusted endorsement authority.
     * 
     * For example, TPM 2.0 chips do not come preinstalled with an Endorsement Credential, so a PrivacyCA would issue an EndorsementCredential 
     * that endorses this Tpm's Endorsement Key Modulus (retrieved with {@link #getEndorsementKeyModulus(byte[]) }) in the form of an encoded X509Certificate
     * </p>
     *
     * @param ownerAuth the owner authorization blob required to issue the command
     * @param credentialType
     * <p>
     * indicator of what type of credential to retrieve. For TPM 1.2 it can be
     * EC, PC, CC, or PCC. On TPM 2.0 credentialType is ignored, and always
     * returns the EC (Endorsement Credential)</p>
     * @return byte array containing the credential blob
     * @throws java.io.IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract byte[] getCredential(byte[] ownerAuth, CredentialType credentialType) throws IOException, TpmException;

    /**
     * <p>
     * Store a credential to the TPM.
     * 
     * A credential is usually an encoded X509 Certificate that is returned in the form of a 
     * byte array. For example, getCredential with CredentialType.EC will give you the Tpm's Endorsement Credential.
     * 
     * No validation is done on the data being stored, so ensure it is correct.
     * </p>
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command
     * @param credentialType
     * <p>
     * indicator of what type of credential to store. For TPM 1.2 it can be EC,
     * PC, CC, or PCC. On TPM 2.0 credentialType is ignored, and always stores
     * the EC( Endorsment Certificate). Therefore, specifying Credential Types other than PC, CC, or PCC
     * should only happen once you've verified that the TPM is version 1.2 via {@link #getTpmVersion() }</p>
     * @param credentialBlob
     * @throws java.io.IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void setCredential(byte[] ownerAuth, CredentialType credentialType, byte[] credentialBlob) throws IOException, TpmException;

    /**
     * <p>
     * Retrieve the Endorsement Key Modulus (public key EKpub)from the Tpm.
     * 
     * The Endorsement Key Modulus is the public portion of an RSA Keypair that is issued at TPM manufacturing time.
     * The Private portion is to never be revealed by any means, and the TPM has software and hardware (physical) protections
     * against this. This function is useful for TPM's that do not come preinstalled with an Endorsement Credential 
     * (synonymous with Endorsement Certificate) from a Trusted Certificate Authority. The Endorsement Key Modulus can be 
     * sent to a Certificate Authority to receive an Endorsement Certificate, which can then be installed using
     * {@link #setCredential(byte[], com.intel.mtwilson.core.tpm.Tpm.CredentialType, byte[]) } with CredentialType.EC
     * </p>
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command
     * @return
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract byte[] getEndorsementKeyModulus(byte[] ownerAuth) throws IOException, TpmException;

    /**
     * <p>
     * Create a new Attestation Identity Key (AIK) and collates the required structures for proving ownership of this AIK
     * inside an IdentityRequest object.
     * 
     * The Attestation Identity Key derives from the Tpm's Endorsement Credential (which derives from the installed Endorsement Key), so it is
     * important that a Endorsement Credential is present before calling this function. You can verify that one exists with 
     * {@link #getCredential(byte[], com.intel.mtwilson.core.tpm.Tpm.CredentialType) } with CredentialType.EC.
     * 
     * The IdentityRequest object this function returns is solely for the use of a PrivacyCA (using the lib-privacyca) to use to generate a 
     * proof request for this tpm.
     * </p>
     * @param ownerAuth the value of ownerAuth
     * @param keyAuth the value of keyAuth, which is a secret to protect this particular new AIK.
     * @param pcaPubKey the value of pcaPubKeyBlob which is the public portion of an external PrivacyCA's RSA keypair.
     * @return IdentityRequest containing the AIK and proof information
     * @throws IOException
     * @throws TpmException
     * @throws CertificateEncodingException
     */
    public abstract IdentityRequest collateIdentityRequest(byte[] ownerAuth, byte[] keyAuth, PublicKey pcaPubKey) throws IOException, TpmException, CertificateEncodingException;

    /**
     * <p>
     * Activate an identity given a Proof Request issued from a PrivacyCA (which generated a proof Request using the 
     * return from {@link #collateIdentityRequest(byte[], byte[], java.security.PublicKey) }.
     * 
     * This function will decrypt a blob of data that was encrypted using the public portion of the AIK.
     * Generally, a PrivacyCA will encrypt some blob of data using AIKpublic. The TPM can decrypt this using
     * AIKprivate which is sufficient to serve as proof of ownership over the private portion of the AIK.
     * </p>
     *
     * <code>activateIdentity</code> should follow after
     * <code>collateIdentityRequest</code> and an identity challenge from an
     * external party. <code>activateIdentity</code> is supported for both TPM
     * 1.2 and 2.0
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command.
     * @param keyAuth key authorization blob, synonymous with AIK Secret
     * @param proofRequest a proof request object that comes from a PrivacyCA.
     * external party (Certificate Authority) is generally decrypted with the
     * decrypted result from <code>asymCaContents</code>
     * @return buffer containing the activated (decrypted) identity.
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract byte[] activateIdentity(byte[] ownerAuth, byte[] keyAuth, IdentityProofRequest proofRequest) throws IOException, TpmException;

    /**
     * Enum that specifies whether a key is for BINDING or SIGNING
     */
    public static enum KeyType {

        /**
         * Indicates Key is for binding
         */
        BIND,
        /**
         * Indicates Key is for signing
         */
        SIGN
    }

    /**
     * <p>
     * Stores the hash of an asset tag to TPM NVRAM. Asset Tag hash must be 32 bytes in length</p>
     *
     * Asset tag is always stored to a unique and static index determined by
     * <code>{@link #getAssetTagIndex() }</code>.
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command
     * @param assetTagHash the hash of the asset tag to store in NVRAM.
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void setAssetTag(byte[] ownerAuth, byte[] assetTagHash) throws IOException, TpmException;

    /**
     * <p>
     * Read the asset tag (hash) from TPM NVRAM</p>
     * Asset tag is always read from a unique and static index determined by
     * <code>getAssetTagIndex()</code>.
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command
     * @return buffer containing the asset tag (hash) value
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract byte[] readAssetTag(byte[] ownerAuth) throws IOException, TpmException;

    /**
     * <p>
     * Returns the NVRAM index of the Asset Tag (hash)</p>
     *
     * @return integer specifying the NVRAM index of the Asset Tag
     */
    public abstract int getAssetTagIndex();

    /**
     * Enum indicating which PcrBanks a TPM supports
     */
    public enum PcrBank {

        /**
         * Indicates TPM supports SHA1 Platform Configuration Registers
         */
        SHA1("0x04"),
        /**
         * Indicates TPM supports SHA256 Platform Configuration Registers
         */
        SHA256("0x0B"),
        /**
         * Indicate TPM supports SHA384 Platform Configuration Registers
         */
        SHA384("0x0C"),
        /**
         * Indicates TPM supports SHA512 Platform Configuration Registers
         */
        SHA512("0x0D"),
        /**
         * Indicates TPM Supports SMX Platform Configuration Registers
         */
        SM3_256("0x12");

        private final String hex;

        PcrBank(String hex) {
            this.hex = hex;
        }

        /**
         *
         * @return
         */
        public String toHex() {
            return hex;
        }
    }

    /**
     * Enum specifying different types of Asymmetric Encryption algorithms and their Hex Identifiers.
     */
    public enum EncryptionAlgorithm {

        /**
         *
         */
        RSA("0x1"),

        /**
         *
         */
        ECC("0x23");

        private final String hex;

        EncryptionAlgorithm(String hex) {
            this.hex = hex;
        }

        /**
         *
         * @return
         */
        public String toHex() {
            return hex;
        }

    }

    /**
     * <p>
     * List the set of supported Crypto Algorithms for extending Platform
     * Configuration Registers (PCR)</p>
     *
     * This information is only useful for TPM 2.0 as 1.2 only supports SHA1
     *
     * @return a <code>Set</code> of <code>Algorithm</code> Enumerations
     * indicating which Algorithms the TPM supports.
     * @throws java.io.IOException
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract Set<PcrBank> getPcrBanks() throws IOException, TpmException;

    /**
     * Enum that specifies different attributes for an NVRAM index on the TPM.
     */
    public enum NVAttribute {

        /**
         * NV Index specific Authorization Password required to write
         */
        AUTHWRITE,

        /**
         * NV Index specific Authorization Password required to read
         */
        AUTHREAD,

        /**
         * Platform Authorization Password required to read
         */
        PPREAD,

        /**
         * Platform Authorization Password required to write
         */
        PPWRITE,

        /**
         * Owner Authorization Password required to read
         */
        OWNERREAD,

        /**
         * Owner Authorization Password required to write
         */
        OWNERWRITE,

        /**
         * Increment Global Lockout counter on fail
         */
        GLOBALLOCK,

        /**
         * Refer to TCG Specification
         */
        READ_STCLEAR,

        /**
         * Refer to TCG Specification
         */
        WRITE_STCLEAR,

        /**
         * Refer to TCG Specification
         */
        WRITEDEFINE,

        /**
         * Refer to TCG Specification
         */
        WRITEALL,

        /**
         * Refer to TCG Specification
         */
        POLICYREAD,

        /**
         * Refer to TCG Specification
         */
        PLATFORMCREATE
    }

    /**
     * <p>
     * Define an NVRAM index entry in the TPM for later usage</p>
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command.
     * @param indexPassword password blob to protect this NVRAM index
     * @param index the index offset to define the NVRAM entry
     * @param size the size of the NVRAM entry
     * @param attributes set of attributes of the NVRAM entry. Is a set of bit
     * fields that differs across TPM 1.2 and 2.0
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, Set<NVAttribute> attributes) throws IOException, TpmException;

    /**
     * <p>
     * Define an NVRAM entry in the TPM for later usage</p>
     *
     * @param ownerAuth the owner authorization blob required to issue the
     * command.
     * @param indexPassword password blob to protect this NVRAM index
     * @param index the index offset to define the NVRAM entry
     * @param size the size of the NVRAM entry
     * @param attributes set of attributes of the NVRAM entry. Is a set of bit
     * fields that differs across TPM 1.2 and 2.0
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public void nvDefine(byte[] ownerAuth, byte[] indexPassword, int index, int size, NVAttribute... attributes) throws IOException, TpmException {
        Set<NVAttribute> attrSet = EnumSet.noneOf(NVAttribute.class);
        attrSet.addAll(Arrays.asList(attributes));
        nvDefine(ownerAuth, indexPassword, index, size, attrSet);
    }

    /**
     * <p>
     * Release an NVRAM entry in the TPM</p>
     *
     * @param ownerAuth the owner authorization blob reuqired to issue the
     * command.
     * @param index the index offset of the NVRAM entry to release
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void nvRelease(byte[] ownerAuth, int index) throws IOException, TpmException;

    /**
     * <p>
     * Read data from an NVRAM entry</p>
     *
     * On TPM 2.0, an NVRAM index can be accessed with that index's password, or
     * via elevated authorization as OWNER or PLATFORM
     *
     * @param authPassword password to read from the NVRAM index.
     * @param index the index to read from
     * @param size the number of bytes to read
     * @param offset the offset to read from
     * @return a buffer containing the bytes read. The number of returned bytes
     * may be different from the size requested
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract byte[] nvRead(byte[] authPassword, int index, int size, int offset) throws IOException, TpmException;

    /**
     * <p>
     * Read data from an NVRAM entry</p>
     *
     * On TPM 2.0, an NVRAM index can be accessed with that index's password, or
     * via elevated authorization as OWNER or PLATFORM
     *
     * @param authPassword password to read from the NVRAM index.
     * @param index the index to read from
     * @param size the number of bytes to read
     * @return a buffer containing the bytes read. The number of returned bytes
     * may be different from the size requested
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public byte[] nvRead(byte[] authPassword, int index, int size) throws IOException, TpmException {
        return nvRead(authPassword, index, size, 0);
    }

    /**
     * <p>
     * Write data to an NVRAM entry</p>
     *
     * On TPM 2.0, an NVRAM index can be accessed with that index's password, or
     * via elevated authorization as OWNER or PLATFORM
     *
     * @param authPassword password to read from the NVRAM index.
     * @param index the index to read from
     * @param data the data which to write to the NVRAM index. Must not exceed
     * the size defined by the NVRAM index.
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract void nvWrite(byte[] authPassword, int index, byte[] data) throws IOException, TpmException;

    /**
     * <p>
     * Determine if an NVRAM index is already defined</p>
     *
     * @param index the index to check
     * @return <code>true</code> if exists, <code>false</code> otherwise
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract boolean nvIndexExists(int index) throws IOException, TpmException;

    /**
     * Enum specifying each of the 24 PCRs on a TPM.
     */
    public static enum Pcr {

        /**
         *
         */
        PCR0(0),

        /**
         *
         */
        PCR1(1),

        /**
         *
         */
        PCR2(2),

        /**
         *
         */
        PCR3(3),

        /**
         *
         */
        PCR4(4),

        /**
         *
         */
        PCR5(5),

        /**
         *
         */
        PCR6(6),

        /**
         *
         */
        PCR7(7),

        /**
         *
         */
        PCR8(8),

        /**
         *
         */
        PCR9(9),

        /**
         *
         */
        PCR10(10),

        /**
         *
         */
        PCR11(11),

        /**
         *
         */
        PCR12(12),

        /**
         *
         */
        PCR13(13),

        /**
         *
         */
        PCR14(14),

        /**
         *
         */
        PCR15(15),

        /**
         *
         */
        PCR16(16),

        /**
         *
         */
        PCR17(17),

        /**
         *
         */
        PCR18(18),

        /**
         *
         */
        PCR19(19),

        /**
         *
         */
        PCR20(20),

        /**
         *
         */
        PCR21(21),

        /**
         *
         */
        PCR22(22),

        /**
         *
         */
        PCR23(23);

        private final int pcr;

        Pcr(int pcr) {
            this.pcr = pcr;
        }

        /**
         *
         * @param pcr
         * @return
         */
        public static Pcr fromInt(int pcr) {
            return Pcr.valueOf("PCR" + pcr);
        }
        
        /**
         *
         * @return
         */
        public int toInt() {
            return pcr;
        }
    }

    /**
     * <p>
     * Get a Quote from the TPM</p>
     *
     * A quote contains a signed list of measurements (PCRs, logs, etc.) from
     * the TPM. The Quote is signed using the AIK, which serves to prove the Quote
     * is legitimate and came from a TPM.
     *
     * @param pcrBanks the set indicating from which pcr algorithm banks to
     * quote from
     * @param pcrs the set indicating which pcrs to quote from each specified
     * bank specified in <code>pcrBanks</code>
     * @param aikBlob the AIK key data required for signing the quote
     * @param aikAuth
     * @param nonce nonce for protecting against replay attacks
     * @return a TpmQuote structure, containing the signed list of measurements.
     * @throws java.io.IOException if there was an error executing the command
     * line Tpm Tools
     * @throws com.intel.mtwilson.core.tpm.Tpm.TpmException
     */
    public abstract TpmQuote getQuote(Set<PcrBank> pcrBanks, Set<Pcr> pcrs, byte[] aikBlob, byte[] aikAuth, byte[] nonce) throws IOException, TpmException;

    /**
     *
     */
    public final static String V20 = "2.0";

    /**
     *
     */
    public final static String V12 = "1.2";

    /**
     * <p>
     * Get configured TPM Version</p>
     *
     * @return a String indicating the configured TPM's version number.
     */
    public abstract String getTpmVersion();
}
