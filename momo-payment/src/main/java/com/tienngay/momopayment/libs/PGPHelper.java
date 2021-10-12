package com.tienngay.momopayment.libs;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 *
 * @author vu
 */
public class PGPHelper {

    private static final int BUFFER_SIZE = 1 << 16; // should always be power of 2(one shifted bitwise 16 places)
    private static final Map<String, PGPHelper> MAP = new ConcurrentHashMap<>();
    private static final String DEFAULT_PARTNER_CODE = "ONE_PARTNER";

    private final BcKeyFingerprintCalculator bcKeyFingerprintCalculator;
    private final PBESecretKeyDecryptor secretKeyDecryptor;
    private PGPPublicKeyRingCollection pgpPub;
    private PGPSecretKeyRingCollection pgpSec;
    private PGPSecretKey secretKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private PGPHelper(String password) {
        this.bcKeyFingerprintCalculator = new BcKeyFingerprintCalculator();
        this.secretKeyDecryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider())
                .build(password.toCharArray());
    }

    private PGPHelper(List<String> publicKeyPaths, String privateKeyPath, String password) throws FileNotFoundException, IOException, PGPException, NoSuchProviderException, CryptoException {
        this(password);
        for (String item : publicKeyPaths) {
            try (FileInputStream pubStream = new FileInputStream(new File(item))) {

                if (pgpPub == null) {
                    pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(pubStream), bcKeyFingerprintCalculator);
                }
                else {
                    PGPPublicKeyRingCollection collection = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(pubStream), bcKeyFingerprintCalculator);
                    for (Iterator<PGPPublicKeyRing> iterator = collection.getKeyRings(); iterator.hasNext();) {
                        pgpPub = PGPPublicKeyRingCollection.addPublicKeyRing(pgpPub, iterator.next());
                    }
                }
            }
        }
        try (FileInputStream priStream = new FileInputStream(new File(privateKeyPath))) {
            readKey(priStream, password);
        }

    }

    private PGPHelper(byte[] publicKey, byte[] privateKey, String password) throws CryptoException, IOException, PGPException {
        this(password);
        InputStream pubStream = new ByteArrayInputStream(publicKey);
        InputStream priStream = new ByteArrayInputStream(privateKey);
        pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(pubStream), bcKeyFingerprintCalculator);
        readKey(priStream, password);
    }

    private PGPPublicKey readPublicKey(PGPPublicKeyRingCollection pkCol) throws IOException, PGPException {
        PGPPublicKeyRing pkRing;
        Iterator it = pkCol.getKeyRings();
        while (it.hasNext()) {
            pkRing = (PGPPublicKeyRing) it.next();
            Iterator pkIt = pkRing.getPublicKeys();
            while (pkIt.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) pkIt.next();
                if (key.isEncryptionKey()) {
                    return key;

                }
            }
        }
        throw new PGPException("Invalid public Key");
    }

    private void readKey(InputStream priStream, String password) throws CryptoException {
        try {
            this.pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(priStream), bcKeyFingerprintCalculator);
            this.secretKey = readSecretKey(pgpSec);
        }
        catch (IOException | PGPException | NoSuchProviderException ex) {
            throw new CryptoException(ex.getMessage(), ex);
        }
    }

    public static void init(String privateKeyPath, String publicKeyPath, String password) throws Exception {
        init(DEFAULT_PARTNER_CODE, privateKeyPath, publicKeyPath, password);
    }

    public static void init(List<String> publicKeyPaths, String privateKeyPath, String password) throws Exception {
        MAP.put(DEFAULT_PARTNER_CODE, new PGPHelper(publicKeyPaths, privateKeyPath, password));
    }

    public static void init(String partnerCode, String privateKeyPath, String publicKeyPath, String password) throws Exception {
        MAP.put(partnerCode, new PGPHelper(Arrays.asList(publicKeyPath), privateKeyPath, password));
    }

    public static void init(byte[] privateKey, byte[] publicKey, String password) throws Exception {
        MAP.put(DEFAULT_PARTNER_CODE, new PGPHelper(publicKey, privateKey, password));
    }

    public static void init(String partnerCode, byte[] privateKey, byte[] publicKey, String password) throws Exception {
        MAP.put(partnerCode, new PGPHelper(publicKey, privateKey, password));
    }

    public static void reload() {
        MAP.clear();
    }

    public static PGPHelper getInstance() {
        return MAP.get(DEFAULT_PARTNER_CODE);
    }

    public static PGPHelper getInstance(String partnerCode) {
        return MAP.get(partnerCode);
    }

    public void decryptAndVerifySignature(byte[] encryptData, OutputStream decryptData) throws CryptoException, SignatureException {

        InputStream clear = null;
        try (InputStream bais = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptData))) {

            PGPObjectFactory objectFactory = new PGPObjectFactory(bais, bcKeyFingerprintCalculator);
            Object message;
            PGPPrivateKey privateKey = null;
            PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
            PGPOnePassSignature calculatedSignature = null;
            PGPSignature verifySignature = null;

            while ((message = objectFactory.nextObject()) != null) {
                if (message instanceof PGPCompressedData ) {
                    PGPCompressedData cData = (PGPCompressedData) message;
                    objectFactory = new PGPObjectFactory(cData.getDataStream(), bcKeyFingerprintCalculator);

                }
                else if (message instanceof PGPEncryptedDataList) {
                    PGPEncryptedDataList dataList = (PGPEncryptedDataList) message;
                    Iterator it = dataList.getEncryptedDataObjects();
                    while (privateKey == null && it.hasNext()) {
                        publicKeyEncryptedData = (PGPPublicKeyEncryptedData) it.next();
                        privateKey = findSecretKey(publicKeyEncryptedData.getKeyID());
                    }
                    if (publicKeyEncryptedData == null || privateKey == null) {
                        throw new PGPException("secret key for message not found.");
                    }
                    clear = publicKeyEncryptedData.getDataStream(buildFactory(privateKey));
                    objectFactory = new PGPObjectFactory(clear, bcKeyFingerprintCalculator);
                }
                else if (message instanceof PGPOnePassSignatureList) {
                    calculatedSignature = handlePgpOnePassSignature((PGPOnePassSignatureList) message, pgpPub);
                    if (calculatedSignature == null) {
                        throw new SignatureException("Signature does not match any pubic keys");
                    }
                }
                else if (message instanceof PGPLiteralData) {
                    PGPLiteralData ld = (PGPLiteralData) message;
                    InputStream literalDataStream = ld.getInputStream();
                    if (calculatedSignature == null) {
                        throw new SignatureException("Signature does not match any pubic keys");
                    }
                    int ch;
                    while ((ch = literalDataStream.read()) >= 0) {
                        calculatedSignature.update((byte) ch);
                        decryptData.write((byte) ch);
                    }
                }
                else if (message instanceof PGPSignatureList) {
                    verifySignature = handleSignatureList((PGPSignatureList) message, calculatedSignature);
                }
            }
            if (calculatedSignature == null) {
                throw new SignatureException("Signature does not match any pubic keys");
            }

            if (!calculatedSignature.verify(verifySignature)) {
                throw new SignatureException("signature verification failed");
            }
            if (publicKeyEncryptedData == null) {
                throw new PGPException("secret key for message not found.");
            }

            if (publicKeyEncryptedData.isIntegrityProtected()) {
                if (!publicKeyEncryptedData.verify()) {
                    throw new PGPException("message failed integrity check");
                }
            }
        }
        catch (IOException | IllegalArgumentException | NoSuchProviderException | PGPException ex) {
            throw new CryptoException(ex.getMessage(), ex);
        }
        finally {
            try {
                if (clear != null) {
                    clear.close();
                }
            } catch (Exception var2) {
            }
        }

    }

    public String decrypt(byte[] encryptData) throws Exception {
        InputStream bais = new ByteArrayInputStream(encryptData);
        bais = PGPUtil.getDecoderStream(bais);
        PGPObjectFactory pgpF = new PGPObjectFactory(bais, bcKeyFingerprintCalculator);
        PGPEncryptedDataList enc;
        Object o = pgpF.nextObject();
        if (o instanceof PGPEncryptedDataList) {
            enc = (PGPEncryptedDataList) o;
        }
        else {
            enc = (PGPEncryptedDataList) pgpF.nextObject();
        }
        Iterator it = enc.getEncryptedDataObjects();
        PGPPrivateKey privateKey = null;
        PGPPublicKeyEncryptedData encryptedData = null;
        while (privateKey == null && it.hasNext()) {
            encryptedData = (PGPPublicKeyEncryptedData) it.next();
            privateKey = findSecretKey(encryptedData.getKeyID());
        }
        if (privateKey == null || encryptedData == null) {
            throw new IllegalArgumentException("secret key for message not found.");
        }
        InputStream clear = encryptedData.getDataStream(buildFactory(privateKey));
        PGPObjectFactory plainFact = new PGPObjectFactory(clear, bcKeyFingerprintCalculator);
        Object message = plainFact.nextObject();
        if (message instanceof PGPCompressedData) {
            PGPCompressedData cData = (PGPCompressedData) message;
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), bcKeyFingerprintCalculator);
            message = pgpFact.nextObject();
        }
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if (message instanceof PGPLiteralData) {
            PGPLiteralData ld = (PGPLiteralData) message;
            InputStream unc = ld.getInputStream();
            int ch;
            while ((ch = unc.read()) >= 0) {
                baos.write(ch);
            }
        }
        else if (message instanceof PGPOnePassSignatureList) {
            throw new PGPException("encrypted message contains a signed message - not literal data.");
        }
        else {
            throw new PGPException("message is not a simple encrypted file - type unknown.");
        }
        return new String(baos.toByteArray());
    }

    public byte[] encrypt(byte[] data) throws IOException, NoSuchProviderException, PGPException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        encrypt(data, baos);
        return baos.toByteArray();

    }

    private PGPEncryptedDataGenerator createEncryptDataGenerator() throws NoSuchProviderException, PGPException {
        PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new BcPGPDataEncryptorBuilder(PGPEncryptedDataGenerator.CAST5));
        PGPPublicKeyRing pkRing;
        Iterator it = pgpPub.getKeyRings();
        while (it.hasNext()) {
            pkRing = (PGPPublicKeyRing) it.next();
            Iterator pkIt = pkRing.getPublicKeys();
            while (pkIt.hasNext()) {
                PGPPublicKey key = (PGPPublicKey) pkIt.next();
                if (key.isEncryptionKey()) {
                    encryptedDataGenerator.addMethod(new BcPublicKeyKeyEncryptionMethodGenerator(key));
                }
            }
        }
        return encryptedDataGenerator;
    }

    private PGPSignatureGenerator createSignatureGenerator() throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(secretKeyDecryptor);
        PGPPublicKey internalPublicKey = secretKey.getPublicKey();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(internalPublicKey.getAlgorithm(), HashAlgorithmTags.SHA1));
        generator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        Iterator i = internalPublicKey.getUserIDs();
        if (i.hasNext()) {
            String userId = (String) i.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            generator.setHashedSubpackets(spGen.generate());
        }
        return generator;
    }

    public void encrypt(byte[] data, OutputStream out) throws IOException, NoSuchProviderException, PGPException {
        out = new DataOutputStream(out);
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = null;
        try {
            comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
            try (OutputStream open = comData.open(bOut)) {
                writeToLiteralData(open, PGPLiteralData.BINARY, data);
            }
        }
        finally {
            if (comData != null) {
                comData.close();
            }
        }
        PGPEncryptedDataGenerator cPk = createEncryptDataGenerator();
        byte[] bytes = bOut.toByteArray();
        try (OutputStream cOut = cPk.open(out, bytes.length)) {
            cOut.write(bytes);
        }

    }

    private PGPPrivateKey findSecretKey(long keyID) throws IOException, PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        return pgpSecKey.extractPrivateKey(secretKeyDecryptor);
    }

    private static void writeToLiteralData(OutputStream out, char fileType, byte[] data) throws IOException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        try (OutputStream pOut = lData.open(out, fileType, "temp", data.length, new Date())) {
            pOut.write(data);
        }
    }

    private static void writeToLiteralData(PGPSignatureGenerator signatureGenerator, OutputStream out, byte[] data) throws IOException, SignatureException {
        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
        ByteArrayInputStream contentStream = new ByteArrayInputStream(data);
        try (OutputStream literalOut = lData.open(out, PGPLiteralData.BINARY, "pgp", new Date(), new byte[BUFFER_SIZE])) {
            byte[] buf = new byte[BUFFER_SIZE];
            int len;
            while ((len = contentStream.read(buf, 0, buf.length)) > 0) {
                literalOut.write(buf, 0, len);
                signatureGenerator.update(buf, 0, len);
            }
        }
        finally {
            lData.close();
        }
    }

    private PGPSecretKey readSecretKey(PGPSecretKeyRingCollection collection) throws IOException, PGPException, NoSuchProviderException {
        Iterator it = collection.getKeyRings();
        PGPSecretKeyRing pbr;
        while (it.hasNext()) {
            Object readData = it.next();
            if (readData instanceof PGPSecretKeyRing) {
                pbr = (PGPSecretKeyRing) readData;
                return pbr.getSecretKey();
            }
        }
        throw new IllegalArgumentException("secret key for message not found.");
    }

    private static PGPOnePassSignature handlePgpOnePassSignature(
            PGPOnePassSignatureList signatureList,
            PGPPublicKeyRingCollection publicKeyRingCollection) throws PGPException {
        PGPOnePassSignature calculatedSignature = null;
        for (int i = 0; i < signatureList.size(); i++) {
            PGPOnePassSignature currSignature = signatureList.get(i);
            PGPPublicKey publicKey
                    = publicKeyRingCollection.contains(currSignature.getKeyID())
                    ? publicKeyRingCollection.getPublicKey(currSignature.getKeyID()) : null;

            if (publicKey != null) {
                calculatedSignature = currSignature;
                calculatedSignature.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
                break;
            }
        }
        return calculatedSignature;
    }

    private static PGPSignature handleSignatureList(PGPSignatureList signatureList,
            PGPOnePassSignature calculatedSignature)
            throws PGPException {

        for (int i = 0; i < signatureList.size(); i++) {
            PGPSignature signature = signatureList.get(i);

            if (signature.getKeyID() == calculatedSignature.getKeyID()) {
                return signature;
            }
        }
        return null;
    }

    private PublicKeyDataDecryptorFactory buildFactory(PGPPrivateKey privateKey) {
        return new BcPublicKeyDataDecryptorFactory(privateKey);
    }

    /*
        prefer to HashAlgorithmTags class
     */
    private PGPSignatureGenerator createSignatureGenerator(int algorithmTags) throws NoSuchProviderException, NoSuchAlgorithmException, PGPException {
        PGPPrivateKey pgpPrivKey = secretKey.extractPrivateKey(secretKeyDecryptor);
        PGPPublicKey internalPublicKey = secretKey.getPublicKey();
        PGPSignatureGenerator generator = new PGPSignatureGenerator(new BcPGPContentSignerBuilder(internalPublicKey.getAlgorithm(), algorithmTags));
        generator.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);
        Iterator i = internalPublicKey.getUserIDs();
        if (i.hasNext()) {
            String userId = (String) i.next();
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, userId);
            generator.setHashedSubpackets(spGen.generate());
        }
        return generator;
    }

    public void encryptAndSign(byte[] data, OutputStream out) throws CryptoException {
        encryptAndSign(data, out, HashAlgorithmTags.SHA1);
    }


    /*
     *  prefer to HashAlgorithmTags class
     */
    public void encryptAndSign(byte[] data, OutputStream out, int hashAlgorithmTags) throws CryptoException {
        try {
            out = new ArmoredOutputStream(out);
            PGPEncryptedDataGenerator encryptedDataGenerator = createEncryptDataGenerator();
            PGPCompressedDataGenerator comData = null;
            try (OutputStream encryptedOut = encryptedDataGenerator.open(out, new byte[BUFFER_SIZE])) {
                comData = new PGPCompressedDataGenerator(PGPCompressedDataGenerator.ZIP);
                try (OutputStream compressedOut = comData.open(encryptedOut)) {
                    PGPSignatureGenerator pgpsg = createSignatureGenerator(hashAlgorithmTags);
                    pgpsg.generateOnePassVersion(false).encode(compressedOut);
                    writeToLiteralData(pgpsg, compressedOut, data);
                    pgpsg.generate().encode(compressedOut);
                }
            }

            finally {
                if (comData != null) {
                    try {
                        comData.close();
                    }
                    catch (IOException ex) {
                        //NO OP
                    }
                }
                try {
                    encryptedDataGenerator.close();
                }
                catch (IOException ex) {
                    //NO OP
                }
                try {
                    if (out != null) {
                        out.close();
                    }
                } catch (Exception var2) {
                }
            }
        }
        catch (IOException | NoSuchAlgorithmException | NoSuchProviderException | PGPException | SignatureException ex) {
            throw new CryptoException(ex.getMessage(), ex);
        }
    }
}
