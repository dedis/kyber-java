package ch.epfl.dedis.calypso;

import ch.epfl.dedis.integration.TestServerController;
import ch.epfl.dedis.integration.TestServerInit;
import ch.epfl.dedis.lib.Hex;
import ch.epfl.dedis.byzcoin.ByzCoinRPC;
import ch.epfl.dedis.byzcoin.Proof;
import ch.epfl.dedis.byzcoin.contracts.DarcInstance;
import ch.epfl.dedis.lib.crypto.KeyPair;
import ch.epfl.dedis.lib.crypto.Point;
import ch.epfl.dedis.lib.darc.Darc;
import ch.epfl.dedis.lib.darc.Rules;
import ch.epfl.dedis.lib.darc.Signer;
import ch.epfl.dedis.lib.darc.SignerEd25519;
import ch.epfl.dedis.lib.exception.CothorityCommunicationException;
import ch.epfl.dedis.lib.exception.CothorityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Duration;
import java.util.Arrays;

import static java.time.temporal.ChronoUnit.MILLIS;
import static org.junit.jupiter.api.Assertions.*;

class CalypsoTest {
    static CalypsoRPC calypso;

    static Signer admin;
    static Darc genesisDarc;
    static Signer publisher;
    static Darc publisherDarc;
    static Signer reader;
    static Darc readerDarc;

    static Document doc;
    static String docData;
    static String extraData;

    private final static Logger logger = LoggerFactory.getLogger(WriteInstanceTest.class);
    private TestServerController testInstanceController;

    @BeforeEach
    void initAll() throws Exception {
        admin = new SignerEd25519();
        publisher = new SignerEd25519();
        reader = new SignerEd25519();
        testInstanceController = TestServerInit.getInstance();
        genesisDarc = ByzCoinRPC.makeGenesisDarc(admin, testInstanceController.getRoster());

        try {
            logger.info("Admin darc: " + genesisDarc.getBaseId().toString());
            calypso = new CalypsoRPC(testInstanceController.getRoster(), genesisDarc, Duration.of(500, MILLIS));
            if (!calypso.checkLiveness()) {
                throw new CothorityCommunicationException("liveness check failed");
            }
        } catch (CothorityCommunicationException e) {
            logger.info("Error is: " + e.toString());
            logger.error("Couldn't start skipchain - perhaps you need to run the following commands:");
            logger.error("cd $(go env GOPATH)/src/github.com/dedis/onchain-secrets/conode");
            logger.error("./run_conode.sh local 4 2");
            fail("Couldn't start ocs!");
        }

        readerDarc = new Darc(Arrays.asList(publisher.getIdentity()), Arrays.asList(reader.getIdentity()), "readerDarc".getBytes());
        calypso.getGenesisDarcInstance().spawnDarcAndWait(readerDarc, admin, 10);

        // Spawn a new darc with the calypso read/write rules for a new signer.
        publisherDarc = new Darc(Arrays.asList(publisher.getIdentity()), Arrays.asList(publisher.getIdentity()), "calypso darc".getBytes());
        publisherDarc.setRule("spawn:calypsoWrite", publisher.getIdentity().toString().getBytes());
        publisherDarc.addIdentity("spawn:calypsoRead", publisher.getIdentity(), Rules.OR);
        publisherDarc.addIdentity("spawn:calypsoRead", readerDarc.getIdentity(), Rules.OR);
        calypso.getGenesisDarcInstance().spawnDarcAndWait(publisherDarc, admin, 10);

        docData = "https://dedis.ch/secret_document.osd";
        extraData = "created on Monday";
        doc = new Document(docData.getBytes(), 16, extraData.getBytes(), publisherDarc.getBaseId());
    }

    // This test creates a full cycle with regard to storing and retrieving a document from Calypso.
    @Test
    void fullCycleDocument() throws CothorityException{
        // The document is stored in 'doc' and not encrypted yet.
        Document doc = new Document(docData.getBytes(), 16, extraData.getBytes(), publisherDarc.getBaseId());

        // First, create an encrypted version of the document. Alternatively one could create
        // an own WriteData from scratch and hand it an already encrypted document.
        // wd holds the encrypted data and the encrypted symmetric key.
        WriteData wd = doc.getWriteData(calypso.getLTS());

        // Now ask Calypso to store it in Byzcoin by creating a WriteInstance.
        WriteInstance wi = new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher), wd);

        // The document is now stored on ByzCoin with the data encrypted by the symmetric key (keyMaterial) and the
        // symmetric key encrypted by the Long Term Secret.

        // To read it, first proof that we have the right to read by creating a ReadInstance:
        ReadInstance ri = new ReadInstance(calypso, wi, Arrays.asList(reader));
        // If successful (no exceptions), Byzcoin holds a proof that we are allowed to read the document.

        // Get the re-encrypted symmetric key from Calypso:
        DecryptKeyReply dkr = calypso.tryDecrypt(calypso.getProof(wi.getInstance().getId()), calypso.getProof(ri.getInstance().getId()));
        // And derive the symmetric key, using the user's private key to decrypt it:
        byte[] keyMaterial = dkr.getKeyMaterial(reader.getPrivate());

        // Finally get the document back:
        Document doc2 = Document.fromWriteInstance(wi, keyMaterial);

        // And check it's the same.
        assertTrue(doc.equals(doc2));
    }

    @Test
    void fullCycleDocumentShort() throws CothorityException{
        // Same as above, but shortest possible calls.
        // Create WriteInstance.
        WriteInstance wi = new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher), doc.getWriteData(calypso.getLTS()));

        // Get ReadInstance with 'reader'
        ReadInstance ri = new ReadInstance(calypso, wi, Arrays.asList(reader));

        // Create new Document from wi and ri
        Document doc2 = Document.fromCalypso(calypso, ri.getInstance().getId(), reader.getPrivate());

        // Should be the same
        assertTrue(doc.equals(doc2));
    }

    @Test
    void ephemeralKey() throws CothorityException{
        KeyPair ephemeral = new KeyPair();

        // Same as above, but shortest possible calls.
        // Create WriteInstance.
        WriteInstance wi = new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher), doc.getWriteData(calypso.getLTS()));

        // Get ReadInstance with 'reader'
        ReadInstance ri = new ReadInstance(calypso, wi, Arrays.asList(reader), ephemeral.point);

        KeyPair wrong = new KeyPair();
        // Create new Document from wi and ri using the wrong ephemeral key
        assertThrows(CothorityException.class, ()->
                Document.fromCalypso(calypso, ri.getInstance().getId(), wrong.scalar));

        // Create new Document from wi and ri using the correct ephemeral key
        Document doc2 = Document.fromCalypso(calypso, ri.getInstance().getId(), ephemeral.scalar);

        // Should be the same
        assertTrue(doc.equals(doc2));
    }

    @Test
    void testDecryptKey() throws Exception {
        Document doc1 = new Document("this is secret 1".getBytes(), 16, null, publisherDarc.getBaseId());
        WriteInstance w1 = new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher),
                doc1.getWriteData(calypso.getLTS()));
        ReadInstance r1 = new ReadInstance(calypso, WriteInstance.fromCalypso(calypso, w1.getInstance().getId()), Arrays.asList(publisher));
        Proof pw1 = calypso.getProof(w1.getInstance().getId());
        Proof pr1 = calypso.getProof(r1.getInstance().getId());

        Document doc2 = new Document("this is secret 2".getBytes(), 16, null, publisherDarc.getBaseId());
        WriteInstance w2 = new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher),
                doc2.getWriteData(calypso.getLTS()));
        ReadInstance r2 = new ReadInstance(calypso, WriteInstance.fromCalypso(calypso, w2.getInstance().getId()), Arrays.asList(publisher));
        Proof pw2 = calypso.getProof(w2.getInstance().getId());
        Proof pr2 = calypso.getProof(r2.getInstance().getId());

        try {
            calypso.tryDecrypt(pw2, pr1);
        } catch (CothorityCommunicationException e) {
            assertTrue(e.getMessage().contains("read doesn't point to passed write"));
        }

        try {
            calypso.tryDecrypt(pw1, pr2);
        } catch (CothorityCommunicationException e) {
            assertTrue(e.getMessage().contains("read doesn't point to passed write"));
        }

        logger.info("trying decrypt 1, pk: " + publisher.getPublic().toString());
        DecryptKeyReply dkr1 = calypso.tryDecrypt(pw1, pr1);
        byte[] km1 = dkr1.getKeyMaterial(publisher.getPrivate());
        assertTrue(Arrays.equals(doc1.getData(), Encryption.decryptData(w1.getWrite().getDataEnc(), km1)));

        logger.info("trying decrypt 2, pk: " + publisher.getPublic().toString());
        DecryptKeyReply dkr2 = calypso.tryDecrypt(pw2, pr2);
        byte[] km2 = dkr2.getKeyMaterial(publisher.getPrivate());
        assertTrue(Arrays.equals(doc2.getData(), Encryption.decryptData(w2.getWrite().getDataEnc(), km2)));
    }

    @Test
    void getSharedPublicKey() throws Exception {
        assertThrows(CothorityCommunicationException.class, ()-> calypso.getSharedPublicKey(new LTSId(new byte[32])));
        Point shared = calypso.getSharedPublicKey(calypso.getLTSId());
        assertNotNull(shared);
        assertTrue(calypso.getLTSX().equals(shared));
    }

    @Test
    void getWrite() throws Exception {
        WriteInstance writeInstance = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);
        WriteInstance writeInstance2 = WriteInstance.fromCalypso(calypso, writeInstance.getInstance().getId());
        assertArrayEquals(doc.getWriteData(calypso.getLTS()).getDataEnc(), writeInstance2.getWrite().getDataEnc());
        assertArrayEquals(doc.getExtraData(), writeInstance2.getWrite().getExtraData());
    }

    ReadInstance readInstance;

    @Test
    void readRequest() throws Exception {
        WriteInstance writeInstance = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);
        Signer reader2 = new SignerEd25519();
        try {
            readInstance = writeInstance.spawnCalypsoRead(calypso, Arrays.asList(reader2));
            fail("a wrong read-signature should not pass");
        } catch (CothorityCommunicationException e) {
            logger.info("correctly failed with wrong signature");
        }
        logger.debug("publisherdarc.ic = " + readerDarc.getBaseId().toString());
        logger.debug("publisherdarc.proto = " + readerDarc.toProto().toString());
        readInstance = writeInstance.spawnCalypsoRead(calypso, Arrays.asList(reader));
        assertNotNull(readInstance);
    }

    @Test
    void readDocument() throws Exception {
        readRequest();
        byte[] keyMaterial = readInstance.decryptKeyMaterial(reader.getPrivate());
        assertNotNull(keyMaterial);
        byte[] data = Encryption.decryptData(doc.getWriteData(calypso.getLTS()).getDataEnc(), keyMaterial);
        assertArrayEquals(docData.getBytes(), data);
    }

    @Test
    void checFailingkWriteAuthorization() throws CothorityException {
        Signer publisher2 = new SignerEd25519();
        try {
            doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher2);
            fail("accepted unknown writer");
        } catch (CothorityCommunicationException e) {
            logger.info("correctly refused unknown writer");
        }
    }

    @Test
    void createDarcForTheSameUserInDifferentSkipchain() throws Exception {
        Darc userDarc = new Darc(Arrays.asList(new SignerEd25519(Hex.parseHexBinary("AEE42B6A924BDFBB6DAEF8B252258D2FDF70AFD31852368AF55549E1DF8FC80D")).getIdentity()), null, null);
        calypso.getGenesisDarcInstance().spawnDarcAndWait(userDarc, admin, 10);

        CalypsoRPC calypso2 = new CalypsoRPC(testInstanceController.getRoster(), genesisDarc,
                Duration.ofMillis(500));
        try {
            calypso2.getGenesisDarcInstance().spawnDarcAndWait(userDarc, admin, 10);
            logger.info("correctly saved same darc in another ByzCoin");
        } catch (CothorityCommunicationException e) {
            fail("incorrectly refused to save again");
        }
    }

    @Test
    void writeRequestWithFailedNode() throws Exception {
        WriteData wr = doc.getWriteData(calypso.getLTS());

        // kill the conode co4 and try to make a request
        testInstanceController.killConode(4);
        assertEquals(3, testInstanceController.countRunningConodes());

        try {
            new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher), wr);
            logger.info("correctly created write instance");
        } catch (CothorityException e){
            fail("should not fail to create write instance with one missing node");
        } finally {
            // bring the conode backup for future tests and make sure we have 4 conodes running
            testInstanceController.startConode(4);
            assertEquals(4, testInstanceController.countRunningConodes());
        }

        // Try to write again with 4 nodes
        new WriteInstance(calypso, publisherDarc.getBaseId(), Arrays.asList(publisher), wr);
    }

    @Test
    void giveReadAccessToDocument() throws CothorityException {
        WriteInstance wi = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);

        Signer reader2 = new SignerEd25519();
        try{
            new ReadInstance(calypso, wi, Arrays.asList(reader2));
            fail("read-request of unauthorized reader should fail");
        } catch (CothorityException e){
            logger.info("correct refusal of invalid read-request");
        }

        DarcInstance rd = DarcInstance.fromByzCoin(calypso, readerDarc);
        readerDarc.addIdentity(Darc.RuleSignature, reader2.getIdentity(), Rules.OR);
        rd.evolveDarcAndWait(readerDarc, publisher, 10);

        ReadInstance ri = new ReadInstance(calypso, wi, Arrays.asList(reader2));
        byte[] keyMaterial = ri.decryptKeyMaterial(reader2.getPrivate());
        assertArrayEquals(doc.getKeyMaterial(), keyMaterial);
    }

    @Test
    void getDocument() throws CothorityException {
        WriteInstance wi = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);
        ReadInstance ri = wi.spawnCalypsoRead(calypso, Arrays.asList(reader));
        Document doc2 = Document.fromCalypso(calypso, ri.getInstance().getId(), reader.getPrivate());
        assertTrue(doc.equals(doc2));

        // Add another reader
        Signer reader2 = new SignerEd25519();
        DarcInstance di = DarcInstance.fromByzCoin(calypso, readerDarc);
        readerDarc.addIdentity(Darc.RuleSignature, reader2.getIdentity(), Rules.OR);
        di.evolveDarcAndWait(readerDarc, publisher, 10);

        ReadInstance ri2 = wi.spawnCalypsoRead(calypso, Arrays.asList(reader2));
        Document doc3 = Document.fromCalypso(calypso, ri2.getInstance().getId(), reader2.getPrivate());
        assertTrue(doc.equals(doc3));
    }

    @Test
    void getDocumentWithFailedNode() throws CothorityException, IOException, InterruptedException {
        WriteInstance wr = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);

        DarcInstance di = DarcInstance.fromByzCoin(calypso, readerDarc);
        Signer reader2 = new SignerEd25519();
        readerDarc.addIdentity(Darc.RuleSignature, reader2.getIdentity(), Rules.OR);
        di.evolveDarcAndWait(readerDarc, publisher, 10);
        ReadInstance ri = new ReadInstance(calypso, wr, Arrays.asList(reader2));
        Document doc2 = Document.fromCalypso(calypso, ri.getInstance().getId(), reader2.getPrivate());
        assertTrue(doc.equals(doc2));

        // kill the conode co3 and try to make a request
        testInstanceController.killConode(4);
        assertEquals(3, testInstanceController.countRunningConodes());

        ReadInstance ri2 = new ReadInstance(calypso, wr, Arrays.asList(reader2));
        Document doc3 = Document.fromCalypso(calypso, ri2.getInstance().getId(), reader2.getPrivate());
        assertTrue(doc.equals(doc3));

        // restart the conode and try the same
        testInstanceController.startConode(4);
        assertEquals(4, testInstanceController.countRunningConodes());

        ReadInstance ri3 = new ReadInstance(calypso, wr, Arrays.asList(reader2));
        Document doc4 = Document.fromCalypso(calypso, ri3.getInstance().getId(), reader2.getPrivate());
        assertTrue(doc.equals(doc4));
    }

    @Test
    void multiLTS() throws CothorityException{
        CalypsoRPC calypso2 = new CalypsoRPC(calypso);
        assertFalse(calypso2.getLTSId().equals(calypso.getLTS().getLtsId()));
    }

    @Test
    void reConnect() throws CothorityException, InterruptedException, IOException {
        WriteInstance wr = doc.spawnWrite(calypso, publisherDarc.getBaseId(), publisher);

        for (int i=0; i<3; i++){
            testInstanceController.killConode(i);
        }
        for (int i=0; i<3; i++){
            testInstanceController.startConode(i);
        }

        // Dropping connection by re-creating an calypso. The following elements are needed:
        // - roster
        // - byzcoin-ic
        // - LTS-id
        // - WriteData-id
        // - reader-signer
        // - publisher-signer
        CalypsoRPC calypso2 = CalypsoRPC.fromCalypso(calypso.getRoster(), calypso.getGenesisBlock().getSkipchainId(),
                calypso.getLTSId());
        Signer reader2 = new SignerEd25519();
        DarcInstance di = DarcInstance.fromByzCoin(calypso2, readerDarc);
        readerDarc.addIdentity(Darc.RuleSignature, reader2.getIdentity(), Rules.OR);
        di.evolveDarcAndWait(readerDarc, publisher, 10);
        ReadInstance ri = new ReadInstance(calypso2, wr, Arrays.asList(reader2));
        Document doc2 = Document.fromCalypso(calypso2, ri.getInstance().getId(), reader2.getPrivate());
        assertTrue(doc.equals(doc2));
    }
}