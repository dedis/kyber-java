package ch.epfl.dedis.byzgen;

import ch.epfl.dedis.integration.TestServerController;
import ch.epfl.dedis.integration.TestServerInit;
import ch.epfl.dedis.lib.Hex;
import ch.epfl.dedis.lib.SkipblockId;
import ch.epfl.dedis.byzcoin.contracts.DarcInstance;
import ch.epfl.dedis.calypso.*;
import ch.epfl.dedis.lib.crypto.TestSignerX509EC;
import ch.epfl.dedis.lib.darc.*;
import ch.epfl.dedis.lib.exception.CothorityException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

public class GrantAccessTest {
    static final String SUPERADMIN_SCALAR = "AEE42B6A924BDFBB6DAEF8B252258D2FDF70AFD31852368AF55549E1DF8FC80D";
    private static final SignerEd25519 superadmin = new SignerEd25519(Hex.parseHexBinary(SUPERADMIN_SCALAR));
    private final SignerX509EC consumerSigner = new TestSignerX509EC();
    private final SignerX509EC publisherSigner = new TestSignerX509EC();
    private final SignerX509EC consumerPublicPart = new TestLimitedSignerX509EC(consumerSigner);
    private TestServerController testServerController;
    private CalypsoRPC calypso;

    @BeforeEach
    void initConodes() {
        testServerController = TestServerInit.getInstance();
    }

    @Test
    void attemptToGrantAccessBeforeCreationDirectlyToKey() throws Exception {
        // given
        // setup skipchain
        CalypsoRPC crpc = createSkipChainForTest();
        calypso = connectToExistingSkipchain(crpc.getGenesisBlock().getSkipchainId(), crpc.getLTSId());
        DarcId publisherId = createPublisher(calypso);

        //when
        IdentityDarc publisherIdentity = new IdentityDarc(publisherId);
        Darc documentDarc = new Darc(Arrays.asList(publisherIdentity), Arrays.asList(publisherIdentity), "document darc".getBytes());
        documentDarc.addIdentity("spawn:calypsoWrite", new IdentityX509EC(publisherSigner), Rules.OR);
        documentDarc.addIdentity("spawn:calypsoRead", new IdentityX509EC(consumerPublicPart), Rules.OR);
        calypso.getGenesisDarcInstance().spawnDarcAndWait(documentDarc, superadmin, 10);

        Document doc = new Document("ala ma kota".getBytes(), 16, "extra data".getBytes(), documentDarc.getBaseId());
        WriteInstance writeInstance = new WriteInstance(calypso, documentDarc.getBaseId(), Arrays.asList(publisherSigner),
                doc.getWriteData(calypso.getLTS()));

        // then
        // Cannot use ephemeral keys yet.
//        ReadInstance read = new ReadInstance(calypso, writeInstance, Arrays.asList(consumerSigner));
//        assertNotNull(read.getRead());
    }

    @Test
    void attemptToGrantAccessToExistingDocumentDirectlyToKey() throws Exception {
        // given
        // setup skipchain
        CalypsoRPC crpc = createSkipChainForTest();
        calypso = connectToExistingSkipchain(crpc.getGenesisBlock().getSkipchainId(), crpc.getLTSId());
        DarcId publisherId = createPublisher(calypso);

        IdentityDarc publisherIdentity = new IdentityDarc(publisherId);
        Darc documentDarc = new Darc(Arrays.asList(publisherIdentity), Arrays.asList(publisherIdentity), "document darc".getBytes());
        documentDarc.addIdentity("spawn:calypsoWrite", new IdentityX509EC(publisherSigner), Rules.OR);
        DarcInstance documentDarcInstance = calypso.getGenesisDarcInstance().spawnDarcAndWait(documentDarc, superadmin, 10);

        Document doc = new Document("ala ma kota".getBytes(), 16, "extra data".getBytes(), documentDarc.getBaseId());
        WriteInstance writeInstance = new WriteInstance(calypso, documentDarc.getBaseId(), Arrays.asList(publisherSigner),
                doc.getWriteData(calypso.getLTS()));

        //when
        Identity identityX509EC = new IdentityX509EC(consumerPublicPart);
        Darc newDarc = documentDarc.copyRulesAndVersion();
        newDarc.addIdentity("spawn:calypsoRead", identityX509EC, Rules.OR);
        documentDarcInstance.evolveDarcAndWait(newDarc, publisherSigner, 10);

        //then
        // Cannot use ephemeral keys yet.
//        ReadInstance read = new ReadInstance(calypso, writeInstance, Arrays.asList(consumerSigner));
//        assertNotNull(read.getRead());
    }

    @Test
    void attemptToGrantAccessToExistingDocumentToOtherDarc() throws Exception {
        // given
        // setup skipchain
        CalypsoRPC crpc = createSkipChainForTest();
        calypso = connectToExistingSkipchain(crpc.getGenesisBlock().getSkipchainId(), crpc.getLTSId());
        DarcId publisherId = createPublisher(calypso);
        DarcId consumerId = createConsumer(calypso);

        IdentityDarc publisherIdentity = new IdentityDarc(publisherId);
        Darc documentDarc = new Darc(Arrays.asList(publisherIdentity), Arrays.asList(publisherIdentity), "document darc".getBytes());
        documentDarc.addIdentity("spawn:calypsoWrite", new IdentityX509EC(publisherSigner), Rules.OR);
        DarcInstance documentDarcInstance = calypso.getGenesisDarcInstance().spawnDarcAndWait(documentDarc, superadmin, 10);

        Document doc = new Document("ala ma kota".getBytes(), 16, "extra data".getBytes(), documentDarc.getBaseId());
        WriteInstance writeInstance = new WriteInstance(calypso, documentDarc.getBaseId(), Arrays.asList(publisherSigner),
                doc.getWriteData(calypso.getLTS()));

        //when
        Darc newDarc = documentDarc.copyRulesAndVersion();
        newDarc.addIdentity("spawn:calypsoRead", new IdentityDarc(consumerId), Rules.OR);
        documentDarcInstance.evolveDarcAndWait(newDarc, publisherSigner, 10);

        //then
        // Cannot use ephemeral keys yet.
//        ReadInstance read = new ReadInstance(calypso, writeInstance, Arrays.asList(consumerSigner));
//        assertNotNull(read.getRead());
    }

    private DarcId createConsumer(CalypsoRPC ocs) throws Exception {
        DarcInstance user = createUser(ocs, consumerSigner.getIdentity());
        return new DarcId(user.getId().getId());
    }

    private CalypsoRPC connectToExistingSkipchain(SkipblockId genesis, LTSId ltsId) throws Exception {
        CalypsoFactory calypsoFactory = new CalypsoFactory();
        calypsoFactory.addConode(testServerController.getMasterConode());
        calypsoFactory.setGenesis(genesis);
        calypsoFactory.setLTSId(ltsId);
        return calypsoFactory.createConnection();
    }

    private DarcId createPublisher(CalypsoRPC ocs) throws Exception {
        DarcInstance user = createUser(ocs, new IdentityX509EC(publisherSigner));
        grantSystemWriteAccess(ocs, user.getDarc());
        return new DarcId(user.getId().getId()); // copy to be sure that it is not the same object
    }

    private CalypsoRPC createSkipChainForTest() throws CothorityException {
        return new CalypsoFactory()
                .addConodes(testServerController.getConodes())
                .initialiseNewCalypso(new SignerEd25519(
                        Hex.parseHexBinary(SUPERADMIN_SCALAR)));
    }

    private static DarcInstance createUser(CalypsoRPC ocs, Identity user) throws Exception {
        Darc userDarc = new Darc(Arrays.asList(user), Arrays.asList(user), "user".getBytes());
        return ocs.getGenesisDarcInstance().spawnDarcAndWait(userDarc, superadmin, 10);
    }

    private static void grantSystemWriteAccess(CalypsoRPC ocs, Darc userDarc) throws Exception {
        Darc newGenesis = ocs.getGenesisDarc().copyRulesAndVersion();
        newGenesis.addIdentity(Darc.RuleSignature, IdentityFactory.New(userDarc), Rules.OR);
        newGenesis.addIdentity(Darc.RuleEvolve, IdentityFactory.New(userDarc), Rules.OR);

        DarcInstance di = DarcInstance.fromByzCoin(ocs, ocs.getGenesisDarc().getBaseId());
        di.evolveDarcAndWait(newGenesis, superadmin, 10);
    }

    private class TestLimitedSignerX509EC extends TestSignerX509EC {
        public TestLimitedSignerX509EC(SignerX509EC consumerKeys) {
            super(consumerKeys.getPublicKey(), null);
        }

        @Override
        public byte[] sign(byte[] msg) throws SignRequestRejectedException {
            throw new SignRequestRejectedException("It is not acceptable to sign message when access is granted to the user", null);
        }
    }
}
