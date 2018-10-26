package ch.epfl.dedis.byzcoin;

import ch.epfl.dedis.byzcoin.contracts.ChainConfigData;
import ch.epfl.dedis.byzcoin.contracts.ChainConfigInstance;
import ch.epfl.dedis.byzcoin.transaction.ClientTransaction;
import ch.epfl.dedis.byzcoin.transaction.ClientTransactionId;
import ch.epfl.dedis.integration.TestServerController;
import ch.epfl.dedis.integration.TestServerInit;
import ch.epfl.dedis.lib.Roster;
import ch.epfl.dedis.lib.ServerIdentity;
import ch.epfl.dedis.lib.SkipBlock;
import ch.epfl.dedis.lib.darc.Darc;
import ch.epfl.dedis.lib.darc.Signer;
import ch.epfl.dedis.lib.darc.SignerEd25519;
import ch.epfl.dedis.lib.exception.CothorityCommunicationException;
import ch.epfl.dedis.lib.exception.CothorityCryptoException;
import ch.epfl.dedis.lib.exception.CothorityException;
import ch.epfl.dedis.lib.exception.CothorityPermissionException;
import ch.epfl.dedis.lib.proto.ByzCoinProto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static ch.epfl.dedis.integration.TestServerController.*;
import static java.time.temporal.ChronoUnit.MILLIS;
import static org.junit.jupiter.api.Assertions.*;

public class ByzCoinRPCTest {
    static ByzCoinRPC bc;

    static Signer admin;
    static Darc genesisDarc;

    private final static Logger logger = LoggerFactory.getLogger(ByzCoinRPCTest.class);
    private TestServerController testInstanceController;

    @BeforeEach
    void initAll() throws Exception {
        testInstanceController = TestServerInit.getInstance();
        admin = new SignerEd25519();
        genesisDarc = ByzCoinRPC.makeGenesisDarc(admin, testInstanceController.getRoster());

        bc = new ByzCoinRPC(testInstanceController.getRoster(), genesisDarc, Duration.of(500, MILLIS));
        if (!bc.checkLiveness()) {
            throw new CothorityCommunicationException("liveness check failed");
        }
    }

    @Test
    void ping() {
        assertTrue(bc.checkLiveness());
    }

    /**
     * We only give the client the roster and the genesis ID. It should be able to find the configuration, latest block
     * and the genesis darc.
     */
    @Test
    void reconnect() throws Exception {
        ByzCoinRPC bc = ByzCoinRPC.fromByzCoin(ByzCoinRPCTest.bc.getRoster(), ByzCoinRPCTest.bc.getGenesisBlock().getSkipchainId());
        assertEquals(ByzCoinRPCTest.bc.getConfig().getBlockInterval(), bc.getConfig().getBlockInterval());
        // check that getMaxBlockSize returned what we expect (from defaultMaxBlockSize in Go).
        assertEquals(4000000, bc.getConfig().getMaxBlockSize());
        assertEquals(ByzCoinRPCTest.bc.getLatestBlock().getTimestampNano(), bc.getLatestBlock().getTimestampNano());
        assertEquals(ByzCoinRPCTest.bc.getGenesisDarc().getBaseId(), bc.getGenesisDarc().getBaseId());

    }

    class TestReceiver implements Subscription.SkipBlockReceiver {
        private int ctr;
        private String error;

        private TestReceiver() {
            ctr = 0;
        }

        @Override
        public void receive(SkipBlock block) {
            if (isOk()) {
                ctr++;
            }
        }

        @Override
        public void error(String s) {
            if (isOk()) {
                error = s;
            }
        }

        private int getCtr() {
            return ctr;
        }

        private boolean isOk() {
            return error == null;
        }
    }

    /**
     * Subscribes to new blocks and verifies it gets them.
     */
    @Test
    void subscribeSkipBlocks() throws Exception {
        logger.info("Subscribing blocks");
        TestReceiver receiver = new TestReceiver();
        assertTrue(bc.getSubscription().isClosed());
        bc.subscribeSkipBlock(receiver);
        assertFalse(bc.getSubscription().isClosed());
        // Wait for two block intervals, we should see 0 blocks because we haven't done anything
        Thread.sleep(4 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(0, receiver.getCtr());

        // Update the darc and thus create one block
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 10);
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        assertNotEquals(0, receiver.getCtr());
        bc.unsubscribeBlock(receiver);
    }

    /**
     * Subscribe to new blocks using a stream
     */
    @Test
    void subscribeSkipBlockStream() throws Exception {
        Stream<SkipBlock> stream = bc.subscribeSkipBlock();

        // create one block
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 0);

        // no need to wait as it will hang until one block is accepted
        assertEquals(1, stream.limit(1).count());

        stream.close();
    }

    @Test
    void multipleSubscribeSkipBlocks() throws Exception {
        logger.info("Subscribing blocks");
        List<TestReceiver> receivers = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            TestReceiver receiver = new TestReceiver();
            bc.subscribeSkipBlock(receiver);
            receivers.add(receiver);
        }
        assertFalse(bc.getSubscription().isClosed());

        // Wait for two block intervals, we should see 0 blocks because we haven't done anything
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        for (TestReceiver receiver : receivers) {
            assertEquals(0, receiver.getCtr());
        }

        // Update the darc and thus create some blocks
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 10);
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        for (TestReceiver receiver : receivers) {
            assertNotEquals(0, receiver.getCtr());
        }

        // Remove all, then the connection should close.
        for (TestReceiver receiver : receivers) {
            bc.unsubscribeBlock(receiver);
        }
    }


    class TestTxReceiver implements Subscription.SkipBlockReceiver {
        private List<ClientTransaction> allCtxs;
        private String error;

        private TestTxReceiver() {
            super();
            allCtxs = new ArrayList<>();
        }

        @Override
        public void receive(SkipBlock block) {
            logger.info("got SkipBlock {}", block);
            try {
                Block b = new Block(block);
                allCtxs.addAll(b.getAcceptedClientTransactions());
            } catch (CothorityCryptoException e) {
                throw new RuntimeException(e);
            }
        }

        @Override
        public void error(String s) {
            if (error == null) {
                error = s;
            }
        }

        private List<ClientTransaction> getAllCtxs() {
            return allCtxs;
        }
    }

    /**
     * Subscribes to new blocks and verifies it gets them.
     */
    @Test
    void subscribeClientTransactions() throws Exception {
        // Create a second subscription that will receive multiple blocks at once.
        TestReceiver receiver = new TestReceiver();
        Subscription sub2 = new Subscription(bc);
        sub2.subscribeSkipBlock(receiver);
        TestTxReceiver txReceiver = new TestTxReceiver();
        bc.subscribeSkipBlock(txReceiver);

        // Wait for two possible blocks and make sure we don't get any transactions
        Thread.sleep(2 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(0, receiver.getCtr());
        assertEquals(0, txReceiver.getAllCtxs().size());

        // Update the darc and thus create at least one block with at least the interesting clientTransaction
        ClientTransactionId ctxid = bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 10);

        Thread.sleep(3 * bc.getConfig().getBlockInterval().toMillis());
        assertNotEquals(0, txReceiver.getAllCtxs().size());
        assertEquals(1, txReceiver.getAllCtxs().stream().filter(ctx ->
                ctx.getId().equals(ctxid)).count());

        // Update the darc again - even if it's the same darc
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 10);

        Thread.sleep(3 * bc.getConfig().getBlockInterval().toMillis());
        assertEquals(2, receiver.getCtr());
    }

    @Test
    void streamClientTransaction() throws Exception {
        TestReceiver receiver = new TestReceiver();
        ServerIdentity.StreamingConn conn = bc.streamTransactions(receiver);

        // Generate a block by updating the darc.
        bc.getGenesisDarcInstance().evolveDarcAndWait(bc.getGenesisDarc(), admin, 10);
        Thread.sleep(bc.getConfig().getBlockInterval().toMillis());
        assertTrue(receiver.isOk());
        assertNotEquals(0, receiver.getCtr());

        conn.close();
    }

    @Test
    void updateInterval() throws Exception {
        List<Signer> admins = Arrays.asList(admin);
        assertThrows(CothorityPermissionException.class, () -> bc.setBlockInterval(Duration.ofMillis(4999), admins, 10));
        logger.info("Setting interval to 5 seconds");
        bc.setBlockInterval(Duration.ofMillis(5000), admins, 10);
        ByzCoinProto.ChainConfig.Builder newCCD = ChainConfigInstance.fromByzcoin(bc).getChainConfig().toProto().toBuilder();
        // Need to set the blockInterval manually, else it will complain.
        logger.info("Setting interval back to 500 milliseconds");
        Instant now = Instant.now();
        newCCD.setBlockinterval(500 * 1000 * 1000);
        ChainConfigInstance.fromByzcoin(bc).evolveConfigAndWait(new ChainConfigData(newCCD.build()), admins, 10);
        assertTrue(Duration.between(now, Instant.now()).toMillis() > 5000);
    }

    @Test
    void updateMaxBlockSize() throws Exception {
        List<Signer> admins = Arrays.asList(admin);
        Arrays.asList(ChainConfigData.blocksizeMin - 1, ChainConfigData.blocksizeMax + 1).forEach(invalidSize ->
                assertThrows(CothorityException.class, () ->
                        bc.setMaxBlockSize(invalidSize, admins, 10)
                )
        );
        Arrays.asList(ChainConfigData.blocksizeMin, (ChainConfigData.blocksizeMin + ChainConfigData.blocksizeMax) / 2,
                ChainConfigData.blocksizeMax).forEach(validSize -> {
                    try {
                        bc.setMaxBlockSize(validSize, admins, 10);
                    } catch (CothorityException e) {
                        fail("should accept this size");
                    }
                }
        );
    }

    @Test
    @Disabled("Cannot change members of a roster for the moment.")
    void updateRoster() throws Exception {
        List<Signer> admins = new ArrayList<>();
        admins.add(admin);

        // First make sure we correctly refuse invalid new rosters.
        // Too few nodes
        final Roster newRoster1 = new Roster(Arrays.asList(conode1, conode2));
        assertThrows(CothorityPermissionException.class, () -> bc.setRoster(newRoster1, admins, 10));

        // Too many new nodes
        List<ServerIdentity> newList = bc.getRoster().getNodes();
        newList.addAll(newRoster1.getNodes());
        final Roster newRoster2 = new Roster(newList);
        assertThrows(CothorityPermissionException.class, () -> bc.setRoster(newRoster2, admins, 10));

        // Too many changes
        final Roster newRoster3 = new Roster(Arrays.asList(conode1, conode2, conode5, conode6));
        assertThrows(CothorityPermissionException.class, () -> bc.setRoster(newRoster3, admins, 10));

        // And finally some real update of the roster
        // First start conode 5 (it is a sleeper conode)
        try {
            testInstanceController.startConode(5);
            logger.info("updating real roster");
            Roster newRoster = new Roster(Arrays.asList(conode1, conode2, conode3, conode4, conode5));
            bc.setRoster(newRoster, admins, 10);

            logger.info("shutting down two nodes and it should still run");
            try {
                testInstanceController.killConode(3);
                testInstanceController.killConode(4);
                bc.setMaxBlockSize(1000 * 1000, admins, 10);
            } finally {
                testInstanceController.startConode(3);
                testInstanceController.startConode(4);
            }
        } finally {
            testInstanceController.killConode(5);
        }
    }
}
