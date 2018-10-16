package ch.epfl.dedis.byzcoin;

import ch.epfl.dedis.lib.Roster;
import ch.epfl.dedis.lib.ServerIdentity;
import ch.epfl.dedis.lib.SkipBlock;
import ch.epfl.dedis.lib.SkipblockId;
import ch.epfl.dedis.byzcoin.contracts.DarcInstance;
import ch.epfl.dedis.byzcoin.transaction.ClientTransaction;
import ch.epfl.dedis.byzcoin.transaction.ClientTransactionId;
import ch.epfl.dedis.lib.crypto.Ed25519Point;
import ch.epfl.dedis.lib.darc.*;
import ch.epfl.dedis.lib.exception.CothorityCommunicationException;
import ch.epfl.dedis.lib.exception.CothorityCryptoException;
import ch.epfl.dedis.lib.exception.CothorityException;
import ch.epfl.dedis.lib.exception.CothorityNotFoundException;
import ch.epfl.dedis.lib.proto.SkipchainProto;
import ch.epfl.dedis.skipchain.SkipchainRPC;
import ch.epfl.dedis.lib.proto.ByzCoinProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Stream;

import static java.time.temporal.ChronoUnit.NANOS;

/**
 * Class ByzCoinRPC interacts with the byzcoin service of a conode. It can either start a new byzcoin service
 * (this needs to be secured somehow) or link to an existing byzcoin service.
 * <p>
 * ByzCoinRPC is the new skipchain service of the cothority that allows batching of transactions and simplified proofs.
 * It is a permissioned blockchain with high throughput (100-1000 transactions) and a byzantine-tolerant consensus
 * algorithm.
 */
public class ByzCoinRPC {
    private Config config;
    private Roster roster;
    private Darc genesisDarc;
    private SkipBlock genesis;
    private SkipBlock latest;
    private SkipchainRPC skipchain;

    private Subscription subscription;
    public static final int currentVersion = 1;

    private static final Logger logger = LoggerFactory.getLogger(ByzCoinRPC.class);

    /**
     * This instantiates a new byzcoin object by asking the cothority to set up a new byzcoin.
     *
     * @param r             is the roster to be used
     * @param d             is the genesis darc
     * @param blockInterval is the block interval between two blocks
     * @throws CothorityException if something goes wrong
     */
    public ByzCoinRPC(Roster r, Darc d, Duration blockInterval) throws CothorityException {
        if (d.getExpression("view_change") == null){
            throw new CothorityCommunicationException("need a 'view_change' rule.");
        }
        ByzCoinProto.CreateGenesisBlock.Builder request =
                ByzCoinProto.CreateGenesisBlock.newBuilder();
        request.setVersion(currentVersion);
        request.setRoster(r.toProto());
        request.setGenesisdarc(d.toProto());
        request.setBlockinterval(blockInterval.get(NANOS));

        ByteString msg = r.sendMessage("ByzCoin/CreateGenesisBlock",
                request.build());

        try {
            ByzCoinProto.CreateGenesisBlockResponse reply =
                    ByzCoinProto.CreateGenesisBlockResponse.parseFrom(msg);
            genesis = new SkipBlock(reply.getSkipblock());
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCommunicationException(e);
        }
        latest = genesis;
        logger.info("Created new ByzCoin ledger with ID: {}", genesis.getId().toString());
        skipchain = new SkipchainRPC(r, genesis.getId());
        config = new Config(blockInterval);
        roster = r;
        genesisDarc = d;
        subscription = new Subscription(this);
    }

    /**
     * For use by fromByzcoin
     */
    protected ByzCoinRPC(){}

    /**
     * For use by CalypsoRPC
     * @param bc the ByzCoinRPC to copy the config from.
     */
    protected ByzCoinRPC(ByzCoinRPC bc){
        config = bc.config;
        roster = bc.roster;
        genesisDarc = bc.genesisDarc;
        genesis = bc.genesis;
        latest = bc.latest;
        skipchain = bc.skipchain;
        subscription = bc.subscription;
    }

    /**
     * Sends a transaction to byzcoin, but doesn't wait for the inclusion of this transaction in a block.
     * Once the transaction has been sent, you need to poll to verify if it has been included or not.
     *
     * @param t is the client transaction holding one or more instructions to be sent to byzcoin.
     * @throws CothorityException if something goes wrong if something goes wrong
     * @return the client transaction
     */
    public ClientTransactionId sendTransaction(ClientTransaction t) throws CothorityException {
        return sendTransactionAndWait(t, 0);
    }

    /**
     * Sends a transaction to byzcoin and waits for up to 'wait' blocks for the transaction to be
     * included in the global state. If more than 'wait' blocks are created and the transaction is not
     * included, an exception will be raised.
     *
     * @param t    is the client transaction holding one or more instructions to be sent to byzcoin.
     * @param wait indicates the number of blocks to wait for the transaction to be included.
     * @return ClientTransactionID the transaction ID
     * @throws CothorityException if the transaction has not been included within 'wait' blocks.
     */
    public ClientTransactionId sendTransactionAndWait(ClientTransaction t, int wait) throws CothorityException {
        ByzCoinProto.AddTxRequest.Builder request =
                ByzCoinProto.AddTxRequest.newBuilder();
        request.setVersion(currentVersion);
        request.setSkipchainid(ByteString.copyFrom(skipchain.getID().getId()));
        request.setTransaction(t.toProto());
        request.setInclusionwait(wait);

        ByteString msg = roster.sendMessage("ByzCoin/AddTxRequest", request.build());
        try {
            ByzCoinProto.AddTxResponse reply =
                    ByzCoinProto.AddTxResponse.parseFrom(msg);
            // TODO do something with the reply?
            logger.info("Successfully stored request - waiting for inclusion");
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCommunicationException(e);
        }
        return t.getId();
    }

    /**
     * Gets a proof from byzcoin to show that a given instance is stored in the
     * global state.
     *
     * @param id is the id of the instance to be fetched
     * @throws CothorityCommunicationException if something goes wrong
     * @return the proof
     */
    public Proof getProof(InstanceId id) throws CothorityCommunicationException {
        ByzCoinProto.GetProof.Builder request =
                ByzCoinProto.GetProof.newBuilder();
        request.setVersion(currentVersion);
        request.setId(skipchain.getID().toProto());
        request.setKey(id.toByteString());

        ByteString msg = roster.sendMessage("ByzCoin/GetProof", request.build());
        try {
            ByzCoinProto.GetProofResponse reply =
                    ByzCoinProto.GetProofResponse.parseFrom(msg);
            logger.info("Successfully received proof");
            return new Proof(reply.getProof());
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCommunicationException(e);
        }
    }

    /**
     * Fetches the latest configuration and genesis darc from byzcoin.
     *
     * @throws CothorityException if something goes wrong if something goes wrong
     */
    public void update() throws CothorityException {
        SkipBlock sb = skipchain.getLatestSkipblock();
        if (sb != null) {
            latest = sb;
        }
    }

    /**
     * Verifies if the nodes representing the cothority are alive and reply to a ping.
     *
     * @return true if all nodes are live, false if one or more are not responding.
     */
    public boolean checkLiveness() {
        for (ServerIdentity si : roster.getNodes()) {
            try {
                logger.info("Checking status of {}", si.getAddress());
                si.GetStatus();
            } catch (CothorityCommunicationException e) {
                logger.warn("Failing node {}: {}", si.getAddress(), e.toString());
                return false;
            }
        }
        return true;
    }

    /**
     * @return a byte representation of this byzcoin object.
     */
    public byte[] toBytes() {
        return null;
    }

    /**
     * @return current configuration
     */
    public Config getConfig() {
        return config;
    }

    /**
     * @return current genesis darc
     */
    public Darc getGenesisDarc() {
        return genesisDarc;
    }

    /**
     * @return the darc instance of the genesis darc.
     * @throws CothorityException if something goes wrong if something goes wrong
     */
    public DarcInstance getGenesisDarcInstance() throws CothorityException{
        return DarcInstance.fromByzCoin(this, genesisDarc);
    }

    /**
     * @return the genesis block of the ledger.
     */
    public SkipBlock getGenesisBlock() {
        return genesis;
    }

    /**
     * @return the roster responsible for the ledger
     */
    public Roster getRoster() {
        return roster;
    }

    /**
     * Fetches a given block from the skipchain and returns the corresponding Block.
     *
     * @param id hash of the skipblock to fetch
     * @return a Block representation of the skipblock
     * @throws CothorityCommunicationException if it couldn't contact the nodes
     * @throws CothorityCryptoException if there's a problem with the cryptography
     */
    public Block getBlock(SkipblockId id) throws CothorityCommunicationException, CothorityCryptoException {
        SkipBlock sb = skipchain.getSkipblock(id);
        return new Block(sb);
    }

    /**
     * Fetches the latest block from the Skipchain and returns the corresponding Block.
     *
     * @return a Block representation of the skipblock
     * @throws CothorityCryptoException if there's a problem with the cryptography
     */
    public Block getLatestBlock() throws CothorityException {
        this.update();
        return new Block(latest);
    }

    /**
     * CheckAuthorization asks ByzCoin which of the rules stored in the latest version of the darc given by id
     * can be resolved with a combination of signatures given by identities. Each identity can be of any type. If
     * it is a darc, then any "_sign" rule given by that darc will be accepted.
     *
     * @param id the base id of the darc to be searched for
     * @param identities a list of identities that might sign
     * @return a list of actions that are allowed by any possible combination of signature from identities
     * @throws CothorityCommunicationException if something goes wrong
     */
    public List<String> checkAuthorization(DarcId id, List<Identity> identities) throws CothorityCommunicationException {
        ByzCoinProto.CheckAuthorization.Builder request =
                ByzCoinProto.CheckAuthorization.newBuilder();
        request.setVersion(currentVersion);
        request.setByzcoinid(ByteString.copyFrom(skipchain.getID().getId()));
        request.setDarcid(ByteString.copyFrom(id.getId()));
        identities.forEach(identity -> request.addIdentities(identity.toProto()));

        ByteString msg = roster.sendMessage("ByzCoin/CheckAuthorization", request.build());
        try {
            ByzCoinProto.CheckAuthorizationResponse reply =
                    ByzCoinProto.CheckAuthorizationResponse.parseFrom(msg);
            logger.info("Got request reply: {}", reply);
            return reply.getActionsList();
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCommunicationException(e);
        }
    }

    /**
     * This should be used with caution. Every time you use this, please open an issue in github and tell us
     * why you think you need this. We'll try to fix it then!
     *
     * @return the underlying skipchain service.
     */
    public SkipchainRPC getSkipchain() {
        logger.warn("usually you should not need this - please tell us why you do anyway.");
        return skipchain;
    }

    /**
     * Subscribes to all new skipBlocks that might arrive. The subscription is implemented using a polling
     * approach until we have a working streaming solution.
     *
     * @param sbr is a SkipBlockReceiver that will be called with any new block(s) available.
     * @throws CothorityCommunicationException if something goes wrong
     */
    public void subscribeSkipBlock(Subscription.SkipBlockReceiver sbr) throws CothorityCommunicationException {
        subscription.subscribeSkipBlock(sbr);
    }

    /**
     * Subscribe to an infinite stream of future SkipBlocks. Note that you need to give a limit or the
     * thread will hang indefinitely
     *
     * Each subscription request uses its own connection and the stream must be correctly closed to clean
     * the resources
     *
     * @throws CothorityCommunicationException if something goes wrong when establishing the connection
     */
    public Stream<SkipBlock> subscribeSkipBlock() throws CothorityCommunicationException {
        BlockingQueue<SkipBlock> queue = new LinkedBlockingQueue<>();
        ServerIdentity.StreamingConn conn = streamTransactions(queue);

        Stream<SkipBlock> stream = Stream.generate(() -> {
            try {
                return queue.take();
            } catch (InterruptedException e) {
                return null;
            }
        });

        return stream.onClose(conn::close).filter(Objects::nonNull); // we don't want any null in the stream
    }

    /**
     * Unsubscribes a BlockReceiver.
     *
     * @param sbr the SkipBlockReceiver to unsubscribe.
     */
    public void unsubscribeBlock(Subscription.SkipBlockReceiver sbr) {
        subscription.unsubscribeSkipBlock(sbr);
    }

    /**
     * Constructs a ByzCoinRPC from a known configuration. The constructor will communicate with the service to
     * populate other fields and perform verification.
     *
     * @param roster      the roster to talk to
     * @param skipchainId the ID of the genesis skipblock, aka skipchain ID
     * @throws CothorityException if something goes wrong
     * @return a new ByzCoinRPC object, connected to the requested roster and chain.
     */
    public static ByzCoinRPC fromByzCoin(Roster roster, SkipblockId skipchainId) throws CothorityException{
        Proof proof = ByzCoinRPC.getProof(roster, skipchainId, InstanceId.zero());
        if (!proof.isContract("config", skipchainId)) {
            throw new CothorityNotFoundException("couldn't verify proof for genesisConfiguration");
        }
        ByzCoinRPC bc = new ByzCoinRPC();
        bc.config = new Config(proof.getValue());

        Proof proof2 = ByzCoinRPC.getProof(roster, skipchainId, new InstanceId(proof.getDarcID().getId()));
        if (!proof2.isContract(DarcInstance.ContractId, skipchainId)) {
            throw new CothorityNotFoundException("couldn't verify proof for genesisConfiguration");
        }
        try {
            bc.genesisDarc = new Darc(proof2.getValue());
        } catch (InvalidProtocolBufferException e){
            throw new CothorityCommunicationException("couldn't get genesis darc: " + e.getMessage());
        }

        // find the skipchain info
        bc.skipchain = new SkipchainRPC(roster, skipchainId);
        bc.roster = roster;
        bc.genesis = bc.skipchain.getSkipblock(skipchainId);
        bc.latest = bc.skipchain.getLatestSkipblock();
        bc.subscription = new Subscription(bc);
        return bc;
    }

    /**
     * Creates a genesis darc to use for the initialisation of Byzcoin.
     * @param admin the admin of Byzcoin
     * @param roster the nodes of Byzcoin
     * @return a Darc with the correct rights, also for the view_change.
     * @throws CothorityCryptoException if there's a problem with the cryptography
     */
    public static Darc makeGenesisDarc(Signer admin, Roster roster) throws CothorityCryptoException{
        Darc d = new Darc(Arrays.asList(admin.getIdentity()), Arrays.asList(admin.getIdentity()), "Genesis darc".getBytes());
        roster.getNodes().forEach(node ->{
            try {
                d.addIdentity("view_change", new IdentityEd25519(new Ed25519Point(node.Public)), Rules.OR);
            } catch (CothorityCryptoException e){
                logger.warn("didn't find Ed25519 point");
            }
        });
        d.addIdentity("spawn:darc", admin.getIdentity(), Rules.OR);
        return d;
    }

   /**
     * Static method to request a proof from ByzCoin. This is used in the instantiation method.
     *
     * @param roster      where to contact the cothority
     * @param skipchainId the id of the underlying skipchain
     * @param key         which key we're interested in
     * @return a proof pointing to the instance. The proof can also be a proof that the instance does not exist.
     * @throws CothorityCommunicationException
     */
    private static Proof getProof(Roster roster, SkipblockId skipchainId, InstanceId key) throws CothorityCommunicationException {
        ByzCoinProto.GetProof.Builder configBuilder = ByzCoinProto.GetProof.newBuilder();
        configBuilder.setVersion(currentVersion);
        configBuilder.setId(skipchainId.toProto());
        configBuilder.setKey(key.toByteString());

        ByteString msg = roster.sendMessage("ByzCoin/GetProof", configBuilder.build());

        try {
            ByzCoinProto.GetProofResponse reply = ByzCoinProto.GetProofResponse.parseFrom(msg);
            return new Proof(reply.getProof());
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCommunicationException(e);
        }
    }

    /**
     * Getter for the subscription object.
     * @return the Subscription
     */
    public Subscription getSubscription() {
        return subscription;
    }

    /**
     * Helper function for making the initial connection to the streaming API endpoint.
     *
     * @param receiver contain callbacks that gets called on every response and/or error.
     * @return the streaming connection
     * @throws CothorityCommunicationException
     */
    ServerIdentity.StreamingConn streamTransactions(Subscription.SkipBlockReceiver receiver) throws CothorityCommunicationException {
        ByzCoinProto.StreamingRequest.Builder req = ByzCoinProto.StreamingRequest.newBuilder();
        req.setId(skipchain.getID().toProto());

        ServerIdentity.StreamHandler h = new ServerIdentity.StreamHandler() {
            @Override
            public void receive(ByteBuffer message) {
                try {
                    SkipchainProto.SkipBlock block = ByzCoinProto.StreamingResponse.parseFrom(message).getBlock();
                    receiver.receive(new SkipBlock(block));
                } catch (InvalidProtocolBufferException e) {
                    receiver.error(e.getMessage());
                }
            }

            @Override
            public void error(String s) {
                receiver.error(s);
            }
        };
        return roster.makeStreamingConn("ByzCoin/StreamingRequest", req.build(), h);
    }

    /**
     * Helper function to make a connection to the streaming API endpoint and populate a blocking queue with the
     * new blocks. The queue will be used during a stream generation
     *
     * As a stream doesn't handle errors, they are ignored and written in the logs.
     *
     * @param queue The blocking queue used by the stream
     * @throws CothorityCommunicationException if something goes wrong when establishing the connection
     */
    private ServerIdentity.StreamingConn streamTransactions(BlockingQueue<SkipBlock> queue) throws CothorityCommunicationException {
        ByzCoinProto.StreamingRequest.Builder req = ByzCoinProto.StreamingRequest.newBuilder();
        req.setId(skipchain.getID().toProto());

        ServerIdentity.StreamHandler h = new ServerIdentity.StreamHandler() {
            @Override
            public void receive(ByteBuffer message) {
                try {
                    SkipchainProto.SkipBlock block = ByzCoinProto.StreamingResponse.parseFrom(message).getBlock();
                    queue.add(new SkipBlock(block));
                } catch (InvalidProtocolBufferException e) {
                    // ignore invalid block but keep a log of the event
                    logger.error(e.getMessage());
                }
            }

            @Override
            public void error(String s) {
                logger.error(s);
            }
        };

        return roster.makeStreamingConn("ByzCoin/StreamingRequest", req.build(), h);
    }

}
