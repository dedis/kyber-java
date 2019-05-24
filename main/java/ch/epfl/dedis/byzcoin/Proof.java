package ch.epfl.dedis.byzcoin;

import ch.epfl.dedis.lib.SkipBlock;
import ch.epfl.dedis.lib.SkipblockId;
import ch.epfl.dedis.lib.crypto.Bn256G2Point;
import ch.epfl.dedis.lib.crypto.Point;
import ch.epfl.dedis.lib.darc.DarcId;
import ch.epfl.dedis.lib.exception.CothorityCryptoException;
import ch.epfl.dedis.lib.network.ServerIdentity;
import ch.epfl.dedis.lib.proto.ByzCoinProto;
import ch.epfl.dedis.lib.proto.NetworkProto;
import ch.epfl.dedis.lib.proto.SkipchainProto;
import ch.epfl.dedis.lib.proto.TrieProto;
import ch.epfl.dedis.skipchain.ForwardLink;
import com.google.protobuf.InvalidProtocolBufferException;

import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Proof represents a key/value entry in the trie and the path to the
 * root node.
 */
public class Proof {
    private final TrieProto.Proof proof;
    private final List<SkipchainProto.ForwardLink> links;
    private final SkipBlock latest;
    private final byte[] key;
    private final StateChangeBody body;

    /**
     * Creates a new proof given a protobuf-representation and a trusted skipchain ID.
     *
     * @param p    is the protobuf representation
     * @param scID is the skipchain ID
     * @throws CothorityCryptoException       if the verification of the forward links are wrong
     */
    public Proof(ByzCoinProto.Proof p, SkipblockId scID, InstanceId iid) throws CothorityCryptoException {
        this.proof = p.getInclusionproof();
        this.latest = new SkipBlock(p.getLatest());
        this.links = p.getLinksList();
        this.key = iid.getId();
        this.verify(scID);

        StateChangeBody tmpBody;
        try {
            tmpBody = new StateChangeBody(ByzCoinProto.StateChangeBody.parseFrom(proof.getLeaf().getValue()));
        } catch (InvalidProtocolBufferException | CothorityCryptoException e) {
            tmpBody = null;
        }
        this.body = tmpBody;
    }

    /**
     * Creates an instance from the proof, it assumes the proof is valid.
     *
     * @return the instance stored in this proof.
     */
    public Instance getInstance() {
        return Instance.fromProof(this);
    }

    /**
     * Get the protobuf representation of the proof.
     *
     * @return the protobuf representation of the proof
     */
    public ByzCoinProto.Proof toProto() {
        ByzCoinProto.Proof.Builder b = ByzCoinProto.Proof.newBuilder();
        b.setInclusionproof(proof);
        b.setLatest(latest.getProto());
        for (SkipchainProto.ForwardLink link : this.links) {
            b.addLinks(link);
        }
        return b.build();
    }

    /**
     * Getter for the skipblock associated with this proof.
     *
     * @return SkipBlock
     */
    public SkipBlock getLatest() {
        return this.latest;
    }

    /**
     * This function take a skipchain id and verifies that the proof is valid for this
     * skipchain. It verifies the proof, that the Merkle-root is stored in the
     * skipblock of the proof and the fact that the skipblock is indeed part of the
     * skipchain. If all verifications are correct, no exceptions are thrown. It does
     * not verify whether a certain key/value pair exists in the proof,
     * use Proof.match or Proof.exists for that.
     *
     * @param scID the skipblock to verify
     * @throws CothorityCryptoException if something goes wrong
     */
    private void verify(SkipblockId scID) throws CothorityCryptoException {
        ByzCoinProto.DataHeader header;
        try {
            header = ByzCoinProto.DataHeader.parseFrom(this.latest.getData());
        } catch (InvalidProtocolBufferException e) {
            throw new CothorityCryptoException(e.getMessage());
        }
        if (!Arrays.equals(this.getRoot(), header.getTrieroot().toByteArray())) {
            throw new CothorityCryptoException("root of trie is not in skipblock");
        }

        SkipblockId sbID = scID;
        List<Point> publics = null;

        for (int i = 0; i < this.links.size(); i++) {
            if (i == 0) {
                publics = getPoints(this.links.get(i).getNewRoster().getListList());
                continue;
            }
            ForwardLink l = new ForwardLink(this.links.get(i));
            if (!l.verifyWithScheme(publics, latest.getSignatureScheme())) {
                throw new CothorityCryptoException("stored skipblock is not properly evolved from genesis block");
            }
            if (!Arrays.equals(l.getFrom().getId(), sbID.getId())) {
                throw new CothorityCryptoException("stored skipblock is not properly evolved from genesis block");
            }
            sbID = l.getTo();
            try {
                if (l.getNewRoster() != null) {
                    publics = getPoints(this.links.get(i).getNewRoster().getListList());
                }
            } catch (URISyntaxException e) {
                throw new CothorityCryptoException(e.getMessage());
            }
        }

        // Check that the latest block is correct
        if (!Arrays.equals(sbID.getId(), this.latest.getHash())) {
            throw new CothorityCryptoException("last forward link does not point to the latest block");
        }
    }

    /**
     * Getter for the Merkle-root, returns null if it doesn't exist.
     */
    public byte[] getRoot() {
        if (this.proof.getInteriorsCount() == 0) {
            return null;
        }
        return hashInterior(this.proof.getInteriors(0));
    }

    /**
     * @return the key of the leaf node
     */
    public byte[] getKey() {
        return proof.getLeaf().getKey().toByteArray();
    }

    /**
     * @return the list of values in the leaf node. Return null if the value cannot be parsed.
     */
    public StateChangeBody getValues() {
        return this.body;
    }

    /**
     * @return the value of the proof. Return null if the value cannot be parsed.
     */
    public byte[] getValue() {
        StateChangeBody body = getValues();
        if (body == null) {
            return null;
        }
        return body.getValue();
    }

    /**
     * @return the string of the contractID. Return null if the value cannot be parsed.
     */
    public String getContractID() {
        StateChangeBody body = getValues();
        if (body == null) {
            return null;
        }
        return body.getContractID();
    }

    /**
     * @return the Darc base ID defining the access rules to the instance.
     */
    public DarcId getDarcBaseID() {
        StateChangeBody body = getValues();
        if (body == null) {
            return null;
        }
        return body.getDarcBaseId();
    }

    /**
     * Checks whether the contract ID matches the expected ID.
     *
     * @param expectedType the expected contractId
     * @return true if the proof is correct with regard to that Byzcoin id and the contract is of the expected type.
     */
    public boolean contractIsType(String expectedType) {
        return getContractID().equals(expectedType);
    }

    /**
     * Check whether the key (Instance ID) exists.
     *
     * @return true if the proof has the key/value pair stored on the leaf, false if it
     * is a proof of absence or an error has occured.
     */
    public boolean matches() {
        try {
            return this.exists(this.key);
        } catch (CothorityCryptoException e) {
            return false;
        }
    }

    /**
     * Check whether the key exists in the proof.
     *
     * @param key is the value that we want to proof whether it exists or is absent.
     * @return true if it's an existence proof.
     * @throws CothorityCryptoException if an unexpected error occurs, an absence proof does not throw an exception.
     */
    public boolean exists(byte[] key) throws CothorityCryptoException {
        if (key == null) {
            throw new CothorityCryptoException("key is nil");
        }

        if (this.proof.getInteriorsCount() == 0) {
            throw new CothorityCryptoException("no interior nodes");
        }

        Boolean[] bits = binSlice(key);
        byte[] expectedHash = hashInterior(this.proof.getInteriors(0));

        int i;
        for (i = 0; i < this.proof.getInteriorsCount(); i++) {
            if (!Arrays.equals(expectedHash, hashInterior(this.proof.getInteriors(i)))) {
                throw new CothorityCryptoException("invalid interior node");
            }
            if (bits[i]) {
                expectedHash = this.proof.getInteriors(i).getLeft().toByteArray();
            } else {
                expectedHash = this.proof.getInteriors(i).getRight().toByteArray();
            }
        }
        // we use i below instead of i+1 (like the go code) because the final i is one more than the i used in the final iteration
        if (Arrays.equals(expectedHash, hashLeaf(this.proof.getLeaf(), this.proof.getNonce().toByteArray()))) {
            if (!Arrays.equals(Arrays.copyOf(bits, i), this.proof.getLeaf().getPrefixList().toArray(new Boolean[0]))) {
                throw new CothorityCryptoException("invalid prefix in leaf node");
            }
            return Arrays.equals(this.proof.getLeaf().getKey().toByteArray(), key);
        } else if (Arrays.equals(expectedHash, hashEmpty(this.proof.getEmpty(), this.proof.getNonce().toByteArray()))) {
            if (!Arrays.equals(Arrays.copyOf(bits, i), this.proof.getEmpty().getPrefixList().toArray(new Boolean[0]))) {
                throw new CothorityCryptoException("invalid prefix in empty node");
            }
            return false;
        }
        throw new CothorityCryptoException("no corresponding leaf/empty node with respect to the interior nodes");
    }

    private static Boolean[] binSlice(byte[] buf) {
        byte[] hashKey;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(buf);
            hashKey = digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        Boolean[] bits = new Boolean[hashKey.length * 8];
        for (int i = 0; i < bits.length; i++) {
            bits[i] = ((hashKey[i / 8] << (i % 8)) & (1 << 7)) > 0;
        }
        return bits;
    }

    private static byte[] toByteSlice(List<Boolean> bits) {
        byte[] buf = new byte[(bits.size() + 7) / 8];
        for (int i = 0; i < bits.size(); i++) {
            if (bits.get(i)) {
                buf[i / 8] |= (1 << 7) >> (i % 8);
            }
        }
        return buf;
    }

    private static byte[] hashInterior(TrieProto.InteriorNode interior) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(interior.getLeft().toByteArray());
            digest.update(interior.getRight().toByteArray());
            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hashLeaf(TrieProto.LeafNode leaf, byte[] nonce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(new byte[]{3}); // typeLeaf
            digest.update(nonce);
            digest.update(toByteSlice(leaf.getPrefixList()));

            byte[] lBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(leaf.getPrefixCount()).array();
            digest.update(lBuf);

            digest.update(leaf.getKey().toByteArray());
            digest.update(leaf.getValue().toByteArray());

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] hashEmpty(TrieProto.EmptyNode empty, byte[] nonce) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(new byte[]{2}); // typeEmpty
            digest.update(nonce);
            digest.update(toByteSlice(empty.getPrefixList()));

            byte[] lBuf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(empty.getPrefixCount()).array();
            digest.update(lBuf);

            return digest.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static List<Point> getPoints(List<NetworkProto.ServerIdentity> protos) throws CothorityCryptoException {
        List<ServerIdentity> sids = new ArrayList<>();
        for (NetworkProto.ServerIdentity sid : protos) {
            try {
                sids.add(new ServerIdentity(sid));
            } catch (URISyntaxException e) {
                throw new CothorityCryptoException(e.getMessage());
            }
        }
        return sids.stream()
                .map(sid -> (Bn256G2Point) sid.getServicePublic("Skipchain"))
                .collect(Collectors.toList());
    }
}
