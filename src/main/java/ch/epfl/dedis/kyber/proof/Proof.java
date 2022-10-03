package ch.epfl.dedis.kyber.proof;

import ch.epfl.dedis.kyber.EdPoint;
import ch.epfl.dedis.kyber.EdScalar;
import ch.epfl.dedis.kyber.Suite;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

// Package proof implements generic support for Sigma-protocols
// and discrete logarithm proofs in the Camenisch/Stadler framework.
// For the cryptographic foundations of this framework see
// "Proof Systems for General Statements about Discrete Logarithms" at
// ftp://ftp.inf.ethz.ch/pub/crypto/publications/CamSta97b.pdf.

// Internal prover/verifier state
public class Proof {
    Suite s;

    int nsvars;                         // number of Scalar variables
    int npvars;                         // number of Point variables
    ArrayList<String> svar, pvar;       // Scalar and Point variable names
    Map<String, Integer> sidx, pidx;    // Maps from strings to variable indexes

    Map<String, EdPoint> pval;          // values of public Point variables
    Map<String, EdScalar> sval;         // values of private Scalar variables

    // prover-specific state
    ProverContext pc;
    Map<Predicate, Integer> choice;     // OR branch choices set by caller
    Map<Predicate, ProverPred> pp;      // per-predicate prover state

    // verifier-specific state
    VerifierContext vc;
    Map<Predicate, VerifierPred> vp;    // per-predicate verifier state

    public Proof(Suite suite, Predicate pred) {
        this.s = suite;

        // Enumerate all the variables in a consistent order.
        // Reserve variable index 0 for convenience.
        this.svar = new ArrayList<String>();
        this.pvar = new ArrayList<String>();
        this.sidx = new HashMap<String, Integer>();
        this.pidx = new HashMap<String, Integer>();
        pred.enumVars(this);
        this.nsvars = this.svar.size();
        this.npvars = this.pvar.size();
    }

    public void enumScalarVar(String name) {
        if (!this.sidx.containsKey(name)) {
            this.sidx.put(name, this.svar.size());
            this.svar.add(name);
        }
    }

    public void enumPointVar(String name) {
        if (!this.pidx.containsKey(name)) {
            this.pidx.put(name, this.pvar.size());
            this.pvar.add(name);
        }
    }

    // Make a response-array if that wasn't already done in a parent predicate.
    public EdScalar[] makeScalars(EdScalar[] pr) {
        if (pr == null) {
            return new EdScalar[this.nsvars];
        }
        else {
            return pr;
        }
    }

    // Transmit our response-array if a corresponding makeScalars() created it.
    public void sendResponses(EdScalar[] pr, EdScalar[] r) {
        if (pr == null) {
            for (int i = 0; i < r.length; i++) {
                // Send responses only for variables
                // that were used in this OR-domain.
                if (r[i] != null) {
                    this.pc.Put(r[i]);
                }
            }
        }
    }

    // In the verifier, get the responses at the top of an OR-domain,
    // if a corresponding makeScalars() call created it.

    public void getResponses(EdScalar[] pr, EdScalar[] r) {
        if (pr == null) {
            for (int i = 0; i < r.length; i++) {
                if (r[i] != null) {
                    this.vc.Get(r[i]);
                }
            }
        }
    }

    public void prove(Predicate p, Map<String, EdScalar> sval,
                      Map<String, EdPoint> pval, Map<Predicate, Integer> choice, ProverContext pc) {
        this.pc = pc;
        this.sval = sval;
        this.pval = pval;
        this.choice = choice;
        this.pp = new HashMap<Predicate, ProverPred>();

        // Generate all commitments
        p.commit(this, null, null);

        // Generate top-level challenge from public randomness
        EdScalar c = this.s.Scalar();
        pc.PubRand(c);

        // Generate all responses based on master challenge
        p.respond(this, c, null);
    }

    public void verify(Predicate p, Map<String, EdPoint> pval, VerifierContext vc) {
        this.vc = vc;
        this.pval = pval;
        this.vp = new HashMap<Predicate, VerifierPred>();

        // Get the commitments from the verifier,
        // and calculate the sets of responses we'll need for each OR-domain.
        p.getCommits(this, null);

        // Produce the top-level challenge
        EdScalar c = this.s.Scalar();
        vc.PubRand(c);

        // Check all the responses and sub-challenges against the commitments.
        p.verify(this, c, null);
    }

    // Produce a higher-order Prover embodying a given proof predicate.
    public Prover prover(Predicate p, Map<String, EdScalar> sval,
                         Map<String, EdPoint> pval, Map<Predicate, Integer> choice) {
        ClassProver cp = new ClassProver(this, p, sval, pval, choice);
        return cp;
    }

    // Produce a higher-order Verifier embodying a given proof predicate.
    public Verifier verifier(Predicate p, Map<String, EdPoint> pval) {
        ClassVerifier cv = new ClassVerifier(this, p, pval);
        return cv;
    }
}

class ClassProver implements Prover {

    Proof prf;
    Predicate p;
    Map<String, EdScalar> sval;
    Map<String, EdPoint> pval;
    Map<Predicate, Integer> choice;

    public ClassProver(Proof prf, Predicate p, Map<String, EdScalar> sval,
                       Map<String, EdPoint> pval, Map<Predicate, Integer> choice) {
        this.prf = prf;
        this.p = p;
        this.sval = sval;
        this.pval = pval;
        this.choice = choice;
    }

    @Override
    public void prove(ProverContext ctx) {
        this.prf.prove(this.p, this.sval, this.pval, this.choice, ctx);
    }
}

class ClassVerifier implements Verifier {

    Proof prf;
    Predicate p;
    Map<String, EdPoint> pval;

    public ClassVerifier(Proof prf, Predicate p, Map<String, EdPoint> pval) {
        this.prf = prf;
        this.p = p;
        this.pval = pval;
    }

    @Override
    public void verify(VerifierContext ctx) {
        this.prf.verify(this.p, this.pval, ctx);
    }
}

class ProverPred {
    EdScalar w;    // secret pre-challenge
    EdScalar[] v;  // secret blinding factor for each variable
    EdScalar[] wi; // OR predicates: individual sub-challenges

    public ProverPred(EdScalar w, EdScalar[] v, EdScalar[] wi) {
        this.w = w;
        this.v = v;
        this.wi = wi;
    }
}

class VerifierPred {
    public EdPoint v;     // public commitment produced by verifier
    public EdScalar[] r;  // per-variable responses produced by verifier

    public VerifierPred(EdPoint v, EdScalar[] r) {
        this.v = v;
        this.r = r;
    }
}

////////// Rep predicate //////////

// Rep creates a predicate stating that the prover knows
// a representation of a point P with respect to
// one or more secrets and base point pairs.
//
// In its simplest usage, Rep indicates that the prover knows a secret x
// that is the (elliptic curve) discrete logarithm of a public point P
// with respect to a well-known base point B:
//
//	Rep(P,x,B)
//
// Rep can take any number of (Scalar,Base) variable name pairs, however.
// A Rep statement of the form Rep(P,x1,B1,...,xn,Bn)
// indicates that the prover knows secrets x1,...,xn
// such that point P is the sum x1*B1+...+xn*Bn.
//

// A term describes a point-multiplication term in a representation expression.
class Term {
    String S; // Scalar multiplier for this term
    String B; // Generator for this term
}

class RepPred implements Predicate {
    String P; // Public point of which a representation is known
    Term[] T; // Public point of which a representation is known

    public RepPred(String P, String... SB) throws Exception {
        if ((SB.length & 1) != 0) {
            throw new Exception("mismatched Scalar");
        }

        this.T = new Term[SB.length / 2];
        for (int i = 0; i < this.T.length; i++) {
            this.T[i].S = SB[i * 2];
            this.T[i].B = SB[i * 2 + 1];
        }

        this.P = P;
    }

    @Override
    public Prover Prover(Suite suite, Map<String, EdScalar> secrets,
                         Map<String, EdPoint> points, Map<Predicate, Integer> choice) {
        Proof prf = new Proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, EdPoint> points) {
        Proof prf = new Proof(suite, this);
        return prf.verifier(this, points);
    }

    // Return a string representation of this proof-of-representation predicate,
    // mainly for debugging.
    @Override
    public String String() {
        return this.precString(Constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.P + "=";
        for (int i = 0; i < this.T.length; i++) {
            if (i > 0) {
                s += "+";
            }
            Term t = this.T[i];
            s += t.S;
            s += "*";
            s += t.B;
        }
        return s;
    }

    @Override
    public void enumVars(Proof prf) {
        prf.enumPointVar(this.P);
        for (int i = 0; i < this.T.length; i++) {
            prf.enumScalarVar(this.T[i].S);
            prf.enumPointVar(this.T[i].B);
        }
    }

    @Override
    public void commit(Proof prf, EdScalar w, EdScalar[] pv) {

        // Create per-predicate prover state
        EdScalar[] v = prf.makeScalars(pv);
        ProverPred pp = new ProverPred(w, v, null);
        prf.pp.put(this, pp);

        // Compute commit V=wY+v1G1+...+vkGk
        EdPoint V = prf.s.Point();
        if (w != null) { // We're on a non-obligated branch
            V.Mul(w, prf.pval.get(this.P));
        }
        else { // We're on a proof-obligated branch, so w=0
            V.Null();
        }

        EdPoint P = prf.s.Point();
        for (int i = 0; i < this.T.length; i++) {
            Term t = this.T[i];     // current term
            int s = prf.sidx.get(t.S);

            // Choose a blinding secret the first time
            // we encounter each variable
            if (v[s] == null) {
                v[s] = prf.s.Scalar();
                v[s].Pick(new SecureRandom());
                prf.pc.PriRand(v[s]);
            }
            P.Mul(v[s], prf.pval.get(t.B));
            V.Add(V, P);
        }

        // Encode and send the commitment to the verifier
        prf.pc.Put(V);
    }

    @Override
    public void respond(Proof prf, EdScalar c, EdScalar[] pr) {

        ProverPred pp = prf.pp.get(this);

        // Create a response array for this OR-domain if not done already
        EdScalar[] r = prf.makeScalars(pr);

        for (int i = 0; i < this.T.length; i++) {
            Term t = this.T[i];         // current term
            int s = prf.sidx.get(t.S);

            // Produce a correct response for each variable
            // the first time we encounter that variable.
            if (r[s] == null) {
                if (pp.w != null) {
                    // We're on a non-proof-obligated branch:
                    // w was our challenge, v[s] is our response.
                    r[s] = pp.v[s];
                    continue;
                }

                // We're on a proof-obligated branch,
                // so we need to calculate the correct response
                // as r = v-cx where x is the secret variable
                EdScalar ri = prf.s.Scalar();
                ri.Mul(c, prf.sval.get(t.S));
                ri.Sub(pp.v[s], ri);
                r[s] = ri;
            }
        }

        // Send our responses if we created the array (i.e., if pr == nil)
        prf.sendResponses(pr, r);
    }

    @Override
    public void getCommits(Proof prf, EdScalar[] pr) {

        // Create per-predicate verifier state
        EdPoint V = prf.s.Point();
        EdScalar[] r = prf.makeScalars(pr);
        VerifierPred vp = new VerifierPred(V, r);
        prf.vp.put(this, vp);

        // Get the commitment for this representation
        prf.vc.Get(vp.v);

        // Fill in the r vector with the responses we'll need.
        for (int i = 0; i < this.T.length; i++) {
            Term t = this.T[i];
            int s = prf.sidx.get(t.S);
            if (r[s] == null) {
                r[s] = prf.s.Scalar();
                r[s].Pick(new SecureRandom());
            }
        }
    }

    @Override
    public void verify(Proof prf, EdScalar c, EdScalar[] pr) throws IllegalArgumentException {
        VerifierPred vp = prf.vp.get(this);
        EdScalar[] r = vp.r;

        // Get the needed responses if a parent didn't already
        prf.getResponses(pr, r);

        // Recompute commit V=cY+r1G1+...+rkGk
        EdPoint V = prf.s.Point();
        V.Mul(c, prf.pval.get(this.P));
        EdPoint P = prf.s.Point();
        for (int i = 0; i < this.T.length; i++) {
            Term t = this.T[i];             // current term
            int s = prf.sidx.get(t.S);
            P.Mul(r[s], prf.pval.get(t.B));
            V.Add(V, P);
        }

        if (!V.Equal(vp.v)) {
            throw new IllegalArgumentException("Invalid Proof: commit mismatch");
        }
    }
}

////////// And predicate //////////

// And predicate states that all the constituent sub-predicates are true.
// And predicates may contain Rep predicates and/or other And predicates.
class AndPred implements Predicate {

    public Predicate[] preds;

    public AndPred(Predicate... preds) {
        int l = preds.length;
        this.preds = new Predicate[l];
        for (int i = 0; i < l; i++)
            this.preds[i] = preds[i];
    }

    @Override
    public Prover Prover(Suite suite, Map<String, EdScalar> secrets,
                         Map<String, EdPoint> points, Map<Predicate, Integer> choice) {
        Proof prf = new Proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, EdPoint> points) {
        Proof prf = new Proof(suite, this);
        return prf.verifier(this, points);
    }

    // Return a string representation of this AND predicate, mainly for debugging.
    @Override
    public String String() {
        return this.precString(Constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.preds[0].precString(Constants.precAnd);
        for (int i = 1; i < this.preds.length; i++) {
            s = s + " && " + this.preds[i].precString(Constants.precAnd);
        }
        if (prec != Constants.precNone && prec != Constants.precAnd) {
            s = "(" + s + ")";
        }
        return s;
    }

    @Override
    public void enumVars(Proof prf) {
        for (int i = 0; i < preds.length; i++)
            this.preds[i].enumVars(prf);
    }

    @Override
    public void commit(Proof prf, EdScalar w, EdScalar[] pv) throws IllegalArgumentException {
        // Create per-predicate prover state
        EdScalar[] v = prf.makeScalars(pv);

        // Recursively generate commitments
        for (int i = 0; i < this.preds.length; i++) {
            try {
                this.preds[i].commit(prf, w, v);
            }
            catch (IllegalArgumentException E) {
                throw E;
            }
        }
    }

    @Override
    public void respond(Proof prf, EdScalar c, EdScalar[] pr) {
        EdScalar[] r = prf.makeScalars(pr);

        // Recursively compute responses in all sub-predicates
        for (int i = 0; i < this.preds.length; i++) {
            this.preds[i].respond(prf, c, r);
        }
        prf.sendResponses(pr, r);
    }

    @Override
    public void getCommits(Proof prf, EdScalar[] pr) {
        // Create per-predicate verifier state
        EdScalar[] r = prf.makeScalars(pr);
        VerifierPred vp = new VerifierPred(null, r);
        prf.vp.put(this, vp);

        for (int i = 0; i < this.preds.length; i++) {
            this.preds[i].getCommits(prf, r);
        }
    }

    @Override
    public void verify(Proof prf, EdScalar c, EdScalar[] pr) throws IllegalArgumentException {
        VerifierPred vp = prf.vp.get(this);
        EdScalar[] r = vp.r;

        prf.getResponses(pr, r);

        for (int i = 0; i < this.preds.length; i++) {
            try {
                this.preds[i].verify(prf, c, r);
            }
            catch (IllegalArgumentException E) {
                throw E;
            }
        }
    }
}

////////// Or predicate //////////

// Or predicate states that the prover knows
// at least one of the sub-predicates to be true,
// but the proof does not reveal any information about which.
class OrPred implements Predicate {

    public Predicate[] preds;

    @Override
    public Prover Prover(Suite suite, Map<String, EdScalar> secrets,
                         Map<String, EdPoint> points, Map<Predicate, Integer> choice) {
        Proof prf = new Proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, EdPoint> points) {
        Proof prf = new Proof(suite, this);
        return prf.verifier(this, points);
    }

    // Return a string representation of this OR predicate, mainly for debugging.
    @Override
    public String String() {
        return this.precString(Constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.preds[0].precString(Constants.precOr);
        for (int i = 1; i < this.preds.length; i++) {
            s = s + "||" + this.preds[i].precString(Constants.precOr);
        }

        if (prec != Constants.precOr && prec != Constants.precNone) {
            s = "(" + s + ")";
        }
        return s;
    }

    @Override
    public void enumVars(Proof prf) {
        for (int i = 0; i < this.preds.length; i++) {
            this.preds[i].enumVars(prf);
        }
    }

    @Override
    public void commit(Proof prf, EdScalar w, EdScalar[] pv) throws IllegalArgumentException {
        if (pv != null) {   // only happens within an AND expression
            throw new IllegalArgumentException("Can't have OR predicates within AND predicates");
        }

        // Create per-predicate prover state
        EdScalar[] wi = new EdScalar[this.preds.length];
        ProverPred pp = new ProverPred(w, null, wi);
        prf.pp.put(this, pp);

        // Choose pre-challenges for our subs.
        if (w == null) {
            // We're on a proof-obligated branch;
            // choose random pre-challenges for only non-obligated subs.
            if (!prf.choice.containsKey(this)) {
                throw new IllegalArgumentException("No choice of proof branch for OR-predicate " + this.String());
            }

            int choice = prf.choice.get(this);
            if (choice < 0 || choice >= this.preds.length) {
                throw new IllegalArgumentException("No choice of proof branch for OR-predicate " + this.String());
            }

            for (int i = 0; i < this.preds.length; i++) {
                if (i != choice) {
                    wi[i] = prf.s.Scalar();
                    wi[i].Pick(new SecureRandom());
                    prf.pc.PriRand(wi[i]);
                } // else wi[i] == nil for proof-obligated sub
            }
        }
        else {
            // Since w != nil, we're in a non-obligated branch,
            // so choose random pre-challenges for all subs
            // such that they add up to the master pre-challenge w.
            int last = this.preds.length - 1;
            EdScalar wl = prf.s.Scalar().Set(w);

            for (int i = 0; i < last; i++) {
                wi[i] = prf.s.Scalar();
                wi[i].Pick(new SecureRandom());
                prf.pc.PriRand(wi[i]);
                wl.Sub(wl, wi[i]);
            }
            wi[last] = wl;
        }

        // Now recursively choose commitments within each sub
        for (int i = 0; i < this.preds.length; i++) {
            try {
                // Fresh variable-blinding secrets for each pre-commitment
                this.preds[i].commit(prf, wi[i], null);
            }
            catch (IllegalArgumentException E) {
                throw E;
            }
        }
    }

    @Override
    public void respond(Proof prf, EdScalar c, EdScalar[] pr) throws IllegalArgumentException {
        ProverPred pp = prf.pp.get(this);
        if (pr != null) {
            throw new IllegalArgumentException("OR predicate can't be nested in anything else");
        }

        EdScalar[] ci = pp.wi;
        if (pp.w == null) {
            // Calculate the challenge for the proof-obligated subtree
            EdScalar cs = prf.s.Scalar().Set(c);
            int choice = prf.choice.get(this);
            for (int i = 0; i < this.preds.length; i++) {
                if (i != choice) {
                    cs.Sub(cs, ci[i]);
                }
            }
            ci[choice] = cs;
        }

        // If there's more than one choice, send all our sub-challenges.
        if (this.preds.length > 1) {
            prf.pc.Put(ci);
        }

        // Recursively compute responses in all subtrees
        for (int i = 0; i < this.preds.length; i++) {
            try {
                this.preds[i].respond(prf, ci[i], null);
            }
            catch (IllegalArgumentException E) {
                throw E;
            }
        }
    }

    // Get from the verifier all the commitments needed for this predicate
    @Override
    public void getCommits(Proof prf, EdScalar[] r) {
        for (int i = 0; i < this.preds.length; i++) {
            this.preds[i].getCommits(prf, null);
        }
    }

    @Override
    public void verify(Proof prf, EdScalar c, EdScalar[] pr) throws IllegalArgumentException {
        if (pr != null) {
            throw new IllegalArgumentException("OR predicates can't be in anything else");
        }

        // Get the prover's sub-challenges
        int nsub = this.preds.length;
        EdScalar[] ci = new EdScalar[nsub];
        if (nsub > 1) {
            prf.vc.Get(ci);

            // Make sure they add up to the parent's composite challenge
            EdScalar csum = prf.s.Scalar().Zero();
            for (int i = 0; i < this.preds.length; i++) {
                csum.Add(csum, ci[i]);
            }
            if (!csum.Equal(c)) {
                throw new IllegalArgumentException("Invalid proof: Bad sub-challenges");
            }
        }
        else {  // trivial single-sub OR
            ci[0] = c;
        }

        // Recursively verify all subs
        for (int i = 0; i < this.preds.length; i++) {
            try {
                this.preds[i].verify(prf, ci[i], null);
            }
            catch (IllegalArgumentException E) {
                throw E;
            }
        }
    }
}
