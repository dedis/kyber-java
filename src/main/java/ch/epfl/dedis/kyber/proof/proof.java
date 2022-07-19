package ch.epfl.dedis.kyber.proof;

import ch.epfl.dedis.kyber.Point;
import ch.epfl.dedis.kyber.Scalar;
import ch.epfl.dedis.kyber.Suite;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class proof {
    Suite s;

    int nsvars;
    int npvars;
    ArrayList<String> svar, pvar;
    Map<String, Integer> sidx, pidx;

    Map<String, Point> pval;
    Map<String, Scalar> sval;

    ProverContext pc;
    Map<Predicate, Integer>  choice;
    Map<Predicate, proverPred> pp;

    VerifierContext vc;
    Map<Predicate, verifierPred> vp;

    public proof(Suite suite, Predicate pred) {
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

    public Scalar[] makeScalars(Scalar[] pr) {
        if (pr == null)
            return new Scalar[this.nsvars];
        else
            return pr;
    }

    public Exception sendResponses(Scalar[] pr, Scalar[] r) {
        if (pr == null) {
            for(int i = 0; i < r.length; i++) {
                // Send responses only for variables
                // that were used in this OR-domain.
                if(r[i] != null) {
                    Exception e = this.pc.Put(r[i]);
                    if (e != null)
                        return e;
                }
            }
        }
        return null;
    }

    // In the verifier, get the responses at the top of an OR-domain,
    // if a corresponding makeScalars() call created it.

    public Exception getResponses(Scalar[] pr, Scalar[] r) {
        if (pr == null) {
            for(int i = 0; i < r.length; i++) {
                if(r[i] != null) {
                    Exception e = this.vc.Get(r[i]);
                    if (e != null)
                        return e;
                }
            }
        }
        return null;
    }

    public Exception prove(Predicate p, Map<String, Scalar> sval,
                           Map<String, Point> pval, Map<Predicate, Integer> choice, ProverContext pc) {
        this.pc = pc;
        this.sval = sval;
        this.pval = pval;
        this.choice = choice;
        this.pp = new HashMap<Predicate, proverPred>();

        Exception e = p.commit(this, null, null);
        if(e != null) {
            return e;
        }

        Scalar c = this.s.Scalar();
        e = pc.PubRand(c);

        if(e != null)
            return e;

        return p.respond(this, c, null);
    }

    public Exception verify(Predicate p, Map<String, Point> pval, VerifierContext vc) {
        this.vc = vc;
        this.pval = pval;
        this.vp = new HashMap<Predicate, verifierPred>();

        Exception e = p.getCommits(this, null);
        if(e != null)
            return e;

        Scalar c = this.s.Scalar();
        e = vc.PubRand(c);
        if(e != null)
            return e;

        return p.verify(this, c, null);
    }

    public Prover prover(Predicate p, Map<String, Scalar> sval,
                         Map<String, Point> pval, Map<Predicate, Integer> choice) {
        classProver cp = new classProver(this, p, sval, pval, choice);
        return cp;
    }

    public Verifier verifier(Predicate p, Map<String, Point> pval) {
        classVerifier cv = new classVerifier(this, p, pval);
        return cv;
    }
}

class classProver implements Prover {

    proof prf;
    Predicate p;
    Map<String, Scalar> sval;
    Map<String, Point> pval;
    Map<Predicate, Integer> choice;

    public classProver(proof prf, Predicate p, Map<String, Scalar> sval,
                       Map<String, Point> pval, Map<Predicate, Integer> choice){
        this.prf = prf;
        this.p = p;
        this.sval = sval;
        this.pval = pval;
        this.choice = choice;
    }

    @Override
    public Exception prove(ProverContext ctx) {
        return this.prf.prove(this.p, this.sval, this.pval, this.choice, ctx);
    }
}

class classVerifier implements Verifier{

    proof prf;
    Predicate p;
    Map<String, Point> pval;

    public classVerifier(proof prf, Predicate p, Map<String, Point> pval){
        this.prf = prf;
        this.p = p;
        this.pval = pval;
    }

    @Override
    public Exception verify(VerifierContext ctx) {
        return this.prf.verify(this.p, this.pval, ctx);
    }
}

class proverPred {
    Scalar w;    // secret pre-challenge
    Scalar[] v;  // secret blinding factor for each variable
    Scalar[] wi; // OR predicates: individual sub-challenges

    public proverPred(Scalar w, Scalar[] v, Scalar[] wi){
        this.w = w;
        this.v = v;
        this.wi = wi;
    }
}

class verifierPred {
    public Point v;     // public commitment produced by verifier
    public Scalar[] r;  // per-variable responses produced by verifier

    public verifierPred(Point v, Scalar[] r) {
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
class term {
    String S; // Scalar multiplier for this term
    String B; // Generator for this term
}

class repPred implements Predicate {
    String P; // Public point of which a representation is known
    term[] T; // Public point of which a representation is known

    public repPred(String P, String... SB) throws Exception {
        if ((SB.length & 1) != 0)
            throw new Exception("mismatched Scalar");

        this.T = new term[SB.length / 2];
        for(int i = 0; i < this.T.length; i++) {
            this.T[i].S = SB[i*2];
            this.T[i].B = SB[i*2 + 1];
        }

        this.P = P;
    }

    @Override
    public Prover Prover(Suite suite, Map<String, Scalar> secrets,
                         Map<String, Point> points, Map<Predicate, Integer> choice) {
        proof prf = new proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, Point> points) {
        proof prf = new proof(suite, this);
        return prf.verifier(this, points);
    }

    @Override
    public String String() {
        return this.precString(constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.P + "=";
        for (int i = 0; i < this.T.length; i++) {
            if (i > 0) {
                s += "+";
            }
            term t = this.T[i];
            s += t.S;
            s += "*";
            s += t.B;
        }
        return s;
    }

    @Override
    public void enumVars(proof prf) {
        prf.enumPointVar(this.P);
        for(int i = 0; i < this.T.length; i++) {
            prf.enumScalarVar(this.T[i].S);
            prf.enumPointVar(this.T[i].B);
        }
    }

    @Override
    public Exception commit(proof prf, Scalar w, Scalar[] pv) {

        Scalar[] v = prf.makeScalars(pv);
        proverPred pp = new proverPred(w, v, null);
        prf.pp.put(this, pp);

        Point V = prf.s.Point();
        if(w != null) {
            V.Mul(w, prf.pval.get(this.P));
        }
        else {
            V.Null();
        }

        Point P = prf.s.Point();
        for(int i = 0; i < this.T.length; i++) {
            term t = this.T[i];
            int s = prf.sidx.get(t.S);

            if(v[s] == null) {
                v[s] = prf.s.Scalar();
                v[s].Pick(new SecureRandom());
                prf.pc.PriRand(v[s]);
            }
            P.Mul(v[s], prf.pval.get(t.B));
            V.Add(V, P);
        }

        return prf.pc.Put(V);
    }

    @Override
    public Exception respond(proof prf, Scalar c, Scalar[] pr) {

        proverPred pp = prf.pp.get(this);
        Scalar[] r = prf.makeScalars(pr);

        for(int i = 0; i < this.T.length; i++) {
            term t = this.T[i];
            int s = prf.sidx.get(t.S);

            if(r[s] == null) {
                if (pp.w != null) {
                    r[s] = pp.v[s];
                    continue;
                }

                Scalar ri = prf.s.Scalar();
                ri.Mul(c, prf.sval.get(t.S));
                ri.Sub(pp.v[s], ri);
                r[s]=  ri;
            }
        }

        return prf.sendResponses(pr, r);
    }

    @Override
    public Exception getCommits(proof prf, Scalar[] pr) {

        Point V = prf.s.Point();
        Scalar[] r = prf.makeScalars(pr);
        verifierPred vp = new verifierPred(V, r);
        prf.vp.put(this, vp);

        Exception e = prf.vc.Get(vp.v);
        if(e != null)
            return e;

        for (int i = 0; i < this.T.length; i++) {
            term t = this.T[i];
            int s = prf.sidx.get(t.S);
            if(r[s] == null) {
                r[s] = prf.s.Scalar();
                r[s].Pick(new SecureRandom());
            }
        }

        return null;
    }

    @Override
    public Exception verify(proof prf, Scalar c, Scalar[] pr) {
        verifierPred vp = prf.vp.get(this);
        Scalar[] r = vp.r;

        Exception e = prf.getResponses(pr, r);
        if(e != null) {
            return e;
        }

        Point V = prf.s.Point();
        V.Mul(c, prf.pval.get(this.P));
        Point P = prf.s.Point();
        for(int i = 0; i < this.T.length; i++) {
            term t = this.T[i];
            int s = prf.sidx.get(t.S);
            P.Mul(r[s], prf.pval.get(t.B));
            V.Add(V, P);
        }

        if (! V.Equal(vp.v))
            return new Exception("Invalid Proof: commit mismatch");

        return null;
    }
}

////////// And predicate //////////

class andPred implements Predicate {

    public Predicate[] preds;

    public andPred(Predicate... preds) {
        int l = preds.length;
        this.preds = new Predicate[l];
        for(int i = 0; i < l ; i++)
            this.preds[i] = preds[i];
    }

    @Override
    public Prover Prover(Suite suite, Map<String, Scalar> secrets,
                         Map<String, Point> points, Map<Predicate, Integer> choice) {
        proof prf = new proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, Point> points) {
        proof prf = new proof(suite, this);
        return prf.verifier(this, points);
    }

    @Override
    public String String() {
        return this.precString(constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.preds[0].precString(constants.precAnd);
        for(int i = 1; i < this.preds.length; i++) {
            s = s + " && " + this.preds[i].precString(constants.precAnd);
        }
        if (prec != constants.precNone && prec != constants.precAnd) {
            s = "(" + s + ")";
        }
        return s;
    }

    @Override
    public void enumVars(proof prf) {
        for (int i = 0; i < preds.length; i++)
            this.preds[i].enumVars(prf);
    }

    @Override
    public Exception commit(proof prf, Scalar w, Scalar[] pv) {
        Scalar[] v = prf.makeScalars(pv);

        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].commit(prf, w, v);
            if (e != null)
                return e;
        }

        return null;
    }

    @Override
    public Exception respond(proof prf, Scalar c, Scalar[] pr) {
        Scalar[] r = prf.makeScalars(pr);
        for(int i = 0; i < this.preds.length; i++){
            Exception e = this.preds[i].respond(prf, c, r);
            if(e != null)
                return e;
        }
        return prf.sendResponses(pr, r);
    }

    @Override
    public Exception getCommits(proof prf, Scalar[] pr) {
        Scalar[] r = prf.makeScalars(pr);
        verifierPred vp = new verifierPred(null, r);
        prf.vp.put(this, vp);

        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].getCommits(prf, r);
            if (e != null)
                return e;
        }

        return null;
    }

    @Override
    public Exception verify(proof prf, Scalar c, Scalar[] pr) {
        verifierPred vp = prf.vp.get(this);
        Scalar[] r = vp.r;

        Exception e = prf.getResponses(pr, r);
        if(e != null){
            return e;
        }

        for(int i = 0; i < this.preds.length; i++) {
            e = this.preds[i].verify(prf, c, r);
            if (e != null)
                return e;
        }
        return null;
    }
}

////////// Or predicate //////////

class orPred implements Predicate {

    public Predicate[] preds;

    @Override
    public Prover Prover(Suite suite, Map<String, Scalar> secrets,
                         Map<String, Point> points, Map<Predicate, Integer> choice) {
        proof prf = new proof(suite, this);
        return prf.prover(this, secrets, points, choice);
    }

    @Override
    public Verifier Verifier(Suite suite, Map<String, Point> points) {
        proof prf = new proof(suite, this);
        return prf.verifier(this, points);
    }

    @Override
    public String String() {
        return this.precString(constants.precNone);
    }

    @Override
    public String precString(int prec) {
        String s = this.preds[0].precString(constants.precOr);
        for(int i = 1; i < this.preds.length; i++){
            s = s + "||" + this.preds[i].precString(constants.precOr);
        }

        if (prec != constants.precOr && prec != constants.precNone) {
            s = "(" + s + ")";
        }
        return s;
    }

    @Override
    public void enumVars(proof prf) {
        for(int i = 0; i < this.preds.length; i++) {
            this.preds[i].enumVars(prf);
        }
    }

    @Override
    public Exception commit(proof prf, Scalar w, Scalar[] pv) {
        if (pv != null) {
            return new Exception("Can't have OR predicates within AND predicates");
        }

        Scalar[] wi = new Scalar[this.preds.length];
        proverPred pp = new proverPred(w, null, wi);
        prf.pp.put(this, pp);

        if (w == null) {
            if(!prf.choice.containsKey(this)){
                return new Exception("No choice of proof branch for OR-predicate " + this.String());
            }

            int choice = prf.choice.get(this);
            if(choice < 0 || choice >= this.preds.length){
                return new Exception("No choice of proof branch for OR-predicate " + this.String());
            }

            for(int i = 0; i < this.preds.length; i++) {
                if(i != choice) {
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
            Scalar wl = prf.s.Scalar().Set(w);

            for(int i = 0; i < last; i++) {
                wi[i] = prf.s.Scalar();
                wi[i].Pick(new SecureRandom());
                prf.pc.PriRand(wi[i]);
                wl.Sub(wl, wi[i]);
            }
            wi[last] = wl;
        }

        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].commit(prf, wi[i], null);
            if(e != null)
                return e;
        }

        return null;
    }

    @Override
    public Exception respond(proof prf, Scalar c, Scalar[] pr) {
        proverPred pp = prf.pp.get(this);
        if(pr != null)
            return new Exception("OR predicate can't be nested in anything else");

        Scalar[] ci = pp.wi;
        if(pp.w == null) {
            Scalar cs = prf.s.Scalar().Set(c);
            int choice = prf.choice.get(this);
            for(int i = 0; i < this.preds.length; i++) {
                if (i != choice) {
                    cs.Sub(cs, ci[i]);
                }
            }
            ci[choice] = cs;
        }

        if (this.preds.length > 1) {
            Exception e = prf.pc.Put(ci);
            if(e != null)
                return e;
        }

        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].respond(prf, ci[i], null);
            if (e != null)
                return e;
        }

        return null;
    }

    @Override
    public Exception getCommits(proof prf, Scalar[] r) {
        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].getCommits(prf, null);
            if(e != null)
                return e;
        }
        return null;
    }

    @Override
    public Exception verify(proof prf, Scalar c, Scalar[] pr) {
        if(pr != null)
            return new Exception("OR predicates can't be in anything else");

        int nsub = this.preds.length;
        Scalar[] ci = new Scalar[nsub];
        if (nsub > 1) {
            Exception e = prf.vc.Get(ci);
            if (e != null)
                return e;

            Scalar csum = prf.s.Scalar().Zero();
            for(int i = 0; i < this.preds.length; i++) {
                csum.Add(csum, ci[i]);
            }
            if (!csum.Equal(c))
                return new Exception("Invalid proof: Bad sub-challenges");
        }
        else
            ci[0] = c;

        for(int i = 0; i < this.preds.length; i++) {
            Exception e = this.preds[i].verify(prf, ci[i], null);
            if(e != null)
                return e;
        }
        return null;
    }
}
