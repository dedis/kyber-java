package ch.epfl.dedis.kyber;

// Suite is the sum of all suites mix-ins in Kyber.
public interface Suite extends RandomGen, Group, HashFactory, XOFFactory{
}
