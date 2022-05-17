package ch.epfl.dedis.lib.crypto.bn256;

import java.util.LinkedList;

/**
 * This singleton class keeps a pool of different GFp. Instead of creating manually new GFp objects that will then
 * be eventually deleted by the GC, one can use this class which will keep no longer used objects and re-use them.
 * If the pool is empty a new object is created. Re-used object are not initialized !
 */
class GFpPool {
    private static GFpPool ourInstance = new GFpPool();

    public static GFpPool getInstance() {
        return ourInstance;
    }

    private GFpPool() { }

    public GFp2  get2()  { return (GFp2)  get(gfp2Pool);  }
    public GFp6  get6()  { return (GFp6)  get(gfp6Pool);  }
    public GFp12 get12() { return (GFp12) get(gfp12Pool); }

    public void put2 (GFp2... gFp2s)   { put(gfp2Pool, (Object[]) gFp2s);  }
    public void put6 (GFp6... gFp6s)   { put(gfp6Pool, (Object[]) gFp6s);  }
    public void put12(GFp12... gFp12s) { put(gfp12Pool, (Object[]) gFp12s); }

    public int getC2()  { return gfp2Pool.count;  }
    public int getC6()  { return gfp6Pool.count;  }
    public int getC12() { return gfp12Pool.count; }

    private Object get(Pool pool) {
        pool.count++;
        if(pool.cache.isEmpty())
            return pool.create();

        return pool.cache.pop();
    }

    private void put(Pool pool, Object... gfps) {
        for(Object gfp : gfps) {
            pool.cache.add(gfp);
            pool.count--;
        }
    }

    private abstract class Pool<E> {
        public LinkedList<E> cache = new LinkedList<>();
        public int count = 0;
        public abstract Object create();
    }

    private Pool gfp2Pool = new Pool<GFp2>() {
        @Override
        public GFp2 create() {
            return new GFp2();
        }
    };

    private Pool gfp6Pool = new Pool<GFp6>() {
        @Override
        public GFp6 create() {
            return new GFp6();
        }
    };

    private Pool gfp12Pool = new Pool<GFp12>() {
        @Override
        public GFp12 create() {
            return new GFp12();
        }
    };
}
