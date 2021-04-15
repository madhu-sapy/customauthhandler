package com.shell.b2b.cq.common.cacheMap;

import java.util.ArrayList;
import java.util.Set;

import org.apache.commons.collections.MapIterator;
import org.apache.commons.collections.map.LRUMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LRUMapWithExpiry<K, T> {

    private static final Logger LOG = LoggerFactory.getLogger(LRUMapWithExpiry.class);
    private long timeToLive;
    private LRUMap cacheLRUMap;

    protected class CacheObject {
        public long lastAccessed = System.currentTimeMillis();
        public T value;

        protected CacheObject(T value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return "CacheObject [lastAccessed=" + lastAccessed + ", value=" + value + "]";
        }
    }

    public LRUMapWithExpiry(long configuredTimeToLive, final long dameonThreadTimerInterval, int maxItems) {
        this.timeToLive = configuredTimeToLive * 1000;

        cacheLRUMap = new LRUMap(maxItems);

        if (timeToLive > 0 && dameonThreadTimerInterval > 0) {

            Thread t = new Thread(new Runnable() {
                public void run() {
                    while (true) {
                        try {
                            Thread.sleep(dameonThreadTimerInterval * 1000);
                        } catch (InterruptedException ex) {
                        }
                        cleanup();
                    }
                }
            });

            t.setDaemon(true);
            t.start();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("TOMCAT MEMORY CACHE Started Successfully.");
            LOG.debug("TOMCAT MEMORY CACHE SIZE = " + cacheLRUMap.size());
        }
    }

    public void put(K key, T value) {
        synchronized (cacheLRUMap) {
            cacheLRUMap.put(key, new CacheObject(value));
        }
    }

    @SuppressWarnings("unchecked")
    public T get(K key) {
        synchronized (cacheLRUMap) {
            CacheObject c = (CacheObject) cacheLRUMap.get(key);

            if (c == null)
                return null;
            else {
                c.lastAccessed = System.currentTimeMillis();
                return c.value;
            }
        }
    }

    public void remove(K key) {
        synchronized (cacheLRUMap) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("REMOVING KEY : " + key + " FROM TOMCAT MEMORY CACHE");
            }
            cacheLRUMap.remove(key);
        }
    }

    public int size() {
        synchronized (cacheLRUMap) {
            return cacheLRUMap.size();
        }
    }

    public void removeAll() {
        synchronized (cacheLRUMap) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CLEANING TOMCAT MEMORY CACHE");
            }
            cacheLRUMap.clear();
            if (LOG.isDebugEnabled()) {
                LOG.debug("TOMCAT MEMORY CACHE SIZE AFTER CLEAN UP = " + cacheLRUMap.size());
            }
        }
    }

    public Set<?> keySet() {
        return cacheLRUMap.keySet();
    }

    @SuppressWarnings("unchecked")
    public void cleanup() {

        long now = System.currentTimeMillis();
        ArrayList<K> deleteKey = null;

        synchronized (cacheLRUMap) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("CURRENT ITEMS IN CACHE : " + cacheLRUMap.toString());
                LOG.debug("TOMCAT MEMORY CACHE SIZE BEFORE CLEAN UP = " + cacheLRUMap.size());
            }
            MapIterator itr = cacheLRUMap.mapIterator();

            deleteKey = new ArrayList<K>((cacheLRUMap.size() / 2) + 1);
            K key = null;
            CacheObject c = null;

            while (itr.hasNext()) {
                key = (K) itr.next();
                c = (CacheObject) itr.getValue();

                if (c != null && (now > (timeToLive + c.lastAccessed))) {
                    deleteKey.add(key);
                }
            }
        }

        for (K key : deleteKey) {
            synchronized (cacheLRUMap) {
                cacheLRUMap.remove(key);
            }

            Thread.yield();
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("TOMCAT MEMORY CACHE SIZE AFTER CLEAN UP = " + cacheLRUMap.size());
        }
    }
}