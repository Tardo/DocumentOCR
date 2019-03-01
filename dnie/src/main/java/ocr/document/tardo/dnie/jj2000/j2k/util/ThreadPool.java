package jj2000.j2k.util;

public class ThreadPool {
    public static final String CONCURRENCY_PROP_NAME = "jj2000.j2k.util.ThreadPool.concurrency";
    private ThreadPoolThread[] idle;
    private int nidle;
    private String poolName;
    private int poolPriority;
    private volatile Error targetE;
    private volatile RuntimeException targetRE;

    class ThreadPoolThread extends Thread {
        private boolean doNotifyAll;
        private Object lock;
        private Runnable target;

        public ThreadPoolThread(int idx, String name) {
            super(name);
            setDaemon(true);
            setPriority(ThreadPool.this.poolPriority);
        }

        public void run() {
            ThreadPool.this.putInIdleList(this);
            synchronized (this) {
                while (true) {
                    if (this.target == null) {
                        try {
                            wait();
                        } catch (InterruptedException e) {
                        }
                    } else {
                        try {
                            this.target.run();
                        } catch (ThreadDeath td) {
                            FacilityManager.getMsgLogger().printmsg(2, "Thread.stop() called on a ThreadPool thread or ThreadDeath thrown. This is deprecated. Lock-up might occur.");
                            throw td;
                        } catch (Error e2) {
                            ThreadPool.this.targetE = e2;
                        } catch (RuntimeException re) {
                            ThreadPool.this.targetRE = re;
                        } catch (Throwable th) {
                            ThreadPool.this.targetRE = new RuntimeException("Unchecked exception thrown by target's run() method in pool " + ThreadPool.this.poolName + ".");
                        }
                        ThreadPool.this.putInIdleList(this);
                        this.target = null;
                        if (this.lock != null) {
                            synchronized (this.lock) {
                                if (this.doNotifyAll) {
                                    this.lock.notifyAll();
                                } else {
                                    this.lock.notify();
                                }
                            }
                        } else {
                            continue;
                        }
                    }
                }
            }
        }

        synchronized void setTarget(Runnable target, Object lock, boolean notifyAll) {
            this.target = target;
            this.lock = lock;
            this.doNotifyAll = notifyAll;
            notify();
        }
    }

    public ThreadPool(int size, int priority, String name) {
        if (size <= 0) {
            throw new IllegalArgumentException("Pool must be of positive size");
        }
        if (priority < 1) {
            this.poolPriority = Thread.currentThread().getPriority();
        } else {
            if (priority >= 10) {
                priority = 10;
            }
            this.poolPriority = priority;
        }
        if (name == null) {
            this.poolName = "Anonymous ThreadPool";
        } else {
            this.poolName = name;
        }
        String prop = System.getProperty(CONCURRENCY_PROP_NAME);
        if (prop != null) {
            try {
                int clevel = Integer.parseInt(prop);
                if (clevel < 0) {
                    throw new NumberFormatException();
                } else if (NativeServices.loadLibrary()) {
                    FacilityManager.getMsgLogger().printmsg(1, "Changing thread concurrency level from " + NativeServices.getThreadConcurrency() + " to " + clevel + ".");
                    NativeServices.setThreadConcurrency(clevel);
                } else {
                    FacilityManager.getMsgLogger().printmsg(2, "Native library to set thread concurrency level as specified by the jj2000.j2k.util.ThreadPool.concurrency property not found. Thread concurrency unchanged.");
                }
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException("Invalid concurrency level in property jj2000.j2k.util.ThreadPool.concurrency");
            }
        }
        this.idle = new ThreadPoolThread[size];
        this.nidle = 0;
        for (int i = 0; i < size; i++) {
            new ThreadPoolThread(i, this.poolName + "-" + i).start();
        }
    }

    public int getSize() {
        return this.idle.length;
    }

    public boolean runTarget(Runnable t, Object l) {
        return runTarget(t, l, false, false);
    }

    public boolean runTarget(Runnable t, Object l, boolean async) {
        return runTarget(t, l, async, false);
    }

    public boolean runTarget(Runnable t, Object l, boolean async, boolean notifyAll) {
        ThreadPoolThread runner = getIdle(async);
        if (runner == null) {
            return false;
        }
        runner.setTarget(t, l, notifyAll);
        return true;
    }

    public void checkTargetErrors() {
        if (this.targetE != null) {
            throw this.targetE;
        } else if (this.targetRE != null) {
            throw this.targetRE;
        }
    }

    public void clearTargetErrors() {
        this.targetE = null;
        this.targetRE = null;
    }

    private void putInIdleList(ThreadPoolThread t) {
        synchronized (this.idle) {
            this.idle[this.nidle] = t;
            this.nidle++;
            if (this.nidle == 1) {
                this.idle.notify();
            }
        }
    }

    private ThreadPoolThread getIdle(boolean async) {
        ThreadPoolThread threadPoolThread = null;
        synchronized (this.idle) {
            if (async) {
                if (this.nidle == 0) {
                }
                this.nidle--;
                threadPoolThread = this.idle[this.nidle];
            } else {
                while (this.nidle == 0) {
                    try {
                        this.idle.wait();
                    } catch (InterruptedException e) {
                    }
                }
                this.nidle--;
                threadPoolThread = this.idle[this.nidle];
            }
        }
        return threadPoolThread;
    }
}
