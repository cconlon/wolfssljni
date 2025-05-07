import javax.net.ssl.*;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.ServerSocketChannel;
import java.nio.channels.SocketChannel;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Benchmark example for JSSE providers, measuring TLS handshake time
 * and throughput for both client and server using SSLSocket and SSLEngine.
 */
public class JSSEBenchmark {

    private static final int PORT = 11112;
    private static final int DATA_SIZE = 131072; /* 128KB */
    private static final int CHUNK_SIZE = 4096;  /* 4KB chunks */
    private static final int WARMUP_ITERATIONS = 5;
    private static final int BENCHMARK_ITERATIONS = 10;
    private static final String DEFAULT_PROVIDER = "wolfJSSE";
    private static final String KEYSTORE_PASSWORD = "wolfSSL test";
    private static String providerName = DEFAULT_PROVIDER;
    private static final int BUFFER_SIZE = 16384;     /* 16KB buffer size */
    private static final int MAX_BUFFER_SIZE = 65536; /* 64KB max buffer size */
    private static final int MAX_RETRIES = 10;
    private static final long RETRY_DELAY_MS = 50;
    private static final int READ_TIMEOUT_MS = 30000;  /* 30s timeout */
    private static final int WRITE_TIMEOUT_MS = 30000; /* 30s timeout */
    private static final int MAX_READ_RETRIES = 20;
    private static final int MAX_WRITE_RETRIES = 20;

    public static void main(String[] args) {
        try {
            parseArguments(args);
            configureProvider();
            runBenchmark();
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void parseArguments(String[] args) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals("-provider") && i + 1 < args.length) {
                providerName = args[++i];
            }
        }
        System.out.println("Using provider: " + providerName);
    }

    private static void configureProvider() throws Exception {
        if (providerName.equals("wolfJSSE")) {
            Security.addProvider(
                new com.wolfssl.provider.jsse.WolfSSLProvider());
        }
    }

    private static KeyStore loadKeyStore(String path, String password)
        throws Exception {

        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path)) {
            keyStore.load(fis, password.toCharArray());
        }
        return keyStore;
    }

    private static KeyStore loadTrustStore(String path, String password)
        throws Exception {

        KeyStore trustStore = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(path)) {
            trustStore.load(fis, password.toCharArray());
        }
        return trustStore;
    }

    /**
     * Custom KeyManager to enforce specific alias selection
     */
    static class AliasSelectingKeyManager implements X509KeyManager {
        private final X509KeyManager baseKeyManager;
        private final String alias;

        AliasSelectingKeyManager(X509KeyManager baseKeyManager, String alias) {
            this.baseKeyManager = baseKeyManager;
            this.alias = alias;
        }

        @Override
        public String chooseClientAlias(String[] keyType,
            java.security.Principal[] issuers, Socket socket) {
            return alias;
        }

        @Override
        public String chooseServerAlias(String keyType,
            java.security.Principal[] issuers, Socket socket) {
            return alias;
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            return baseKeyManager.getCertificateChain(alias);
        }

        @Override
        public String[] getClientAliases(String keyType,
            java.security.Principal[] issuers) {
            return baseKeyManager.getClientAliases(keyType, issuers);
        }

        @Override
        public String[] getServerAliases(String keyType,
            java.security.Principal[] issuers) {
            return baseKeyManager.getServerAliases(keyType, issuers);
        }

        @Override
        public java.security.PrivateKey getPrivateKey(String alias) {
            return baseKeyManager.getPrivateKey(alias);
        }
    }

    private static SSLContext createSSLContext(String role) throws Exception {
        String keyStorePath = role.equals("server") ?
            "../provider/server.jks" : "../provider/client.jks";
        String trustStorePath = role.equals("server") ?
            "../provider/ca-client.jks" : "../provider/ca-server.jks";
        String alias = role;

        KeyStore keyStore = loadKeyStore(keyStorePath, KEYSTORE_PASSWORD);
        KeyStore trustStore = loadTrustStore(trustStorePath, KEYSTORE_PASSWORD);

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, KEYSTORE_PASSWORD.toCharArray());

        /* Wrap the KeyManager to enforce alias selection */
        KeyManager[] keyManagers = kmf.getKeyManagers();
        for (int i = 0; i < keyManagers.length; i++) {
            if (keyManagers[i] instanceof X509KeyManager) {
                keyManagers[i] = new AliasSelectingKeyManager(
                    (X509KeyManager)keyManagers[i], alias);
            }
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext ctx = SSLContext.getInstance("TLS", providerName);
        ctx.init(keyManagers, tmf.getTrustManagers(), null);
        return ctx;
    }

    private static void runBenchmark() throws Exception {
        /* SSLSocket Benchmark */
        System.out.println("Running SSLSocket Benchmark...");
        Server socketServer = new Server();
        Client socketClient = new Client();

        ExecutorService socketExecutor = Executors.newFixedThreadPool(2);
        try {
            /* Start server */
            socketExecutor.submit(socketServer);

            /* Wait briefly to ensure server is ready */
            Thread.sleep(100);

            /* Run client */
            socketExecutor.submit(socketClient);

            /* Wait for completion */
            socketExecutor.shutdown();
            if (!socketExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
                System.err.println(
                    "SSLSocket benchmark timed out, forcing shutdown");
                socketExecutor.shutdownNow();
            }
        } finally {
            if (!socketExecutor.isTerminated()) {
                socketExecutor.shutdownNow();
            }
        }

        /* Print SSLSocket results */
        System.out.println("\nSSLSocket Benchmark Results:");
        System.out.println("Provider: " + providerName);
        System.out.printf("Server Handshake Time: %.2f ms (avg)\n",
            socketServer.avgHandshakeTime);
        System.out.printf("Client Handshake Time: %.2f ms (avg)\n",
            socketClient.avgHandshakeTime);
        System.out.printf("Server Send Throughput: %.2f MB/s (avg)\n",
            socketServer.avgSendThroughput);
        System.out.printf("Server Receive Throughput: %.2f MB/s (avg)\n",
            socketServer.avgReceiveThroughput);
        System.out.printf("Client Send Throughput: %.2f MB/s (avg)\n",
            socketClient.avgSendThroughput);
        System.out.printf("Client Receive Throughput: %.2f MB/s (avg)\n",
            socketClient.avgReceiveThroughput);

        /* Wait for a bit to ensure all resources are cleaned up */
        Thread.sleep(1000);

        /* SSLEngine Benchmark */
        System.out.println("\nRunning SSLEngine Benchmark...");
        EngineServer engineServer = new EngineServer();
        EngineClient engineClient = new EngineClient();

        ExecutorService engineExecutor = Executors.newFixedThreadPool(2);
        try {
            /* Start server */
            Future<?> serverFuture = engineExecutor.submit(engineServer);

            /* Wait briefly to ensure server is ready */
            Thread.sleep(100);

            /* Run client */
            Future<?> clientFuture = engineExecutor.submit(engineClient);

            /* Wait for completion with timeout */
            engineExecutor.shutdown();
            if (!engineExecutor.awaitTermination(60, TimeUnit.SECONDS)) {
                System.err.println(
                    "SSLEngine benchmark timed out, forcing shutdown");
                serverFuture.cancel(true);
                clientFuture.cancel(true);
                engineExecutor.shutdownNow();
            }
        } finally {
            if (!engineExecutor.isTerminated()) {
                engineExecutor.shutdownNow();
            }
        }

        /* Print SSLEngine results */
        System.out.println("\nSSLEngine Benchmark Results:");
        System.out.println("Provider: " + providerName);
        System.out.printf("Server Handshake Time: %.2f ms (avg)\n",
            engineServer.avgHandshakeTime);
        System.out.printf("Client Handshake Time: %.2f ms (avg)\n",
            engineClient.avgHandshakeTime);
        System.out.printf("Server Send Throughput: %.2f MB/s (avg)\n",
            engineServer.avgSendThroughput);
        System.out.printf("Server Receive Throughput: %.2f MB/s (avg)\n",
            engineServer.avgReceiveThroughput);
        System.out.printf("Client Send Throughput: %.2f MB/s (avg)\n",
            engineClient.avgSendThroughput);
        System.out.printf("Client Receive Throughput: %.2f MB/s (avg)\n",
            engineClient.avgReceiveThroughput);
    }

    static class Server implements Runnable {
        private double avgHandshakeTime = 0.0;
        private double avgSendThroughput = 0.0;
        private double avgReceiveThroughput = 0.0;

        @Override
        public void run() {
            try {
                SSLContext ctx = createSSLContext("server");
                SSLServerSocketFactory factory = ctx.getServerSocketFactory();
                try (SSLServerSocket serverSocket =
                    (SSLServerSocket)factory.createServerSocket(PORT)) {
                    serverSocket.setNeedClientAuth(true);
                    runIterations(serverSocket);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void runIterations(SSLServerSocket serverSocket)
            throws Exception {

            double[] handshakeTimes = new double[BENCHMARK_ITERATIONS];
            double[] sendThroughputs = new double[BENCHMARK_ITERATIONS];
            double[] receiveThroughputs = new double[BENCHMARK_ITERATIONS];

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                try (SSLSocket clientSocket =
                    (SSLSocket)serverSocket.accept()) {
                    performHandshakeAndTransfer(clientSocket);
                }
            }

            /* Benchmark */
            for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
                try (SSLSocket clientSocket =
                    (SSLSocket)serverSocket.accept()) {

                    long startHandshake = System.nanoTime();
                    clientSocket.startHandshake();
                    long endHandshake = System.nanoTime();
                    handshakeTimes[i] =
                        (endHandshake - startHandshake) / 1_000_000.0; /* ms */

                    /* Receive data, metrics in sec and MB/s */
                    long startReceive = System.nanoTime();
                    InputStream in = clientSocket.getInputStream();
                    byte[] buffer = new byte[8192];
                    int totalRead = 0;
                    while (totalRead < DATA_SIZE) {
                        int read = in.read(buffer);
                        if (read == -1) break;
                        totalRead += read;
                    }
                    long endReceive = System.nanoTime();
                    double receiveTime =
                        (endReceive - startReceive) / 1_000_000_000.0;
                    receiveThroughputs[i] =
                        (DATA_SIZE / (1024.0 * 1024.0)) / receiveTime;

                    /* Send data, metrics in sec and MB/s */
                    long startSend = System.nanoTime();
                    OutputStream out = clientSocket.getOutputStream();
                    byte[] data = new byte[DATA_SIZE];
                    Arrays.fill(data, (byte) 'A');
                    out.write(data);
                    out.flush();
                    long endSend = System.nanoTime();
                    double sendTime = (endSend - startSend) / 1_000_000_000.0;
                    sendThroughputs[i] =
                        (DATA_SIZE / (1024.0 * 1024.0)) / sendTime;
                }
            }

            avgHandshakeTime =
                Arrays.stream(handshakeTimes).average().orElse(0.0);
            avgSendThroughput =
                Arrays.stream(sendThroughputs).average().orElse(0.0);
            avgReceiveThroughput =
                Arrays.stream(receiveThroughputs).average().orElse(0.0);
        }

        private void performHandshakeAndTransfer(SSLSocket socket)
            throws Exception {

            socket.startHandshake();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[8192];
            int totalRead = 0;
            while (totalRead < DATA_SIZE) {
                int read = in.read(buffer);
                if (read == -1) break;
                totalRead += read;
            }
            OutputStream out = socket.getOutputStream();
            byte[] data = new byte[DATA_SIZE];
            Arrays.fill(data, (byte) 'A');
            out.write(data);
            out.flush();
        }
    }

    static class Client implements Runnable {
        private double avgHandshakeTime = 0.0;
        private double avgSendThroughput = 0.0;
        private double avgReceiveThroughput = 0.0;

        @Override
        public void run() {
            try {
                SSLContext ctx = createSSLContext("client");
                SSLSocketFactory factory = ctx.getSocketFactory();
                runIterations(factory);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        private void runIterations(SSLSocketFactory factory) throws Exception {
            double[] handshakeTimes = new double[BENCHMARK_ITERATIONS];
            double[] sendThroughputs = new double[BENCHMARK_ITERATIONS];
            double[] receiveThroughputs = new double[BENCHMARK_ITERATIONS];

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS; i++) {
                try (SSLSocket socket =
                    (SSLSocket)factory.createSocket("localhost", PORT)) {
                    performHandshakeAndTransfer(socket);
                }
            }

            /* Benchmark */
            for (int i = 0; i < BENCHMARK_ITERATIONS; i++) {
                try (SSLSocket socket =
                    (SSLSocket) factory.createSocket("localhost", PORT)) {
                    long startHandshake = System.nanoTime();
                    socket.startHandshake();
                    long endHandshake = System.nanoTime();
                    handshakeTimes[i] =
                        (endHandshake - startHandshake) / 1_000_000.0; /* ms */

                    /* Send data, metrics in sec and MB/s */
                    long startSend = System.nanoTime();
                    OutputStream out = socket.getOutputStream();
                    byte[] data = new byte[DATA_SIZE];
                    Arrays.fill(data, (byte) 'B');
                    out.write(data);
                    out.flush();
                    long endSend = System.nanoTime();
                    double sendTime =
                        (endSend - startSend) / 1_000_000_000.0;
                    sendThroughputs[i] =
                        (DATA_SIZE / (1024.0 * 1024.0)) / sendTime;

                    /* Receive data, metrics in sec, MB/s */
                    long startReceive = System.nanoTime();
                    InputStream in = socket.getInputStream();
                    byte[] buffer = new byte[8192];
                    int totalRead = 0;
                    while (totalRead < DATA_SIZE) {
                        int read = in.read(buffer);
                        if (read == -1) break;
                        totalRead += read;
                    }
                    long endReceive = System.nanoTime();
                    double receiveTime =
                        (endReceive - startReceive) / 1_000_000_000.0;
                    receiveThroughputs[i] =
                        (DATA_SIZE / (1024.0 * 1024.0)) / receiveTime;
                }
            }

            avgHandshakeTime =
                Arrays.stream(handshakeTimes).average().orElse(0.0);
            avgSendThroughput =
                Arrays.stream(sendThroughputs).average().orElse(0.0);
            avgReceiveThroughput =
                Arrays.stream(receiveThroughputs).average().orElse(0.0);
        }

        private void performHandshakeAndTransfer(SSLSocket socket)
            throws Exception {

            socket.startHandshake();
            OutputStream out = socket.getOutputStream();
            byte[] data = new byte[DATA_SIZE];
            Arrays.fill(data, (byte) 'B');
            out.write(data);
            out.flush();
            InputStream in = socket.getInputStream();
            byte[] buffer = new byte[8192];
            int totalRead = 0;

            while (totalRead < DATA_SIZE) {
                int read = in.read(buffer);
                if (read == -1) break;
                totalRead += read;
            }
        }
    }

    private static class TransferResult {
        double sendThroughput;
        double receiveThroughput;

        TransferResult(double sendThroughput, double receiveThroughput) {
            this.sendThroughput = sendThroughput;
            this.receiveThroughput = receiveThroughput;
        }
    }

    private static TransferResult transferData(SSLEngine engine,
        SocketChannel channel, byte[] data, boolean isServer) throws Exception {

        /* Allocate buffers */
        ByteBuffer appData = ByteBuffer.allocateDirect(
            engine.getSession().getApplicationBufferSize());
        ByteBuffer netData = ByteBuffer.allocateDirect(
            engine.getSession().getPacketBufferSize());
        ByteBuffer peerAppData = ByteBuffer.allocateDirect(
            engine.getSession().getApplicationBufferSize());
        ByteBuffer peerNetData = ByteBuffer.allocateDirect(
            engine.getSession().getPacketBufferSize());

        int totalSent = 0;
        int totalReceived = 0;
        long startSendTime = System.nanoTime();
        long startReceiveTime = 0;
        long endSendTime = 0;
        long endReceiveTime = 0;

        try {
            /* First send our data */
            while (totalSent < DATA_SIZE) {
                /* Prepare chunk to send */
                int remaining = DATA_SIZE - totalSent;
                int chunkSize = Math.min(CHUNK_SIZE, remaining);
                appData.clear();
                appData.put(data, totalSent, chunkSize);
                appData.flip();

                /* Wrap and send the chunk */
                netData.clear();
                SSLEngineResult result = engine.wrap(appData, netData);

                /* Handle buffer overflow */
                if (result.getStatus() ==
                    SSLEngineResult.Status.BUFFER_OVERFLOW) {
                    netData = ByteBuffer.allocateDirect(
                        engine.getSession().getPacketBufferSize());
                    continue;
                }

                netData.flip();
                while (netData.hasRemaining()) {
                    int written = channel.write(netData);
                    if (written == -1) {
                        throw new IOException("Channel closed during write");
                    }
                    if (written == 0) {
                        Thread.sleep(RETRY_DELAY_MS);
                        continue;
                    }
                }

                totalSent += chunkSize;
            }
            endSendTime = System.nanoTime();

            /* Receive data */
            startReceiveTime = System.nanoTime();
            while (totalReceived < DATA_SIZE) {
                peerNetData.clear();
                int read = channel.read(peerNetData);
                if (read == -1) {
                    throw new IOException("Channel closed during read");
                }
                if (read == 0) {
                    Thread.sleep(RETRY_DELAY_MS);
                    continue;
                }

                peerNetData.flip();
                while (peerNetData.hasRemaining()) {
                    peerAppData.clear();
                    SSLEngineResult result =
                        engine.unwrap(peerNetData, peerAppData);

                    /* Handle buffer overflow/underflow */
                    if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        peerAppData = ByteBuffer.allocateDirect(
                            engine.getSession().getApplicationBufferSize());
                        continue;
                    } else if (result.getStatus() ==
                        SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        break;
                    }

                    if (result.getStatus() == SSLEngineResult.Status.OK) {
                        peerAppData.flip();
                        totalReceived += peerAppData.remaining();
                        peerAppData.position(peerAppData.limit());
                    }
                }
            }
            endReceiveTime = System.nanoTime();

            /* Calculate throughput (sec, MB/s) */
            double sendTime =
                (endSendTime - startSendTime) / 1_000_000_000.0;
            double receiveTime =
                (endReceiveTime - startReceiveTime) / 1_000_000_000.0;
            double sendThroughput =
                (DATA_SIZE / (1024.0 * 1024.0)) / sendTime;
            double receiveThroughput =
                (DATA_SIZE / (1024.0 * 1024.0)) / receiveTime;

            return new TransferResult(sendThroughput, receiveThroughput);

        } finally {
            /* Properly close the connection */
            engine.closeOutbound();
            while (!engine.isOutboundDone()) {
                netData.clear();
                SSLEngineResult result = engine.wrap(ByteBuffer.allocate(0), netData);
                netData.flip();
                while (netData.hasRemaining()) {
                    channel.write(netData);
                }
            }
            channel.close();
        }
    }

    static class EngineServer implements Runnable {
        private double avgHandshakeTime = 0.0;
        private double avgSendThroughput = 0.0;
        private double avgReceiveThroughput = 0.0;

        @Override
        public void run() {
            try {
                SSLContext ctx = createSSLContext("server");
                try (ServerSocketChannel serverChannel =
                    ServerSocketChannel.open()) {

                    serverChannel.bind(new InetSocketAddress(PORT + 1));
                    serverChannel.configureBlocking(true);
                    runIterations(ctx, serverChannel);
                }
            } catch (Exception e) {
                System.err.println("EngineServer failed: " + e.getMessage());
                e.printStackTrace();
            }
        }

        private void runIterations(SSLContext ctx,
            ServerSocketChannel serverChannel) throws Exception {

            double[] handshakeTimes = new double[BENCHMARK_ITERATIONS];
            double[] sendThroughputs = new double[BENCHMARK_ITERATIONS];
            double[] receiveThroughputs = new double[BENCHMARK_ITERATIONS];

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS &&
                    !Thread.currentThread().isInterrupted(); i++) {

                SocketChannel channel = null;
                SSLEngine engine = null;
                try {
                    channel = serverChannel.accept();
                    if (channel != null && channel.isOpen()) {
                        channel.socket().setSoTimeout(60000); /* 60s timeout */
                        engine = performHandshake(ctx, channel, true);
                        byte[] data = new byte[DATA_SIZE];
                        Arrays.fill(data, (byte) 'A');
                        transferData(engine, channel, data, true);
                    }
                } catch (Exception e) {
                    System.err.println(
                        "Warmup iteration " + i + " failed: " + e.getMessage());
                }
            }

            /* Benchmark */
            for (int i = 0; i < BENCHMARK_ITERATIONS &&
                    !Thread.currentThread().isInterrupted(); i++) {

                SocketChannel channel = null;
                SSLEngine engine = null;
                try {
                    channel = serverChannel.accept();
                    if (channel == null || !channel.isOpen()) {
                        System.err.println("Benchmark iteration " + i +
                            " failed: SocketChannel is null or closed");
                        continue;
                    }
                    channel.socket().setSoTimeout(60000); /* 60s timeout */
                    long startHandshake = System.nanoTime();
                    engine = performHandshake(ctx, channel, true);
                    long endHandshake = System.nanoTime();
                    handshakeTimes[i] =
                        (endHandshake - startHandshake) / 1_000_000.0; /* ms */

                    /* Log session state */
                    SSLSession session = engine.getSession();
                    System.out.println("Server session: CipherSuite = " +
                        session.getCipherSuite() + ", Protocol = " +
                        session.getProtocol());

                    byte[] data = new byte[DATA_SIZE];
                    Arrays.fill(data, (byte) 'A');
                    TransferResult result =
                        transferData(engine, channel, data, true);
                    sendThroughputs[i] = result.sendThroughput;
                    receiveThroughputs[i] = result.receiveThroughput;

                } catch (Exception e) {
                    System.err.println("Benchmark iteration " + i +
                        " failed: " + e.getMessage());
                }
            }

            avgHandshakeTime =
                Arrays.stream(handshakeTimes).average().orElse(0.0);
            avgSendThroughput =
                Arrays.stream(sendThroughputs).average().orElse(0.0);
            avgReceiveThroughput =
                Arrays.stream(receiveThroughputs).average().orElse(0.0);
        }
    }

    static class EngineClient implements Runnable {
        private double avgHandshakeTime = 0.0;
        private double avgSendThroughput = 0.0;
        private double avgReceiveThroughput = 0.0;

        @Override
        public void run() {
            try {
                SSLContext ctx = createSSLContext("client");
                runIterations(ctx);
            } catch (Exception e) {
                System.err.println("EngineClient failed: " + e.getMessage());
                e.printStackTrace();
            }
        }

        private void runIterations(SSLContext ctx) throws Exception {
            double[] handshakeTimes = new double[BENCHMARK_ITERATIONS];
            double[] sendThroughputs = new double[BENCHMARK_ITERATIONS];
            double[] receiveThroughputs = new double[BENCHMARK_ITERATIONS];

            /* Warmup */
            for (int i = 0; i < WARMUP_ITERATIONS &&
                    !Thread.currentThread().isInterrupted(); i++) {

                SocketChannel channel = null;
                SSLEngine engine = null;
                try {
                    channel = SocketChannel.open(
                        new InetSocketAddress("localhost", PORT + 1));
                    channel.socket().setSoTimeout(60000); /* 60s timeout */
                    engine = performHandshake(ctx, channel, false);
                    byte[] data = new byte[DATA_SIZE];
                    Arrays.fill(data, (byte) 'B');
                    transferData(engine, channel, data, false);
                } catch (Exception e) {
                    System.err.println(
                        "Warmup iteration " + i + " failed: " + e.getMessage());
                }
            }

            /* Benchmark */
            for (int i = 0; i < BENCHMARK_ITERATIONS &&
                !Thread.currentThread().isInterrupted(); i++) {

                SocketChannel channel = null;
                SSLEngine engine = null;
                try {
                    channel = SocketChannel.open(
                        new InetSocketAddress("localhost", PORT + 1));
                    channel.socket().setSoTimeout(60000); /* 60s timeout */
                    long startHandshake = System.nanoTime();
                    engine = performHandshake(ctx, channel, false);
                    long endHandshake = System.nanoTime();
                    handshakeTimes[i] =
                        (endHandshake - startHandshake) / 1_000_000.0; /* ms */

                    /* Log session state */
                    SSLSession session = engine.getSession();
                    System.out.println("Client session: CipherSuite = " +
                        session.getCipherSuite() + ", Protocol = " +
                        session.getProtocol());

                    byte[] data = new byte[DATA_SIZE];
                    Arrays.fill(data, (byte) 'B');
                    TransferResult result =
                        transferData(engine, channel, data, false);
                    sendThroughputs[i] = result.sendThroughput;
                    receiveThroughputs[i] = result.receiveThroughput;
                } catch (Exception e) {
                    System.err.println("Benchmark iteration " + i +
                        " failed: " + e.getMessage());
                }
            }

            avgHandshakeTime =
                Arrays.stream(handshakeTimes).average().orElse(0.0);
            avgSendThroughput =
                Arrays.stream(sendThroughputs).average().orElse(0.0);
            avgReceiveThroughput =
                Arrays.stream(receiveThroughputs).average().orElse(0.0);
        }
    }

    private static SSLEngine performHandshake(SSLContext ctx,
        SocketChannel channel, boolean isServer) throws Exception {

        if (channel == null || !channel.isOpen()) {
            throw new IOException("Invalid or closed SocketChannel");
        }

        SSLEngine engine = ctx.createSSLEngine("localhost", PORT + 1);
        engine.setUseClientMode(!isServer);
        engine.setNeedClientAuth(isServer);

        /* Force TLS 1.2 and AES-GCM */
        engine.setEnabledProtocols(
            new String[] {"TLSv1.2"});
        engine.setEnabledCipherSuites(
            new String[] {"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"});

        /* Set buffer sizes */
        SSLSession session = engine.getSession();
        int appBufferSize = session.getApplicationBufferSize();
        int packetBufferSize = session.getPacketBufferSize();

        /* Allocate buffers with some extra space */
        ByteBuffer myAppData = ByteBuffer.allocateDirect(appBufferSize + 50);
        ByteBuffer peerAppData = ByteBuffer.allocateDirect(appBufferSize + 50);
        ByteBuffer myNetData = ByteBuffer.allocateDirect(packetBufferSize);
        ByteBuffer peerNetData = ByteBuffer.allocateDirect(packetBufferSize);

        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus hs = engine.getHandshakeStatus();
        long startTime = System.currentTimeMillis();

        while (hs != SSLEngineResult.HandshakeStatus.FINISHED &&
            hs != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            if (System.currentTimeMillis() - startTime > READ_TIMEOUT_MS) {
                throw new IOException(
                    "Handshake timed out after " + READ_TIMEOUT_MS + " ms");
            }

            switch (hs) {
                case NEED_TASK:
                    Runnable task;
                    while ((task = engine.getDelegatedTask()) != null) {
                        task.run();
                    }
                    hs = engine.getHandshakeStatus();
                    break;
                case NEED_UNWRAP:
                    peerNetData.clear();
                    int read = channel.read(peerNetData);
                    if (read == -1) {
                        throw new IOException(
                            "Channel closed during handshake");
                    }
                    if (read == 0) {
                        Thread.sleep(RETRY_DELAY_MS);
                        continue;
                    }
                    peerNetData.flip();
                    SSLEngineResult result =
                        engine.unwrap(peerNetData, peerAppData);
                    hs = result.getHandshakeStatus();

                    /* Handle buffer overflow/underflow */
                    if (result.getStatus() ==
                            SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        peerAppData = ByteBuffer.allocateDirect(
                            engine.getSession().getApplicationBufferSize());
                    } else if (result.getStatus() ==
                            SSLEngineResult.Status.BUFFER_UNDERFLOW) {
                        peerNetData = ByteBuffer.allocateDirect(
                            engine.getSession().getPacketBufferSize());
                    }
                    break;
                case NEED_WRAP:
                    myNetData.clear();
                    SSLEngineResult wrapResult =
                        engine.wrap(myAppData, myNetData);
                    hs = wrapResult.getHandshakeStatus();

                    /* Handle buffer overflow */
                    if (wrapResult.getStatus() ==
                        SSLEngineResult.Status.BUFFER_OVERFLOW) {
                        myNetData = ByteBuffer.allocateDirect(
                            engine.getSession().getPacketBufferSize());
                        continue;
                    }

                    myNetData.flip();
                    while (myNetData.hasRemaining()) {
                        int written = channel.write(myNetData);
                        if (written == -1) {
                            throw new IOException(
                                "Channel closed during handshake");
                        }
                        if (written == 0) {
                            Thread.sleep(RETRY_DELAY_MS);
                            continue;
                        }
                    }
                    break;
                default:
                    break;
            }
        }

        return engine;
    }
}

