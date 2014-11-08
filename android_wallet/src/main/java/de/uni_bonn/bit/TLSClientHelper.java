/*
* Copyright 2014 Christopher Mann
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package de.uni_bonn.bit;
package de.uni_bonn.bit;

import org.apache.avro.ipc.NettyTransceiver;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.socket.SocketChannel;
import org.jboss.netty.channel.socket.nio.NioClientSocketChannelFactory;
import org.jboss.netty.handler.ssl.SslHandler;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.Executors;

/**
 * This class contains some helper methods for establishing a TLS connection.
 */
public class TLSClientHelper {

    public static NettyTransceiver createNettyTransceiver(PublicKey publicKey, List<String> ipAddresses) throws IOException {
        String ipAddress = IPAddressHelper.findFirstAddressInCommonNetwork(ipAddresses);
         NettyTransceiver client = new NettyTransceiver(
                new InetSocketAddress(ipAddress, 7001),
                new SSLChannelFactory(publicKey));
        return client;
    }

    private static class SSLChannelFactory extends NioClientSocketChannelFactory {

        private PublicKey publicKey;

        public SSLChannelFactory(PublicKey publicKey) {
            super(Executors.newCachedThreadPool(), Executors.newCachedThreadPool());
            this.publicKey = publicKey;
        }

        @Override
        public SocketChannel newChannel(ChannelPipeline pipeline) {
            try {
                SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
                sslContext.init(null, new TrustManager[]{new BogusTrustManager(publicKey)},
                        null);
                SSLEngine sslEngine = sslContext.createSSLEngine();
                sslEngine.setUseClientMode(true);
                pipeline.addFirst("ssl", new SslHandler(sslEngine));
                return super.newChannel(pipeline);
            } catch (Exception ex) {
                throw new RuntimeException("Cannot create SSL channel", ex);
            }
        }
    }

    /**
     * Bogus trust manager accepting any certificate
     */
    private static class BogusTrustManager implements X509TrustManager {

        private PublicKey publicKey;

        public BogusTrustManager(PublicKey publicKey) {
            this.publicKey = publicKey;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String s) {
            // nothing
        }

        @Override
        public void checkServerTrusted(X509Certificate[] certs, String s) throws CertificateException {
            if(certs.length != 1)
                throw new CertificateException("Only a single self-signed certificate is expected, but a longer certificate chain was provided.");
            X509Certificate cert = certs[0];
            if(! cert.getPublicKey().equals(publicKey))
                throw new CertificateException("The server is not using the expected public key");
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
