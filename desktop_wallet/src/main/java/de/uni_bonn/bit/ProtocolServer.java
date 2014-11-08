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

import org.apache.avro.ipc.NettyServer;
import org.apache.avro.ipc.reflect.ReflectResponder;
import org.jboss.netty.channel.ChannelFactory;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.channel.Channels;
import org.jboss.netty.channel.socket.nio.NioServerSocketChannelFactory;
import org.jboss.netty.handler.ssl.SslHandler;
import org.spongycastle.asn1.x500.X500Name;
import org.spongycastle.asn1.x509.AlgorithmIdentifier;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.bc.BcX509v3CertificateBuilder;
import org.spongycastle.cert.jcajce.JcaX509CertificateConverter;
import org.spongycastle.crypto.AsymmetricCipherKeyPair;
import org.spongycastle.crypto.generators.RSAKeyPairGenerator;
import org.spongycastle.crypto.params.RSAKeyGenerationParameters;
import org.spongycastle.crypto.params.RSAKeyParameters;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.spongycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.bc.BcRSAContentSignerBuilder;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Calendar;
import java.util.concurrent.Executors;

/**
 * This class contains the boiler plate code to create a server for the {@link de.uni_bonn.bit.wallet_protocol.IPairingProtocol}
 * or the {@link de.uni_bonn.bit.wallet_protocol.IWalletProtocol}. The server supports incoming TLS connections. A random
 * RSA key pair generated when creating a new instance of this class. The TLS connection uses a certificate which is generated ad-hoc.
 * The certificate contains the RSA public key. The key can be retrieved with {@link ProtocolServer#getPublicKey()}.
 */
public class ProtocolServer {

    AsymmetricCipherKeyPair keyPair;
    NettyServer nettyServer;

    public ProtocolServer(Class protocolInterfaceType, Object protocolImpl){
        RSAKeyPairGenerator rsaGen = new RSAKeyPairGenerator();
        rsaGen.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x1001), new SecureRandom(), 2048, 25));
        keyPair = rsaGen.generateKeyPair();

        ChannelFactory channelFactory = new NioServerSocketChannelFactory(
                Executors.newCachedThreadPool(),
                Executors.newCachedThreadPool()
        );
        nettyServer = new NettyServer(new ReflectResponder(
                protocolInterfaceType,
                protocolImpl), new InetSocketAddress(7001),
                channelFactory, new SSLChannelPipelineFactory(keyPair),
                null);
    }

    public RSAPublicKey getPublicKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        RSAKeyParameters publicKey = (RSAKeyParameters) keyPair.getPublic();
        RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(publicKey.getModulus(), publicKey.getExponent());
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(publicKeySpec);
    }

    public void close() {
        nettyServer.close();
    }

    private static class SSLChannelPipelineFactory
            implements ChannelPipelineFactory {

        private AsymmetricCipherKeyPair keyPair;

        public SSLChannelPipelineFactory(AsymmetricCipherKeyPair keyPair){
            this.keyPair = keyPair;
        }

        /**
         * Generates a short-living certificate for the keyPair.
         */
        private X509Certificate generateCertificate() throws NoSuchProviderException, NoSuchAlgorithmException, CertificateException, SignatureException, InvalidKeyException, IOException, OperatorCreationException {
            /* The certificate starts to be valid one minute in the past to be safe
             * if the clocks are a bit out of sync. */
            Calendar startDate = Calendar.getInstance();
            startDate.add(Calendar.MINUTE, -1);
            /* The certificate is not valid anymore after two minutes. This should
             * be enough to complete the protocol. */
            Calendar expiryDate = Calendar.getInstance();
            expiryDate.add(Calendar.MINUTE, +2);
            AlgorithmIdentifier sha1withRSA = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA");
            ContentSigner signer = new BcRSAContentSignerBuilder(
                    new DefaultSignatureAlgorithmIdentifierFinder().find("SHA1withRSA"),
                    new DefaultDigestAlgorithmIdentifierFinder().find(sha1withRSA))
                    .build(keyPair.getPrivate());
            X500Name subjectName = new X500Name("CN=Wallet Protocol Server Ephemeral Certificate");
            BcX509v3CertificateBuilder certBuilder = new BcX509v3CertificateBuilder(
                    subjectName,
                    BigInteger.ONE,
                    startDate.getTime(), expiryDate.getTime(),
                    subjectName,
                    keyPair.getPublic()
            );
            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certHolder);
            return cert;
        }

        private SSLContext createServerSSLContext() {
            try {
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                java.security.cert.Certificate cert = generateCertificate();
                RSAKeyParameters privateKey = (RSAKeyParameters) keyPair.getPrivate();
                RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(privateKey.getModulus(), privateKey.getExponent());
                PrivateKey jPrivateKey = KeyFactory.getInstance("RSA").generatePrivate(privateKeySpec);
                keyStore.setKeyEntry("myCert", jPrivateKey, "aaa".toCharArray(), new java.security.cert.Certificate[]{cert});
                KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
                kmf.init(keyStore, "aaa".toCharArray());
                SSLContext serverContext = SSLContext.getInstance("TLS");
                serverContext.init(kmf.getKeyManagers(), null, null);
                return serverContext;
            } catch (Exception e) {
                throw new Error("Failed to initialize the server-side SSLContext", e);
            }
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            ChannelPipeline pipeline = Channels.pipeline();
            SSLEngine sslEngine = createServerSSLContext().createSSLEngine();
            /**
             * This fixes the cipher suite and disables DH key agreement. The RSA key pair itself only lives as long
             * as the instance of this class. Therefore, there is no need to do a DH key agreement for PFS. The RSA key
             * itself will only be used for a very short time.
             */
            sslEngine.setEnabledCipherSuites(new String[]{"TLS_RSA_WITH_AES_128_CBC_SHA"});
            sslEngine.setUseClientMode(false);
            pipeline.addLast("ssl", new SslHandler(sslEngine));
            return pipeline;
        }
    }
}
