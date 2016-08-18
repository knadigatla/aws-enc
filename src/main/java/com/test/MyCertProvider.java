package com.test;

import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifacts;
import com.amazonaws.services.elasticmapreduce.spi.security.TLSArtifactsProvider;

import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

public class MyCertProvider extends TLSArtifactsProvider {

    public TLSArtifacts getTlsArtifacts() {

        TLSArtifacts artifacts = null;
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            FileInputStream keyfis = new FileInputStream("privateKey.pem");
            byte[] pkeybits = new byte[keyfis.available()];
            keyfis.read(pkeybits);
            PrivateKey privateKey = keyFactory
                    .generatePrivate(new PKCS8EncodedKeySpec(pkeybits));


            Certificate certsChain = certFactory.generateCertificate(new FileInputStream("certificateChain.pem"));
            List<Certificate> listCertsChain = new ArrayList<Certificate>(1);
            listCertsChain.add(certsChain);

            Certificate trustCerts = certFactory.generateCertificate(new FileInputStream("trustedCertificates.pem"));
            List<Certificate> listTrustCerts = new ArrayList<Certificate>(1);
            listTrustCerts.add(trustCerts);
            artifacts = new TLSArtifacts(privateKey, listCertsChain, listTrustCerts);

        } catch (Exception e) {
            e.printStackTrace();
        }

        return artifacts;

    }
}
