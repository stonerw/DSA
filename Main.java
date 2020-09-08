package com.company;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import com.sun.org.apache.xerces.internal.impl.dv.util.HexBin;

class RSA {
    private static String src = "security";
    public static void main(String[] args) {
        long startTime = new Date().getTime();
        jdkRSA();
        long endTime = new Date().getTime();
        System.out.println("This program runs in " + (endTime - startTime)
                + "MS" );
    }

    public static void jdkRSA(){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(512);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();


            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);
            java.security.Signature signature = java.security.Signature.getInstance("MD5withRSA");
            signature.initSign(privateKey);
            signature.update(src.getBytes());
            byte[] res = signature.sign();
            System.out.println("signature:"+HexBin.encode(res));


            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
            keyFactory.getInstance("RSA");
            PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
            signature = Signature.getInstance("MD5withRSA");
            signature.initVerify(publicKey);
            signature.update(src.getBytes());
            boolean bool = signature.verify(res);
            System.out.println("result："+bool);
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}