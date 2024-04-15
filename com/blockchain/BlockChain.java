package com.blockchain;

import java.security.*;

public class BlockChain {
    public static void main(String[] args) throws Exception {
        String nickname = "Nicky.Zhang";
        proofOfWork(nickname, 4);
        proofOfWork(nickname, 5);
    }

    /**
     * 基于POW不断进行 sha256 Hash 运算
     * @param nickname
     * @param num
     * @throws Exception
     */
    public static void proofOfWork(String nickname, int num) throws Exception {
        if (num != 4 && num != 5) {
            return;
        }

        int nonce = 0;
        // 开始时间
        long begin = System.currentTimeMillis();
        String hash = calculateHashValue(nickname + nonce);
        if (num == 4) {
            while (!hash.startsWith("0000")) {
                nonce++;
                hash = calculateHashValue(nickname + nonce);
            }
            // 结束时间
            long end = System.currentTimeMillis();
            System.out.println("满足 4 个 0 开头的哈希值:"+ hash+", 共耗费"+(end - begin)+"ms");

            // 签名验证
            boolean result = verifySignature(hash, nickname, num);
            System.out.println("验签结果:"+ result);
        } else if (num == 5) {
            while (!hash.startsWith("00000")) {
                nonce++;
                hash = calculateHashValue(nickname + nonce);
            }
            long end = System.currentTimeMillis();
            System.out.println("满足 5 个 0 开头的哈希值:"+ hash+", 共耗费"+(end - begin)+"ms");
        }
    }

    /**
     * 根据SHA256算法产生hash value
     * @param data
     * @return
     */
    public static String calculateHashValue(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes());

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证签名条
     * @param hashValue
     * @param nickname
     * @param nonce
     * @return
     * @throws Exception
     */
    public static boolean verifySignature(String hashValue, String nickname, int nonce) throws Exception {
        // 生成RSA密钥对
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String message = nickname + nonce;

        // 使用私钥对数据进行签名
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(message.getBytes());
        byte[] signature = privateSignature.sign();

        // 使用公钥验证签名
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(message.getBytes());
        boolean verified = publicSignature.verify(signature);

        System.out.println("Signature verified: " + verified);
        return verified;
    }
}
