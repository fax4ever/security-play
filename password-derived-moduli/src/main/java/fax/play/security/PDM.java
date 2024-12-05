package fax.play.security;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;

public class PDM {

   private static final int PASSWORD_DERIVATION_ITERATIONS = 1_000;

   // used as salt
   private final String username;
   // used to generate p and W
   private final String password;
   // digest used to generate W
   private final Digest digestW; // DigestFactory.createSHA384()
   // digest used to generate q
   private final Digest digestQ; // DigestFactory.createSHA384()
   // size of W
   private final int sizeW;
   // size of q
   private final int sizeQ;
   // certainty
   private final SecureRandom secureRandom;

   // OUTPUT:
   private BigInteger w;
   private BigInteger initialQ;
   private BigInteger q;
   private BigInteger p;
   private DHPrivateKeyParameters a;
   private DHPrivateKeyParameters b;
   private BigInteger sessionKeyPart1;
   private BigInteger sessionKeyPart2;

   public PDM(String username, String password, Digest digestW, Digest digestQ, int sizeW, int sizeQ,
              SecureRandom secureRandom) {
      this.username = username;
      this.password = password;
      this.digestW = digestW;
      this.digestQ = digestQ;
      this.sizeW = sizeW;
      this.sizeQ = sizeQ;
      this.secureRandom = secureRandom;
   }

   public String username() {
      return username;
   }

   public String password() {
      return password;
   }

   public String digestW() {
      return digestW.getAlgorithmName();
   }

   public Integer sizeW() {
      return sizeW;
   }

   public String digestQ() {
      return digestQ.getAlgorithmName();
   }

   public Integer sizeQ() {
      return sizeQ;
   }

   public String w() {
      return w.toString(16);
   }

   public String initialQ() {
      return initialQ.toString(16);
   }

   public String q() {
      return q.toString(16);
   }

   public String p() {
      return p.toString(16);
   }

   public String a() {
      return a.getX().toString(16);
   }

   public String b() {
      return b.getX().toString(16);
   }

   public String sessionKeyPart1() {
      return sessionKeyPart1.toString(16);
   }

   public String sessionKeyPart2() {
      return sessionKeyPart2.toString(16);
   }

   public void calculateSessionKey() {
      PKCS5S2ParametersGenerator kdf = new PKCS5S2ParametersGenerator(digestW);
      kdf.init(password.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), PASSWORD_DERIVATION_ITERATIONS);
      byte[] wByte = ((KeyParameter) kdf.generateDerivedMacParameters(sizeW)).getKey();
      w = new BigInteger(1, wByte);

      PKCS5S2ParametersGenerator kdf2 = new PKCS5S2ParametersGenerator(digestQ);
      kdf2.init(password.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), PASSWORD_DERIVATION_ITERATIONS);
      byte[] qByte = ((KeyParameter) kdf2.generateDerivedMacParameters(sizeQ)).getKey();
      initialQ = new BigInteger(1, qByte);
      // inspired by DHParametersHelper#generateSafePrime
      // but different since here we want a deterministic result based on q
      BigInteger[] safePrimes = generateSafePrime(initialQ);

      p = safePrimes[0];
      q = safePrimes[1];
      DHParameters parameters = new DHParameters(p, BigInteger.TWO, q);

      KeyGenerationParameters kgp = new DHKeyGenerationParameters(secureRandom, parameters);
      var keyGen = new DHBasicKeyPairGenerator();
      keyGen.init(kgp);

      AsymmetricCipherKeyPair aliceKeyPair = keyGen.generateKeyPair();
      DHBasicAgreement aliceKeyAgree = new DHBasicAgreement();
      a = (DHPrivateKeyParameters) aliceKeyPair.getPrivate();
      aliceKeyAgree.init(a);

      AsymmetricCipherKeyPair bobKeyPair = keyGen.generateKeyPair();
      DHBasicAgreement bobKeyAgree = new DHBasicAgreement();
      b = (DHPrivateKeyParameters) bobKeyPair.getPrivate();
      bobKeyAgree.init(b);

      BigInteger aliceAgree = aliceKeyAgree.calculateAgreement(bobKeyPair.getPublic());
      BigInteger bobAgree = bobKeyAgree.calculateAgreement(aliceKeyPair.getPublic());

      if (!aliceAgree.equals(bobAgree))
      {
         throw new RuntimeException("Keys do not match.");
      }

      // first part of the key: 2^(ab) mod p
      sessionKeyPart1 = bobAgree;
      // second part of the key: 2^(bw) mod p
      sessionKeyPart2 = ((DHPublicKeyParameters) bobKeyPair.getPublic()).getY().modPow(w, p);
   }

   public static BigInteger[] generateSafePrime(BigInteger initialQValue) {
      var q = initialQValue.nextProbablePrime();
      // p <- 2q + 1
      var p = q.shiftLeft(1).add(BigInteger.ONE);

      return new BigInteger[] { p, q };
   }
}
