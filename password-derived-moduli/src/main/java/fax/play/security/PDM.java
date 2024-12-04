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
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

public class PDM {

   private static int PASSWORD_DERIVATION_ITERATIONS = 1_000;

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
   private final int certainty;

   public PDM(String username, String password, Digest digestW, Digest digestQ, int sizeW, int sizeQ, int certainty) {
      this.username = username;
      this.password = password;
      this.digestW = digestW;
      this.digestQ = digestQ;
      this.sizeW = sizeW;
      this.sizeQ = sizeQ;
      this.certainty = certainty;
   }

   public Object calculateSessionKey() {
      PKCS5S2ParametersGenerator kdf = new PKCS5S2ParametersGenerator(digestW);
      kdf.init(password.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), PASSWORD_DERIVATION_ITERATIONS);
      byte[] w = ((KeyParameter) kdf.generateDerivedMacParameters(sizeW)).getKey();

      PKCS5S2ParametersGenerator kdf2 = new PKCS5S2ParametersGenerator(digestQ);
      kdf2.init(password.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), PASSWORD_DERIVATION_ITERATIONS);
      byte[] qByte = ((KeyParameter) kdf2.generateDerivedMacParameters(sizeQ)).getKey();
      BigInteger initialQ = new BigInteger(1, qByte);
      // inspired by DHParametersHelper#generateSafePrime
      // but different since here we want a deterministic result based on q
      BigInteger[] safePrimes = generateSafePrime(initialQ, certainty);

      BigInteger p = safePrimes[0];
      BigInteger q = safePrimes[1];
      DHParameters parameters = new DHParameters(p, BigInteger.TWO, q);

      KeyGenerationParameters kgp = new DHKeyGenerationParameters(new SecureRandom(), parameters);
      var keyGen = new DHBasicKeyPairGenerator();
      keyGen.init(kgp);

      AsymmetricCipherKeyPair aliceKeyPair = keyGen.generateKeyPair();
      DHBasicAgreement aliceKeyAgree = new DHBasicAgreement();
      aliceKeyAgree.init(aliceKeyPair.getPrivate());

      AsymmetricCipherKeyPair bobKeyPair = keyGen.generateKeyPair();
      DHBasicAgreement bobKeyAgree = new DHBasicAgreement();
      bobKeyAgree.init(bobKeyPair.getPrivate());

      BigInteger aliceAgree = aliceKeyAgree.calculateAgreement(bobKeyPair.getPublic());
      BigInteger bobAgree = bobKeyAgree.calculateAgreement(aliceKeyPair.getPublic());

      if (!aliceAgree.equals(bobAgree))
      {
         throw new RuntimeException("Keys do not match.");
      }
      return aliceAgree;
   }

   public static BigInteger[] generateSafePrime(BigInteger initialQValue, int certainty) {
      var q = initialQValue;
      while (!q.isProbablePrime(certainty)) {
         q = q.add(BigInteger.ONE);
      }
      // p <- 2q + 1
      var p = q.shiftLeft(1).add(BigInteger.ONE);

      return new BigInteger[] { p, q };
   }
}
