package fax.play.security;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.generators.DHBasicKeyPairGenerator;
import org.bouncycastle.crypto.generators.DHParametersGenerator;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHParameters;

public final class DiffieHellman {

   public static void generate() {
      int DefaultPrimeProbability = 30;

      DHParametersGenerator generator = new DHParametersGenerator();
      generator.init(512, DefaultPrimeProbability, new SecureRandom());
      DHParameters parameters = generator.generateParameters();

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
   }

}
