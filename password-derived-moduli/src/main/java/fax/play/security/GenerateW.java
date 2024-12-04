package fax.play.security;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.util.DigestFactory;

public class GenerateW {

   private static final int ITERATION = 10_000;
   private static final int HASH_SIZE = 512;

   private final String username; // used as salt
   private final String password;

   public GenerateW(String username, String password) {
      this.username = username;
      this.password = password;
   }

   public byte[] generate() {
      PKCS5S2ParametersGenerator kdf = new PKCS5S2ParametersGenerator(DigestFactory.createSHA384());
      kdf.init(password.getBytes(StandardCharsets.UTF_8), username.getBytes(StandardCharsets.UTF_8), ITERATION);
      return ((KeyParameter) kdf.generateDerivedMacParameters(HASH_SIZE)).getKey();
   }
}
