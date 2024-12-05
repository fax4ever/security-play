package fax.play.security;

import java.security.SecureRandom;

import org.bouncycastle.crypto.util.DigestFactory;
import org.junit.jupiter.api.Test;

public class PDMExecutionTest {

   @Test
   public void test() throws Exception {
      SecureRandom secureRandom = new SecureRandom();
      secureRandom.setSeed(739); // fix the seed to make the test deterministic
      PDMExecutions pdmExecutions = new PDMExecutions();
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 128, 256, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 128, 256, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 128, 256, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 256, 512, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 512, 1024, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 1024, 2048, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla2", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 128, 256, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla2", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 128, 256, secureRandom));
      pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA224(), DigestFactory.createSHA1(), 128, 256, secureRandom));
      pdmExecutions.createFile();
   }
}
