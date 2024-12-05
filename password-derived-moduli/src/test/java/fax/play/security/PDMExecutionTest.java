package fax.play.security;

import org.bouncycastle.crypto.util.DigestFactory;
import org.junit.jupiter.api.Test;

public class PDMExecutionTest {

   @Test
   public void test() throws Exception {
      PDMExecutions pdmExecutions = new PDMExecutions();
      int size = 256;
      for (int i = 0; i < 3; i++) {
         pdmExecutions.add(new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), size/2, size, size));
         size *= 2;
      }
      pdmExecutions.createFile();
   }
}
