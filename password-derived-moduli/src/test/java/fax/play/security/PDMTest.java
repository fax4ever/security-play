package fax.play.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.bouncycastle.crypto.util.DigestFactory;
import org.junit.jupiter.api.Test;

public class PDMTest {

   @Test
   public void test() {
      PDM pdm = new PDM("fax4ever", "blablabla", DigestFactory.createSHA3_256(), DigestFactory.createSHA3_512(), 512, 2048, 3);
      Object o = pdm.calculateSessionKey();
      assertThat(o).isNotNull();
   }
}
