package fax.play.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

public class GenerateWTest {

   @Test
   public void test() {
      GenerateW generateW = new GenerateW("blablabla", "fax4ever");
      byte[] w = generateW.generate();
      String hex = Hex.encodeHexString(w);
      byte[] w2 = generateW.generate();
      String hex2 = Hex.encodeHexString(w2);
      assertThat(hex).isEqualTo(hex2);
   }
}
