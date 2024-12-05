package fax.play.security;

import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVPrinter;

public class PDMExecutions {

   private static final String CSV_FILE_PATH = "./executions.csv";

   private final List<PDM> executions = new ArrayList<>();

   public void add(PDM execution) {
      execution.calculateSessionKey();
      executions.add(execution);
   }

   public void createFile() throws IOException {
      try (
            BufferedWriter writer = Files.newBufferedWriter(Paths.get(CSV_FILE_PATH));
            CSVPrinter csvPrinter = new CSVPrinter(writer, CSVFormat.DEFAULT
                  .withHeader("username", "password", "digestW", "sizeW",
                        "digestQ", "sizeQ", "W", "initialQ",
                        "q", "p", "a", "b", "session key (1/2)", "session key (2/2)"))
      ) {
         for (PDM execution : executions) {
            csvPrinter.printRecord(execution.username(), execution.password(), execution.digestW(), execution.sizeW(),
                  execution.digestQ(), execution.sizeQ(), execution.w(), execution.initialQ(),
                  execution.q(), execution.p(), execution.a(), execution.b(), execution.sessionKeyPart1(), execution.sessionKeyPart2());
         }
         csvPrinter.flush();
      }
   }
}
