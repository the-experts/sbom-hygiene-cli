package nl.theexperts.sbom.reporter;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;

class ReportWriterTest {

    private final ReportWriter reportWriter = new ReportWriter();

    @Test
    void generateReport_returnsNonEmptyString() throws JsonProcessingException {
        var results = reportWriter.generateReport(Path.of("/tmp/output.json"), List.of());

        assertNotNull(results);
        assertThat(results).containsIgnoringCase("Test result 1");
    }

}