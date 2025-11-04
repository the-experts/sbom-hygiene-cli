package nl.theexperts.sbom.parser;

import com.siemens.sbom.standardbom.StandardBomParser;
import org.cyclonedx.exception.ParseException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class SbomParserTest {

    // Use the sample SBOM shipped in the cli-runner test resources (relative to the parser module)
    private static final File sbom = new File("../cli-runner/src/test/resources/syft-bom.json");

    @Test
    void when_sbom_then_return_standardbom() throws IOException, ParseException {
        var standardBom = new StandardBomParser().parse(sbom);
        assertThat(standardBom).isNotNull();
    }

}