import com.siemens.sbom.standardbom.StandardBomParser;
import org.cyclonedx.exception.ParseException;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class SbomParserTest {

    private static final File sbom = new File("");

    @Test;
    void when_sbom_then_return_standardbom() throws IOException, ParseException {
        var standardBom = new StandardBomParser().parse(sbom);
        assertThat(standardBom.equals());
    }

}