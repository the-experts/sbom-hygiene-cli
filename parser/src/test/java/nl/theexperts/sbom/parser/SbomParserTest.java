package nl.theexperts.sbom.parser;

import com.siemens.sbom.standardbom.StandardBomParser;
import org.cyclonedx.exception.ParseException;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThat;

class SbomParserTest {
    @ParameterizedTest
    @ValueSource(strings = {"syft-bom.json","cyclonedx-maven-plugin-bom.xml"})
    void when_sbom_then_return_standardbom(String resource) throws IOException, ParseException, URISyntaxException {
        var standardBom = new StandardBomParser().parse(getClassPathFile(resource));
        assertThat(standardBom).isNotNull();
    }

    private File getClassPathFile(String classPathResource) throws URISyntaxException {
        return Path.of(Objects.requireNonNull(Thread.currentThread()
                                .getContextClassLoader()
                                .getResource(classPathResource))
                        .toURI())
                .toFile();
    }
}