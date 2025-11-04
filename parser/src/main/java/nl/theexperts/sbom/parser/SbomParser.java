package nl.theexperts.sbom.parser;

import com.siemens.sbom.standardbom.StandardBomParser;
import com.siemens.sbom.standardbom.model.StandardBom;
import org.cyclonedx.exception.ParseException;

import java.io.File;
import java.io.IOException;

public class SbomParser {

    public StandardBom read(File bomFile) {
        try {
            return new StandardBomParser().parse(bomFile);
        } catch (IOException | ParseException e) {
            throw new RuntimeException(e);
        }
    }

}
