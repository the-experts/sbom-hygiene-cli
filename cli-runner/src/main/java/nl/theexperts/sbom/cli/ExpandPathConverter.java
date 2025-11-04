package nl.theexperts.sbom.cli;

import picocli.CommandLine;

import java.nio.file.Path;

public class ExpandPathConverter implements CommandLine.ITypeConverter<Path> {
    @Override
    public Path convert(String raw) {
        if (raw.startsWith("~")) {
            raw = raw.replaceFirst("~", System.getProperty("user.home"));
        }
        return Path.of(raw).toAbsolutePath().normalize();
    }
}
