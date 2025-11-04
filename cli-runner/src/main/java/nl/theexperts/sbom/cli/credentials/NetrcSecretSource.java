package nl.theexperts.sbom.cli.credentials;

import nl.theexperts.sbom.api.VcsType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Path;

public final class NetrcSecretSource {

    private static final Logger log = LoggerFactory.getLogger(NetrcSecretSource.class);
    private final Path credentialsPath;

    public NetrcSecretSource(Path credentialsPath) {
        if (credentialsPath != null) {
            this.credentialsPath = credentialsPath;
        } else {
            this.credentialsPath = Path.of(System.getProperty("user.home"),
                    ".config", "sbom-hygiene", "credentials");
        }
    }

    public char[] get(VcsType vcsType) {
        if (java.nio.file.Files.isReadable(credentialsPath)) {
            try {
                for (var line : java.nio.file.Files.readAllLines(credentialsPath)) {
                    var s = line.trim();
                    if (s.isEmpty() || s.startsWith("#")) continue;
                    // format: machine <host> login token password <secret>
                    var tok = s.split("\\s+");
                    for (int i = 0; i < tok.length - 5; i++) {
                        if (tok[i].equals("machine") && tok[i + 1].endsWith(vcsType.getHostname())
                                && tok[i + 2].equals("login") && tok[i + 3].equals("token")
                                && tok[i + 4].equals("password")) {
                            return tok[i + 5].toCharArray();
                        }
                    }
                }
            } catch (IOException e) {
                log.warn("Error reading credentials file", e);
            }
        }
        return new char[0];
    }
}
