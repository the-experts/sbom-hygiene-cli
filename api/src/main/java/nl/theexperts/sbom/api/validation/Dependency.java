package nl.theexperts.sbom.api.validation;

import java.net.URL;
import java.time.LocalDateTime;

public record Dependency(URL url, Score score, String license) {
    public record Score(int downloads, int stars, int releases, int contributors, LocalDateTime firstReleaseDateTime,
                        LocalDateTime lastReleaseDateTime) {
    }
}
