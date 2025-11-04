package nl.theexperts.sbom.dependencyvalidator.model;

import java.net.URL;
import java.time.LocalDateTime;

public record Dependency(URL url, Score score) {
    public record Score(int downloads, int stars, int releases, int contributors, LocalDateTime firstReleaseDateTime,
                        LocalDateTime lastReleaseDateTime) {
    }
}
