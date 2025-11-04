package nl.theexperts.sbom.collector;

import java.net.URL;
import java.time.LocalDateTime;

public record SourceCodeRepositoryHygiene(URL url, Score score) {

    public record Score(int downloads, int stars, int releases, int contributors, LocalDateTime firstReleaseDateTime,
                        LocalDateTime lastReleaseDateTime) {
    }

}
