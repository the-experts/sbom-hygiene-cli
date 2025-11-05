package nl.theexperts.sbom.collector.fetcher;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GitHubRelease(String published_at, Boolean prerelease) {
} // published_at from /releases/latest. :contentReference[oaicite:4]{index=4}
