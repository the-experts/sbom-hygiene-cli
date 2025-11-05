package nl.theexperts.sbom.collector.fetcher;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public record GitHubRepo(int stargazers_count) {} // stargazers_count comes from /repos. :contentReference[oaicite:3]{index=3}
