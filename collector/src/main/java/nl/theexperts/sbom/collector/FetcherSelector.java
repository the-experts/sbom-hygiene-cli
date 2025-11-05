package nl.theexperts.sbom.collector;

import jakarta.enterprise.context.ApplicationScoped;
import nl.theexperts.sbom.api.VcsType;
import nl.theexperts.sbom.collector.fetcher.GitHubHygieneFetcher;
import nl.theexperts.sbom.collector.fetcher.SourceCodeRepositoryHygieneFetcher;

@ApplicationScoped
public class FetcherSelector {

    SourceCodeRepositoryHygieneFetcher selectFetcher(VcsType type, char[] token) {
        return switch (type) {
            case GITHUB -> new GitHubHygieneFetcher("https://api.github.com", token);
            default -> null;
        };
    }

}
