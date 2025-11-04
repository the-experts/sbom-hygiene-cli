package nl.theexperts.sbom.collector;

import nl.theexperts.sbom.collector.fetcher.GitHubHygieneFetcher;
import nl.theexperts.sbom.collector.fetcher.SourceCodeRepositoryHygieneFetcher;

public class FetcherSelector {

    SourceCodeRepositoryHygieneFetcher selectFetcher(VcsType type) {
        return switch (type) {
            case GITHUB -> new GitHubHygieneFetcher("https://api.github.com");
            default -> null;
        };
    }

}
