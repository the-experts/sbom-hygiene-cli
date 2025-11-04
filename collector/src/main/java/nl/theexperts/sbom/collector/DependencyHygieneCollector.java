package nl.theexperts.sbom.collector;

import nl.theexperts.sbom.collector.fetcher.GitHubHygieneFetcher;
import nl.theexperts.sbom.collector.fetcher.SourceCodeRepositoryHygieneFetcher;

import java.net.URL;

public class DependencyHygieneCollector {

    public SourceCodeRepositoryHygiene collect(URL uri) {
        var fetcher = selectFetcher(VcsType.find(uri.getHost()));
        if (fetcher == null) {
            throw new VcsTypeNotSupportedException(VcsType.OTHER, uri.toString());
        }
        return fetcher.fetch(uri);
    }

    private SourceCodeRepositoryHygieneFetcher selectFetcher(VcsType type) {
        return switch (type) {
            case GITHUB -> new GitHubHygieneFetcher("https://api.github.com");
            default -> null;
        };
    }

}
