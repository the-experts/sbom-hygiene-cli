package nl.theexperts.sbom.collector.fetcher;

import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;

import java.net.URL;

public interface SourceCodeRepositoryHygieneFetcher {

    SourceCodeRepositoryHygiene fetch(URL url);

}
