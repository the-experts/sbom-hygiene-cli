package nl.theexperts.sbom.collector;

import nl.theexperts.sbom.collector.fetcher.GitHubHygieneFetcher;
import org.junit.jupiter.api.Test;

import java.net.MalformedURLException;
import java.net.URI;
import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.*;

class DependencyHygieneCollectorTest {

    private static final String GITHUB_URL = "https://github.com/the-experts/sbom-hygiene-cli";

    private final FetcherSelector fetcherSelector = mock(FetcherSelector.class);

    private final DependencyHygieneCollector collector = new DependencyHygieneCollector(fetcherSelector);

    @Test
    void when_GitHub_vcs_url_then_return_GitHubHygieneFetcher() throws MalformedURLException {
        var url = URI.create(GITHUB_URL).toURL();
        var sourceCodeRepositoryHygiene = new SourceCodeRepositoryHygiene(
                url, new SourceCodeRepositoryHygiene.Score(
                -1,
                1,
                1,
                3,
                null,
                LocalDateTime.of(2025, 11, 4, 12, 17, 22)
        ));
        var githubFetcher = mock(GitHubHygieneFetcher.class);
        when(fetcherSelector.selectFetcher(VcsType.GITHUB))
                .thenReturn(githubFetcher);
        when(githubFetcher.fetch(url)).thenReturn(sourceCodeRepositoryHygiene);

        var result = collector.collect(url);

        assertThat(result.url()).hasToString(GITHUB_URL);
        assertThat(result).isEqualTo(sourceCodeRepositoryHygiene);
        verify(githubFetcher).fetch(url);
    }

    @Test
    void when_unknown_vcs_url_then_throw_exception() throws MalformedURLException {
        var url = URI.create("https://mydomain.com/repo").toURL();
        assertThatExceptionOfType(VcsTypeNotSupportedException.class)
                .isThrownBy(() -> collector.collect(url))
                .withMessage("VCS type OTHER with URL https://mydomain.com/repo is currently not supported");
    }

}
