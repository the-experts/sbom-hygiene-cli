package nl.theexperts.sbom.collector.fetcher;

import nl.theexperts.sbom.collector.SourceCodeRepositoryHygiene;
import nl.theexperts.sbom.collector.VcsCollectionException;
import org.kohsuke.github.GHRepository;
import org.kohsuke.github.GitHub;
import org.kohsuke.github.GitHubBuilder;

import java.io.IOException;
import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZoneOffset;

public class GitHubHygieneFetcher implements SourceCodeRepositoryHygieneFetcher {

    private final GitHub githubClient;

    public GitHubHygieneFetcher(String apiHost) {
        try {
            githubClient = new GitHubBuilder().withEndpoint(apiHost).build();
        } catch (IOException e) {
            throw new VcsCollectionException("Could not initialize GitHub client", apiHost, e);
        }
    }

    @Override
    public SourceCodeRepositoryHygiene fetch(URL url) {
        try {
            var repository = githubClient.getRepository(url.getPath().substring(1));
            return new SourceCodeRepositoryHygiene(url, toScore(repository));
        } catch (IOException e) {
            throw new VcsCollectionException(url.toString(), e);
        }
    }

    private SourceCodeRepositoryHygiene.Score toScore(GHRepository repository) throws IOException {
        return new SourceCodeRepositoryHygiene.Score(
                -1,
                repository.getStargazersCount(),
                repository.listReleases().toSet().size(),
                repository.listContributors().toSet().size(),
                null,
                LocalDateTime.ofInstant(repository.getLatestRelease().getPublished_at().toInstant(), ZoneOffset.UTC)
        );
    }

}
