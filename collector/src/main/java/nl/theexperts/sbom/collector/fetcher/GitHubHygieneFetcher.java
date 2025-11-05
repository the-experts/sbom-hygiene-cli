package nl.theexperts.sbom.collector.fetcher;

import io.quarkus.rest.client.reactive.QuarkusRestClientBuilder;
import jakarta.ws.rs.core.Response;
import nl.theexperts.sbom.api.SourceCodeRepositoryHygiene;

import java.net.URI;
import java.net.URL;
import java.nio.file.Path;
import java.time.OffsetDateTime;

public class GitHubHygieneFetcher implements SourceCodeRepositoryHygieneFetcher {

    private final GitHubClient githubClient;

    public GitHubHygieneFetcher(String apiHost, char[] token) {
        githubClient = QuarkusRestClientBuilder.newBuilder()
                .baseUri(URI.create(apiHost))
                .register(new BearerTokenFilter(String.copyValueOf(token)))
                .build(GitHubClient.class);
    }

    @Override
    public SourceCodeRepositoryHygiene fetch(URL url) {
        var path = Path.of(url.getPath()).normalize();
        var owner = path.subpath(0, 1).toString();
        var repo = path.subpath(1, 2).toString();

        // stars
        int stars = githubClient.getRepo(owner, repo).stargazers_count(); // :contentReference[oaicite:5]{index=5}

        // contributors (1 per page → last page number == total)
        Response contribResp = githubClient.getContributorsPage(owner, repo, 1, "true"); // :contentReference[oaicite:6]{index=6}
        int contribSize = contribResp.getStatus() == 200 ? contribResp.readEntity(java.util.List.class).size() : 0;
        int contributors = LinkHeaderUtil.lastPageOrSize(contribResp.getHeaderString("Link"), contribSize);
        contribResp.close();

        // releases count
        Response relResp = githubClient.getReleasesPage(owner, repo, 1); // list endpoint; we parse Link. :contentReference[oaicite:7]{index=7}
        int releasesSize = relResp.getStatus() == 200 ? relResp.readEntity(java.util.List.class).size() : 0;
        int releases = LinkHeaderUtil.lastPageOrSize(relResp.getHeaderString("Link"), releasesSize);
        relResp.close();

        // last release date
        String publishedAt = null;
        try {
            var latest = githubClient.getLatestRelease(owner, repo); // published_at is ISO8601. :contentReference[oaicite:8]{index=8}
            publishedAt = latest.published_at();
        } catch (Exception ignored) {
            // No releases yet or API error
        }

        OffsetDateTime lastRelease = publishedAt == null ? null : OffsetDateTime.parse(publishedAt);
        return new SourceCodeRepositoryHygiene(url, new SourceCodeRepositoryHygiene.Score(
                -1,
                stars,
                releases,
                contributors,
                null,
                lastRelease == null ? null : lastRelease.toLocalDateTime()));
    }

}
