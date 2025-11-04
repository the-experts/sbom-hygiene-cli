package nl.theexperts.sbom.collector;

public enum VcsType {

    GITHUB("github.com"),
    GITLAB("gitlab.com"),
    BITBUCKET("bitbucket.com"),
    OTHER("");

    private final String hostname;

    VcsType(String hostname) {
        this.hostname = hostname;
    }

    public static VcsType find(String host) {
        for (VcsType vcsType : VcsType.values()) {
            if (vcsType.hostname.equals(host)) {
                return vcsType;
            }
        }
        return OTHER;
    }

}
