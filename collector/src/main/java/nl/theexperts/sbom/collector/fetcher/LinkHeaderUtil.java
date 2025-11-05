package nl.theexperts.sbom.collector.fetcher;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class LinkHeaderUtil {
    private static final Pattern LAST_PAGE =
            Pattern.compile(".*<[^>]*[?&]page=(\\d+)[^>]*>;\\s*rel=\"last\".*");

    static int lastPageOrSize(String linkHeader, int fallbackSize) {
        if (linkHeader == null || linkHeader.isBlank()) return fallbackSize;
        Matcher m = LAST_PAGE.matcher(linkHeader);
        return m.matches() ? Integer.parseInt(m.group(1)) : fallbackSize;
    }

    private LinkHeaderUtil() {
    }
}
