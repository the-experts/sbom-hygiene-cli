package nl.theexperts.sbom.collector;

import io.quarkus.runtime.util.ClassPathUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;

public class TestUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(TestUtils.class);

    private TestUtils() {
        // Hide constructor
    }

    public static String readClassPathResource(String path) {
        var url = Thread.currentThread().getContextClassLoader().getResource(path);
        if (url != null) {
            try {
                return ClassPathUtils.readStream(url, is -> {
                    try {
                        return new String(is.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                });
            } catch (IOException | RuntimeException e) {
                LOGGER.warn("Could not read ClassPathResource {}", path, e);
            }
        }
        return "";
    }

}
