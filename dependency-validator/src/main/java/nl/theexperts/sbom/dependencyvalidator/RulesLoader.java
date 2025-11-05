package nl.theexperts.sbom.dependencyvalidator;

import com.fasterxml.jackson.databind.ObjectMapper;
import nl.theexperts.sbom.api.validation.FailureRules;
import nl.theexperts.sbom.api.validation.LicenseRules;
import nl.theexperts.sbom.api.validation.ValidationRules;

import java.nio.file.Path;

public class RulesLoader {
    private static final ObjectMapper objectMapper = new ObjectMapper();

    public static ValidationRules loadValidationRules(Path override) {
        return load(override, "validation-rules.json", ValidationRules.class);
    }

    public static FailureRules loadFailureRules(Path override) {
        return load(override, "failure-rules.json", FailureRules.class);
    }

    public static LicenseRules loadLicenseRules(Path override) {
        return load(override, "license-rules.json", LicenseRules.class);
    }

    private static <T> T load(Path overridePath, String defaultResourcePath, Class<T> type) {
        try {
            if (overridePath != null) {
                return objectMapper.readValue(overridePath.toFile(), type);
            }
            try (var in = RulesLoader.class.getClassLoader().getResourceAsStream(defaultResourcePath)) {
                return objectMapper.readValue(in, type);
            }
        } catch (Exception e) {
            throw new RuntimeException("Error loading rules: " + defaultResourcePath, e);
        }
    }
}
