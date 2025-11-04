package nl.theexperts.sbom.dependencyvalidator;

import nl.theexperts.sbom.dependencyvalidator.model.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

public class RuleEngine {

    private static final String UNKNOWN = "unknown";
    private static final String ALLOW = "allow";
    private static final String NON_SPDX = "non-spdx";
    private static final String NO_LICENSE_FILE = "no-license-file";

    public ValidationSummary evaluate(
            List<Dependency> dependencies,
            ValidationRules validationRules,
            LicenseRules licenseRules,
            FailureRules failureRules
    ) {
        List<RuleFinding> findings = new ArrayList<>();

        for (Dependency dep : dependencies) {
            // Evaluate each dependency against the provided rules
            findings.addAll(applyValidationRules(dep, validationRules));
            findings.addAll(applyLicenseRules(dep, licenseRules));
        }

        FailureEvaluationResult eval = FailurePolicyEvaluator.evaluate(findings, failureRules);

        return new ValidationSummary(eval.success(), eval.score(), findings);
    }

    private List<RuleFinding> applyValidationRules(Dependency dep, ValidationRules validationRules) {
        List<RuleFinding> results = new ArrayList<>();

        validationRules.getRules().forEach((ruleId, criteria) -> {
            RuleFinding finding = applyValidationRule(dep, ruleId, criteria);
            results.add(finding);
        });

        return results;
    }

    private RuleFinding applyValidationRule(
            Dependency dep,
            String ruleId,
            ValidationRuleCriteria criteria
    ) {
        // Extract metric name
        Object metricObj = criteria.get("metric");
        if (metricObj == null) {
            return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.INFO, List.of("No metric specified in rule"));
        }
        String metric = metricObj.toString();

        // Extract thresholds (try multiple key variants)
        Double warnThreshold = extractThreshold(criteria, "warn-at", "warn-at-days", "warn-at-count", "warn-at-days");
        Double failThreshold = extractThreshold(criteria, "fail-at", "fail-at-days", "fail-at-count", "fail-at-days");

        // Resolve metric value
        MetricInfo metricInfo = resolveMetricValue(dep, metric);
        if (!metricInfo.available) {
            return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.INFO, List.of(metricInfo.message));
        }

        // If no thresholds configured, PASS
        if (warnThreshold == null && failThreshold == null) {
            return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.PASS, List.of("No thresholds configured"));
        }

        // Evaluate thresholds and return finding
        return evaluateThresholds(dep, ruleId, metricInfo.value, metricInfo.higherIsBetter, warnThreshold, failThreshold);
    }

    // Helper to extract a numeric threshold from multiple possible keys
    private Double extractThreshold(ValidationRuleCriteria criteria, String... keys) {
        for (String k : keys) {
            Object v = criteria.get(k);
            if (v == null) continue;
            if (v instanceof Number number) return number.doubleValue();
            try {
                return Double.parseDouble(v.toString());
            } catch (NumberFormatException _) {
                // ignore and try next key
            }
        }
        return null;
    }

    private record MetricInfo(boolean available, Double value, boolean higherIsBetter, String message) {
    }

    // Resolve metric value from Dependency
    private MetricInfo resolveMetricValue(Dependency dep, String metric) {
        if (dep == null || dep.score() == null) {
            return new MetricInfo(false, null, true, "No score metadata for dependency");
        }

        switch (metric.toLowerCase()) {
            case "stars" -> {
                return new MetricInfo(true, (double) dep.score().stars(), true, null);
            }
            case "downloads-per-month", "downloads" -> {
                return new MetricInfo(true, (double) dep.score().downloads(), true, null);
            }
            case "contributors-12-months", "contributors" -> {
                return new MetricInfo(true, (double) dep.score().contributors(), true, null);
            }
            case "age-since-initial-commit-days", "initial-commit-age" -> {
                if (dep.score().firstReleaseDateTime() == null) {
                    return new MetricInfo(false, null, true, "No initial commit / release date available");
                }
                long days = java.time.Duration.between(dep.score().firstReleaseDateTime(), java.time.LocalDateTime.now()).toDays();
                return new MetricInfo(true, (double) days, true, null);
            }
            case "open-issue-ratio" -> {
                return new MetricInfo(false, null, false, "Open-issue-ratio not available in dependency score");
            }
            default -> {
                return new MetricInfo(false, null, true, "Metric not supported: " + metric);
            }
        }
    }

    // Evaluate thresholds: return appropriate RuleFinding
    private RuleFinding evaluateThresholds(Dependency dep, String ruleId, Double value, boolean higherIsBetter, Double warnThreshold, Double failThreshold) {
        List<String> messages = new ArrayList<>();

        // Fail check
        if (failThreshold != null) {
            boolean fails = higherIsBetter ? (value < failThreshold) : (value > failThreshold);
            if (fails) {
                messages.add(String.format("Value %.2f failed threshold %.2f", value, failThreshold));
                return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.FAIL, messages);
            }
        }

        // Warn check
        if (warnThreshold != null) {
            boolean warns = higherIsBetter ? (value < warnThreshold) : (value > warnThreshold);
            if (warns) {
                messages.add(String.format("Value %.2f below warn threshold %.2f", value, warnThreshold));
                return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.WARN, messages);
            }
        }

        messages.add(String.format("Value %.2f meets thresholds", value));
        return new RuleFinding(dep, ruleId, RuleCategory.VALIDATION, RuleOutcome.PASS, messages);
    }

    private List<RuleFinding> applyLicenseRules(Dependency dep, LicenseRules rules) {
        List<RuleFinding> results = new ArrayList<>();

        Map<String, Object> all = safeAsMap(rules.getRules());

        Map<String, Object> licensePolicy = safeAsMap(all.get("license-policy"));
        Map<String, String> enforcement = safeAsStringMap(all.get("license-enforcement"));
        List<String> allowlist = safeAsList(all.get("license-allowlist"));
        List<String> denylist = safeAsList(all.get("license-denylist"));

        boolean hasCopyleftFail = false;
        Object hasCopyleftObj = all.get("has-copyleft-license");
        if (hasCopyleftObj instanceof Map<?,?> m) {
            Object f = m.get("fail");
            if (f instanceof Boolean b) hasCopyleftFail = b;
        }

        String detectedLicense = detectLicenseForDependency(dep, licensePolicy);

        // Denylist override
        if (detectedLicense != null && denylist.stream().anyMatch(s -> s.equalsIgnoreCase(detectedLicense))) {
            results.add(new RuleFinding(dep, "license-denylist", RuleCategory.LICENSE, RuleOutcome.FAIL, List.of("License " + detectedLicense + " is denylisted")));
            return results;
        }

        // Allowlist note
        if (detectedLicense != null && allowlist.stream().anyMatch(s -> s.equalsIgnoreCase(detectedLicense))) {
            results.add(new RuleFinding(dep, "license-allowlist", RuleCategory.LICENSE, RuleOutcome.PASS, List.of("License " + detectedLicense + " is allowlisted")));
        }

        // Map license to group and apply copyleft rule
        String group = mapLicenseToGroup(detectedLicense, licensePolicy);
        if (group == null) group = UNKNOWN;

        if (hasCopyleftFail && "strong-copyleft".equalsIgnoreCase(group)) {
            results.add(new RuleFinding(dep, "has-copyleft-license", RuleCategory.LICENSE, RuleOutcome.FAIL, List.of("Dependency uses strong copyleft license: " + detectedLicense)));
            return results;
        }

        // Determine enforcement action
        String action;
        if (detectedLicense == null) {
            action = enforcement.getOrDefault(NO_LICENSE_FILE, enforcement.getOrDefault(UNKNOWN, ALLOW));
        } else if (UNKNOWN.equalsIgnoreCase(group)) {
            action = enforcement.getOrDefault(NON_SPDX, enforcement.getOrDefault(UNKNOWN, ALLOW));
        } else {
            action = enforcement.getOrDefault(group, ALLOW);
        }

        RuleOutcome outcome = switch (action.toLowerCase()) {
            case ALLOW -> RuleOutcome.PASS;
            case "warn" -> RuleOutcome.WARN;
            case "fail" -> RuleOutcome.FAIL;
            default -> RuleOutcome.INFO;
        };

        String licenseLabel = detectedLicense == null ? "<unknown/no-license>" : detectedLicense;
        results.add(new RuleFinding(
                dep,
                "license-enforcement",
                RuleCategory.LICENSE,
                outcome,
                List.of("License: " + licenseLabel + ", policy-group: " + group + ", action: " + action)
        ));

        return results;
    }

    // Safe helpers to coerce objects from the rules map
    @SuppressWarnings("unchecked")
    private Map<String, Object> safeAsMap(Object o) {
        if (o instanceof Map) return (Map<String, Object>) o;
        return Map.of();
    }

    private Map<String, String> safeAsStringMap(Object o) {
        if (o instanceof Map) return ((Map<?, ?>) o).entrySet().stream()
                .filter(e -> e.getKey() != null && e.getValue() != null)
                .collect(Collectors.toMap(e -> e.getKey().toString(), e -> e.getValue().toString()));
        return Map.of();
    }

    private List<String> safeAsList(Object o) {
        if (o instanceof List) return ((List<?>) o).stream().map(Object::toString).toList();
        return List.of();
    }

    /**
     * Attempt to detect a license identifier for the dependency.
     * Strategies:
     *  - Reflectively check common properties (license, getLicense, licenses)
     *  - Heuristic: try to match known SPDX ids or license names from the licensePolicy map inside the dependency URL path
     */
    private String detectLicenseForDependency(Dependency dep, Map<String, Object> licensePolicy) {
        if (dep == null) return null;

        // Try reflection first
        String fromReflection = detectLicenseByReflection(dep);
        if (fromReflection != null) return fromReflection;

        // Then heuristics based on URL and known tokens
        return detectLicenseByUrl(dep, licensePolicy);
    }

    private String detectLicenseByReflection(Dependency dep) {
        try {
            var cls = dep.getClass();
            for (var m : cls.getMethods()) {
                String name = m.getName().toLowerCase();
                if (name.equals("license") || name.equals("getlicense")) {
                    Object v = m.invoke(dep);
                    if (v != null) return v.toString();
                }
                if (name.equals("licenses") || name.equals("getlicenses")) {
                    Object v = m.invoke(dep);
                    if (v instanceof Iterable<?> it) {
                        for (Object e : it) {
                            if (e != null) return e.toString();
                        }
                    } else if (v != null) return v.toString();
                }
            }
        } catch (Exception _) {
            // ignore reflection errors and fall back
        }
        return null;
    }

    private String detectLicenseByUrl(Dependency dep, Map<String, Object> licensePolicy) {
        if (dep.url() == null) return null;
        String path = dep.url().getPath();
        if (path == null) return null;
        String lower = path.toLowerCase();

        // Build a flattened set of known license tokens from licensePolicy
        Set<String> tokens = licensePolicy.values().stream()
                .filter(Iterable.class::isInstance)
                .flatMap(v -> StreamSupport.stream(((Iterable<?>) v).spliterator(), false))
                .map(Object::toString)
                .map(String::toLowerCase)
                .collect(Collectors.toSet());

        for (String t : tokens) {
            if (lower.contains(t)) return t;
        }
        return null;
    }

    private String mapLicenseToGroup(String licenseId, Map<String, Object> licensePolicy) {
        if (licenseId == null) return UNKNOWN;
        String lower = licenseId.toLowerCase();

        for (var entry : licensePolicy.entrySet()) {
            String group = entry.getKey();
            Object listObj = entry.getValue();
            if (!(listObj instanceof Iterable)) continue;
            for (Object o : (Iterable<?>) listObj) {
                if (o == null) continue;
                String s = o.toString();
                if (s.equalsIgnoreCase(licenseId) || s.toLowerCase().contains(lower) || lower.contains(s.toLowerCase())) {
                    return group;
                }
            }
        }
        return UNKNOWN;
    }
}
