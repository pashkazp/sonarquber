package com.example;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SonarMetricsFetcher {
    private static final String SONAR_URL = "http://localhost:9000"; // change to your SonarQube URL
    private static final String SONAR_TOKEN = "your_token_here"; // change to your token

    private static final String METRICS = String.join(",",
            "coverage",
            "duplicated_lines_density",
            "reliability_rating",
            "security_rating",
            "sqale_rating",
            "new_coverage",
            "new_duplicated_lines_density",
            "new_reliability_rating",
            "new_security_rating",
            "new_maintainability_rating");

    private final HttpClient client;
    private final ObjectMapper mapper = new ObjectMapper();

    private static final X509TrustManager TRUST_ALL_CERTS = new X509TrustManager() {
        @Override
        public void checkClientTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public void checkServerTrusted(java.security.cert.X509Certificate[] chain, String authType) {
        }

        @Override
        public java.security.cert.X509Certificate[] getAcceptedIssuers() {
            return new java.security.cert.X509Certificate[0];
        }
    };

    public SonarMetricsFetcher() {
        SSLContext sslContext;
        try {
            sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, new TrustManager[]{TRUST_ALL_CERTS}, new SecureRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            throw new RuntimeException("Failed to init SSL context", e);
        }
        SSLParameters params = new SSLParameters();
        params.setEndpointIdentificationAlgorithm("");
        client = HttpClient.newBuilder()
                .sslContext(sslContext)
                .sslParameters(params)
                .build();
    }

    private String authHeader() {
        String tokenColon = SONAR_TOKEN + ":";
        return "Basic " + Base64.getEncoder().encodeToString(tokenColon.getBytes(StandardCharsets.UTF_8));
    }

    private JsonNode getJson(String path) throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(URI.create(SONAR_URL + path))
                .header("Authorization", authHeader())
                .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException("Request failed: " + response.statusCode());
        }
        return mapper.readTree(response.body());
    }

    private List<String> getProjects() throws IOException, InterruptedException {
        JsonNode root = getJson("/api/projects/search?ps=500");
        return root.path("components").findValuesAsText("key");
    }

    private Map<String, String> getMetrics(String projectKey) throws IOException, InterruptedException {
        JsonNode root = getJson("/api/measures/component?component=" + projectKey + "&metricKeys=" + METRICS);
        return StreamSupport.stream(root.path("component").path("measures").spliterator(), false)
                .collect(Collectors.toMap(m -> m.path("metric").asText(), m -> m.path("value").asText()));
    }

    private void printHeader() {
        System.out.println(String.join(",",
                "project",
                "coverage",
                "duplicated_lines_density",
                "reliability_rating",
                "security_rating",
                "sqale_rating",
                "new_coverage",
                "new_duplicated_lines_density",
                "new_reliability_rating",
                "new_security_rating",
                "new_maintainability_rating"));
    }

    public void run() throws IOException, InterruptedException {
        List<String> projects = getProjects();
        printHeader();
        for (String project : projects) {
            Map<String, String> metrics = getMetrics(project);
            System.out.println(String.join(",",
                    project,
                    metrics.getOrDefault("coverage", ""),
                    metrics.getOrDefault("duplicated_lines_density", ""),
                    metrics.getOrDefault("reliability_rating", ""),
                    metrics.getOrDefault("security_rating", ""),
                    metrics.getOrDefault("sqale_rating", ""),
                    metrics.getOrDefault("new_coverage", ""),
                    metrics.getOrDefault("new_duplicated_lines_density", ""),
                    metrics.getOrDefault("new_reliability_rating", ""),
                    metrics.getOrDefault("new_security_rating", ""),
                    metrics.getOrDefault("new_maintainability_rating", "")));
        }
    }

    public static void main(String[] args) throws Exception {
        new SonarMetricsFetcher().run();
    }
}
