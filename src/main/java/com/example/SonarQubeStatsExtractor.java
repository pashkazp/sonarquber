package com.example;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.*;

public class SonarQubeStatsExtractor {
    private static final Logger logger = LoggerFactory.getLogger(SonarQubeStatsExtractor.class);
    
    // Захардкожені налаштування
    private static final String SONAR_URL = "https://your-sonarqube-server.com";
    private static final String SONAR_TOKEN = "your-sonar-token-here";
    
    // Ключові метрики для Quality Gates
    private static final String[] METRICS = {
        "alert_status",
        "bugs", 
        "new_bugs",
        "vulnerabilities", 
        "new_vulnerabilities",
        "security_hotspots", 
        "new_security_hotspots",
        "code_smells", 
        "new_code_smells",
        "coverage", 
        "new_coverage",
        "duplicated_lines_density", 
        "new_duplicated_lines_density",
        "reliability_rating", 
        "new_reliability_rating",
        "security_rating", 
        "new_security_rating", 
        "sqale_rating", 
        "new_maintainability_rating",
        "sqale_index", 
        "new_technical_debt",
        "ncloc",
        "new_lines_to_cover"
    };
    
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final CloseableHttpClient httpClient = HttpClients.createDefault();
    
    public static void main(String[] args) {
        SonarQubeStatsExtractor extractor = new SonarQubeStatsExtractor();
        try {
            extractor.extractAndPrintStatistics();
        } catch (Exception e) {
            logger.error("Помилка під час виконання: ", e);
        } finally {
            try {
                extractor.httpClient.close();
            } catch (IOException e) {
                logger.error("Помилка закриття HTTP клієнта: ", e);
            }
        }
    }
    
    public void extractAndPrintStatistics() throws IOException {
        logger.info("Отримання списку проєктів...");
        List<ProjectInfo> projects = getProjects();
        
        logger.info("Знайдено проєктів: {}", projects.size());
        
        List<ProjectStatistics> statisticsList = new ArrayList<>();
        
        for (ProjectInfo project : projects) {
            logger.info("Обробка проєкту: {}", project.getName());
            ProjectStatistics stats = getProjectStatistics(project);
            statisticsList.add(stats);
        }
        
        printStatisticsTable(statisticsList);
    }
    
    private List<ProjectInfo> getProjects() throws IOException {
        String url = SONAR_URL + "/api/projects/search?ps=500";
        String response = makeApiCall(url);
        
        JsonNode root = objectMapper.readTree(response);
        JsonNode components = root.get("components");
        
        List<ProjectInfo> projects = new ArrayList<>();
        for (JsonNode component : components) {
            ProjectInfo project = new ProjectInfo(
                component.get("key").asText(),
                component.get("name").asText()
            );
            projects.add(project);
        }
        
        return projects;
    }
    
    private ProjectStatistics getProjectStatistics(ProjectInfo project) throws IOException {
        String metricsParam = String.join(",", METRICS);
        String url = String.format("%s/api/measures/component?component=%s&metricKeys=%s", 
                                 SONAR_URL, project.getKey(), metricsParam);
        
        String response = makeApiCall(url);
        JsonNode root = objectMapper.readTree(response);
        JsonNode measures = root.get("component").get("measures");
        
        Map<String, String> metricsMap = new HashMap<>();
        for (JsonNode measure : measures) {
            String metric = measure.get("metric").asText();
            String value = measure.has("value") ? measure.get("value").asText() : "N/A";
            metricsMap.put(metric, value);
        }
        
        return new ProjectStatistics(project, metricsMap);
    }
    
    private String makeApiCall(String url) throws IOException {
        HttpGet request = new HttpGet(url);
        request.setHeader("Authorization", "Bearer " + SONAR_TOKEN);
        request.setHeader("Accept", "application/json");
        
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            HttpEntity entity = response.getEntity();
            if (entity != null) {
                return EntityUtils.toString(entity);
            }
            throw new IOException("Порожня відповідь від SonarQube");
        }
    }
    
    private void printStatisticsTable(List<ProjectStatistics> statisticsList) {
        // Заголовок таблиці
        System.out.println("\n" + "=".repeat(200));
        System.out.printf("%-30s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-15s %-15s%n",
            "Проєкт", "Quality Gate", "Bugs", "New Bugs", "Vuln", "New Vuln", 
            "Code Smells", "New Smells", "Coverage", "New Coverage", 
            "Duplication", "New Dupl", "Tech Debt", "Lines");
        System.out.println("=".repeat(200));
        
        // Дані проєктів
        for (ProjectStatistics stats : statisticsList) {
            Map<String, String> metrics = stats.getMetrics();
            
            System.out.printf("%-30s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-15s %-15s%n",
                truncate(stats.getProject().getName(), 29),
                getQualityGateStatus(metrics.get("alert_status")),
                metrics.getOrDefault("bugs", "0"),
                metrics.getOrDefault("new_bugs", "0"),
                metrics.getOrDefault("vulnerabilities", "0"),
                metrics.getOrDefault("new_vulnerabilities", "0"),
                metrics.getOrDefault("code_smells", "0"),
                metrics.getOrDefault("new_code_smells", "0"),
                formatPercentage(metrics.get("coverage")),
                formatPercentage(metrics.get("new_coverage")),
                formatPercentage(metrics.get("duplicated_lines_density")),
                formatPercentage(metrics.get("new_duplicated_lines_density")),
                formatTechDebt(metrics.get("sqale_index")),
                metrics.getOrDefault("ncloc", "0")
            );
        }
        
        System.out.println("=".repeat(200));
        
        // CSV формат для інших інструментів
        System.out.println("\n--- CSV формат ---");
        System.out.println("Project,QualityGate,Bugs,NewBugs,Vulnerabilities,NewVulnerabilities,CodeSmells,NewCodeSmells,Coverage,NewCoverage,Duplication,NewDuplication,TechnicalDebt,Lines");
        
        for (ProjectStatistics stats : statisticsList) {
            Map<String, String> metrics = stats.getMetrics();
            System.out.printf("%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s%n",
                escapeCSV(stats.getProject().getName()),
                getQualityGateStatus(metrics.get("alert_status")),
                metrics.getOrDefault("bugs", "0"),
                metrics.getOrDefault("new_bugs", "0"),
                metrics.getOrDefault("vulnerabilities", "0"),
                metrics.getOrDefault("new_vulnerabilities", "0"),
                metrics.getOrDefault("code_smells", "0"),
                metrics.getOrDefault("new_code_smells", "0"),
                metrics.getOrDefault("coverage", "0"),
                metrics.getOrDefault("new_coverage", "0"),
                metrics.getOrDefault("duplicated_lines_density", "0"),
                metrics.getOrDefault("new_duplicated_lines_density", "0"),
                metrics.getOrDefault("sqale_index", "0"),
                metrics.getOrDefault("ncloc", "0")
            );
        }
    }
    
    private String getQualityGateStatus(String status) {
        if (status == null) return "UNKNOWN";
        switch (status.toUpperCase()) {
            case "OK": return "PASSED";
            case "ERROR": return "FAILED";
            case "WARN": return "WARNING";
            default: return "UNKNOWN";
        }
    }
    
    private String formatPercentage(String value) {
        if (value == null || value.equals("N/A")) return "N/A";
        try {
            return String.format("%.1f%%", Double.parseDouble(value));
        } catch (NumberFormatException e) {
            return value;
        }
    }
    
    private String formatTechDebt(String minutes) {
        if (minutes == null || minutes.equals("N/A")) return "N/A";
        try {
            long mins = Long.parseLong(minutes);
            long hours = mins / 60;
            long days = hours / 8; // 8 робочих годин на день
            if (days > 0) {
                return days + "d";
            } else if (hours > 0) {
                return hours + "h";
            } else {
                return mins + "m";
            }
        } catch (NumberFormatException e) {
            return minutes;
        }
    }
    
    private String truncate(String text, int maxLength) {
        if (text.length() <= maxLength) return text;
        return text.substring(0, maxLength - 3) + "...";
    }
    
    private String escapeCSV(String value) {
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
}
