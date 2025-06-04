package com.example;

import java.util.Map;

public class ProjectStatistics {
    private final ProjectInfo project;
    private final Map<String, String> metrics;
    
    public ProjectStatistics(ProjectInfo project, Map<String, String> metrics) {
        this.project = project;
        this.metrics = metrics;
    }
    
    public ProjectInfo getProject() { return project; }
    public Map<String, String> getMetrics() { return metrics; }
}
