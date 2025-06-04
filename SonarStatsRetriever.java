package com.example.sonarstats;

import org.json.JSONArray;
import org.json.JSONObject;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;

public class SonarStatsRetriever {

    // --- КОНФІГУРАЦІЯ ---
    // ЗАМІНІТЬ ЦІ ЗНАЧЕННЯ НА ВАШІ
    private static final String SONARQUBE_URL = "YOUR_SONARQUBE_URL"; // Наприклад: "http://localhost:9000"
    private static final String SONARQUBE_TOKEN = "YOUR_SONARQUBE_TOKEN";
    // --- КІНЕЦЬ КОНФІГУРАЦІЇ ---

    // Метрики, які потрібно отримати.
    // Ви можете додати або видалити метрики за потреби.
    // Див. документацію SonarQube Web API (/api/metrics/search) для повного списку.
    private static final String[] METRIC_KEYS_ARRAY = {
        "bugs", "vulnerabilities", "code_smells", "coverage", "duplicated_lines_density",
        "sqale_debt_ratio", "security_rating", "reliability_rating", "sqale_rating", // Загальні метрики
        "new_bugs", "new_vulnerabilities", "new_code_smells", "new_coverage",
        "new_duplicated_lines_density", "new_sqale_debt_ratio" // Метрики для нового коду
    };
    private static final String METRIC_KEYS_PARAM = String.join(",", METRIC_KEYS_ARRAY);

    private final HttpClient httpClient;

    public SonarStatsRetriever() {
        this.httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .build();
    }

    /**
     * Головний метод для отримання та виведення статистики.
     */
    public void fetchAndPrintStats() {
        if ("YOUR_SONARQUBE_URL".equals(SONARQUBE_URL) || "YOUR_SONARQUBE_TOKEN".equals(SONARQUBE_TOKEN)) {
            System.err.println("ПОМИЛКА: Будь ласка, встановіть SONARQUBE_URL та SONARQUBE_TOKEN у файлі SonarStatsRetriever.java");
            return;
        }

        try {
            List<Project> projects = getProjects();
            if (projects.isEmpty()) {
                System.out.println("Проєкти не знайдено або сталася помилка під час їх отримання.");
                return;
            }

            // Друк CSV заголовка
            StringJoiner headerJoiner = new StringJoiner(",");
            headerJoiner.add("ProjectKey").add("ProjectName");
            for (String metricKey : METRIC_KEYS_ARRAY) {
                headerJoiner.add(metricKey);
            }
            System.out.println(headerJoiner.toString());

            // Отримання та друк метрик для кожного проєкту
            for (Project project : projects) {
                Map<String, String> measures = getProjectMeasures(project.getKey());
                
                StringJoiner rowJoiner = new StringJoiner(",");
                rowJoiner.add(escapeCsvValue(project.getKey())).add(escapeCsvValue(project.getName()));
                
                for (String metricKey : METRIC_KEYS_ARRAY) {
                    rowJoiner.add(escapeCsvValue(measures.getOrDefault(metricKey, "")));
                }
                System.out.println(rowJoiner.toString());
            }

        } catch (Exception e) {
            System.err.println("Сталася помилка: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Отримує список проєктів з SonarQube.
     * @return Список об'єктів Project.
     * @throws Exception Якщо сталася помилка під час HTTP-запиту або обробки JSON.
     */
    private List<Project> getProjects() throws Exception {
        List<Project> projects = new ArrayList<>();
        int page = 1;
        int pageSize = 100; // SonarQube API зазвичай має обмеження на розмір сторінки (наприклад, 100 або 500)
        boolean moreProjects = true;

        while(moreProjects) {
            // Додаємо параметри пагінації до URL
            String url = SONARQUBE_URL + "/api/projects/search?p=" + page + "&ps=" + pageSize;
            HttpRequest request = buildSonarApiRequest(url);

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() != 200) {
                throw new RuntimeException("Не вдалося отримати проєкти. Код стану: " + response.statusCode() + "\nВідповідь: " + response.body());
            }

            JSONObject jsonResponse = new JSONObject(response.body());
            JSONArray components = jsonResponse.getJSONArray("components");

            if (components.length() == 0) {
                moreProjects = false; // Більше немає проєктів для завантаження
            } else {
                for (int i = 0; i < components.length(); i++) {
                    JSONObject component = components.getJSONObject(i);
                    projects.add(new Project(component.getString("key"), component.getString("name")));
                }
                page++; // Перехід на наступну сторінку
            }
            
            // Перевірка пагінації (якщо загальна кількість відома)
            // JSONObject paging = jsonResponse.optJSONObject("paging");
            // if (paging != null) {
            //     int total = paging.getInt("total");
            //     if (page * pageSize >= total) {
            //         moreProjects = false;
            //     }
            // } else if (components.length() < pageSize) { 
            //    // Якщо paging не надано, але отримано менше елементів, ніж розмір сторінки
            //    moreProjects = false;
            // }
             if (components.length() < pageSize) { // Простіша перевірка, якщо paging не використовується активно
                moreProjects = false;
            }
        }
        return projects;
    }

    /**
     * Отримує метрики для вказаного проєкту.
     * @param projectKey Ключ проєкту SonarQube.
     * @return Мапа, де ключ - це ключ метрики, а значення - її значення.
     * @throws Exception Якщо сталася помилка під час HTTP-запиту або обробки JSON.
     */
    private Map<String, String> getProjectMeasures(String projectKey) throws Exception {
        Map<String, String> measuresMap = new HashMap<>();
        // Кодуємо projectKey для безпечного використання в URL
        String encodedProjectKey = URLEncoder.encode(projectKey, StandardCharsets.UTF_8.toString());
        String url = SONARQUBE_URL + "/api/measures/component?component=" + encodedProjectKey + "&metricKeys=" + METRIC_KEYS_PARAM;
        
        HttpRequest request = buildSonarApiRequest(url);
        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            System.err.println("Попередження: Не вдалося отримати метрики для проєкту " + projectKey + ". Код стану: " + response.statusCode() + "\nВідповідь: " + response.body());
            // Повертаємо порожню мапу, щоб продовжити з іншими проєктами
            return measuresMap;
        }

        JSONObject jsonResponse = new JSONObject(response.body());
        JSONObject component = jsonResponse.getJSONObject("component");
        JSONArray measures = component.getJSONArray("measures");

        for (int i = 0; i < measures.length(); i++) {
            JSONObject measure = measures.getJSONObject(i);
            String metric = measure.getString("metric");
            String value = "";
            // Деякі метрики можуть мати 'value', деякі 'period.value' для нового коду
            if (measure.has("value")) {
                value = measure.getString("value");
            } else if (measure.has("period") && measure.getJSONObject("period").has("value")) {
                // Це для метрик нового коду, які можуть бути вкладені
                value = measure.getJSONObject("period").getString("value");
            }
            measuresMap.put(metric, value);
        }
        return measuresMap;
    }

    /**
     * Будує HTTP-запит до SonarQube API з необхідною автентифікацією.
     * @param urlString URL-адреса API.
     * @return Об'єкт HttpRequest.
     */
    private HttpRequest buildSonarApiRequest(String urlString) {
        // Автентифікація за допомогою токена (токен як ім'я користувача, порожній пароль)
        String auth = SONARQUBE_TOKEN + ":";
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes(StandardCharsets.UTF_8));

        return HttpRequest.newBuilder()
                .uri(URI.create(urlString))
                .header("Authorization", "Basic " + encodedAuth)
                .GET()
                .build();
    }
    
    /**
     * Екранує значення для CSV (обробляє коми та лапки).
     * @param value Рядок для екранування.
     * @return Екранований рядок.
     */
    private String escapeCsvValue(String value) {
        if (value == null) {
            return "";
        }
        // Якщо значення містить кому, лапки або новий рядок, беремо його в лапки
        // і подвоюємо внутрішні лапки.
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }

    /**
     * Внутрішній клас для представлення проєкту SonarQube.
     */
    private static class Project {
        private final String key;
        private final String name;

        public Project(String key, String name) {
            this.key = key;
            this.name = name;
        }

        public String getKey() {
            return key;
        }

        public String getName() {
            return name;
        }
    }

    public static void main(String[] args) {
        SonarStatsRetriever retriever = new SonarStatsRetriever();
        retriever.fetchAndPrintStats();
    }
}
