# SonarQube Statistics Extractor

Простий Java Maven інструмент для отримання статистики проєктів з SonarQube.

## Налаштування

1. **Відредагуйте константи в `SonarQubeStatsExtractor.java`:**
```java
private static final String SONAR_URL = "https://your-sonarqube-server.com";
private static final String SONAR_TOKEN = "your-sonar-token-here";
```

2. **Отримання токену SonarQube:**
   - Увійдіть в SonarQube
   - Перейдіть в User → My Account → Security
   - Створіть новий User Token
   - Скопіюйте токен та вставте в код

## Компіляція та запуск

```bash
# Компіляція
mvn clean compile

# Запуск
mvn exec:java

# Або створення JAR
mvn clean package
java -cp target/sonarqube-stats-1.0.0.jar com.example.SonarQubeStatsExtractor
```

## Що отримуємо

Інструмент виводить дві таблиці:

1. **Форматована таблиця** для читання людиною
2. **CSV формат** для подальшого використання іншими інструментами

### Метрики що збираються:

**Quality Gates метрики:**
- Quality Gate Status (PASSED/FAILED/WARNING)
- Bugs (загальна кількість та нові)
- Vulnerabilities (загальна кількість та нові)
- Security Hotspots (загальна кількість та нові)
- Code Smells (загальна кількість та нові)
- Code Coverage (загальне та нове покриття)
- Duplicated Lines Density (загальна та нова)
- Reliability/Security/Maintainability Ratings
- Technical Debt
- Lines of Code

### Приклад виводу:

```
========================================================================================================
Проєкт                         Quality Gate    Bugs       New Bugs   Vuln       New Vuln   Code Smells...
========================================================================================================
my-awesome-project             PASSED          5          2          1          0          45         ...
another-project                FAILED          12         8          3          2          89         ...
========================================================================================================

--- CSV формат ---
Project,QualityGate,Bugs,NewBugs,Vulnerabilities,NewVulnerabilities,CodeSmells,NewCodeSmells...
my-awesome-project,PASSED,5,2,1,0,45,12,85.5,90.2,2.1,1.8,2d,15420
another-project,FAILED,12,8,3,2,89,45,65.2,45.8,5.7,8.2,5d,8920
```

## Перенаправлення виводу

```bash
# Збереження результатів у файл
mvn exec:java > sonar_stats_$(date +%Y%m%d).txt

# Тільки CSV частина
mvn exec:java 2>/dev/null | grep -A 1000 "CSV формат" > sonar_stats.csv
```

## Вимоги

- Java 11+
- Maven 3.6+
- Доступ до SonarQube API
- Валідний SonarQube токен з правами читання проєктів
