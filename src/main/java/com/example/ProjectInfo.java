ackage com.example;

public class ProjectInfo {
    private final String key;
    private final String name;
    
    public ProjectInfo(String key, String name) {
        this.key = key;
        this.name = name;
    }
    
    public String getKey() { return key; }
    public String getName() { return name; }
}
