import java.util.HashMap;
import java.util.Map;

public class Authorization {
    private static final Map<String, String> users = new HashMap<>();
    //Конструктор класса для логина и пароля
    static {
        users.put("user1", "qwerty123");
        users.put("admin", "admin123");
    }
    public Authorization(){
    }
    public void chekUser(String username, String password) {
        try{
            if(users.containsKey(username) && users.get(username).equals(password)){
                System.out.println("Успешная авторизация...");
            } else {
                System.out.println("Невереный логин и пароль...");
            }
        } catch(Exception err){
            System.err.println("Ошибка данных" + err.getMessage());
        }
    }
}
