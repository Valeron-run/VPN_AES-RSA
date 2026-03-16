import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;


class UserData{
    String hashedLogin;
    String hashedPassword;

    //Логин/Пароль
    public UserData(String hashedLogin, String hashedPassword){
        this.hashedLogin = hashedLogin;
        this.hashedPassword = hashedPassword;
    }
}

class ClientSession{
    SecretKey key;
    IvParameterSpec iv;
    
    private static final Map<String, UserData> userTable = new ConcurrentHashMap<>();

    //volatile boolean initialized - гарантирует, что все потоки увидят актуальное значение флага
    private static volatile boolean initialized = false;
    
    //synchronized - гарантирует, что только один поток может выполнить этот метод одновременно
    private static synchronized void initialize() {
        if (!initialized) {
            try {
                System.out.println("Инициализация базы пользователей...");
                registerUserForTable("user1", "qwerty123");
                registerUserForTable("user2", "qwerty1234");
                initialized = true;
                System.out.println("База пользователей инициализирована");
            } catch(Exception err) {
                System.err.println("Ошибка при инициализации пользователей: " + err.getMessage());
            }
        }
    }
    
    static {
        initialize(); // Вызов при загрузке класса
    }

    public ClientSession(SecretKey key, IvParameterSpec iv){
        this.key = key;
        this.iv = iv;
    }
    
    public static void registerUserForTable(String login, String password){
        // Хэшируем логин и пароль
        String hashedLogin = CryptoUtils.hashString(login);
        String hashedPassword = CryptoUtils.hashString(password);

        // Проверяем, есть ли уже такой пользователь
        if (userTable.containsKey(hashedLogin)) {
            System.out.println("Пользователь уже зарегистрирован: " + hashedLogin);
            return;
        }

        // записываем пользователя
        userTable.put(hashedLogin, new UserData(hashedLogin, hashedPassword));
        System.out.println("Пользователь зарегистрирован: " + login);
    }

    public static void registerUser(String hashedLogin, String hashedPassword){
        initialize();
        userTable.put(hashedLogin, new UserData(hashedLogin, hashedPassword));
        System.out.println("Пользователь зарегистрирован: " + hashedLogin);
    }

    public static boolean validateData(String hashedLogin, String hashedPassword){
        initialize();
        System.out.println("Проверка логина: " + hashedLogin);
        UserData userLog = userTable.get(hashedLogin);
        
        if (userLog == null) {
            System.out.println("Пользователь не найден");
            return false;
        }

        System.out.println("Хэш пароля из базы: " + userLog.hashedPassword);
        System.out.println("Хэш пароля для проверки: " + hashedPassword);

        return userLog.hashedPassword.equals(hashedPassword);
    }
}