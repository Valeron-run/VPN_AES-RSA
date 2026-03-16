import java.io.DataOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class SendMessage {
    //OutputStream - абстрактный класс, который представляет собой поток для записи данных(Является базовым классом для всех потоков)
    private OutputStream out; // Поле класса - хранит метод OutputStream, нужно для записи данных

    public SendMessage(OutputStream out){
        this.out = out; // Конструктор класса, вызывается при создании нового обьекта класса
    }

    /**
     * Метод для отправки зашифрованного сообщения.
     *
     * @param message Исходное сообщение.
     * @param key     Секретный ключ для шифрования.
     * @param iv      Вектор инициализации (IV).
     */


    //Генерация ключа AES
    public static SecretKey generateAESKey() throws Exception {
        return CryptoUtils.generateAESKey();
    }
    //Генерация вектора инициализации
    public static IvParameterSpec generateIV(){
        return CryptoUtils.generateIV();
    }

    //Отправка зашифрованного сообщения
    public static void sendMessage(DataOutputStream out, String message, SecretKey key, IvParameterSpec iv){
        try{
            //Создания сообщения с метаданными
            String cryptoMess = "[TYPE:text][DATA:" + message + "]";

            //Шифрование сообщения
            String encryptMessage = CryptoUtils.encrypString(cryptoMess, key, iv);
            byte[] encryptMessageBytes = encryptMessage.getBytes(StandardCharsets.UTF_8);
            out.writeInt(encryptMessageBytes.length);
            out.write(encryptMessageBytes);            
            out.flush();
            
            //Отладочные сообщения
            //System.out.println("Отправка длинны сообщения: " + encryptMessageBytes.length);
            //System.out.println("Отправка сообщения: " + encryptMessage);
            //System.out.println("Зашифрованное сообщение отправлено на сервер");
        } catch(Exception err){
            System.err.println("Ошибка при отправки сообщения" + err.getMessage());
        }
    }
    //Получение расшифрованного сообщения
    public static String receiveMessage(String message){
        try{
            //Создаем паттерн(регулярное выражение)
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[TYPE:(.*?)\\]\\s*\\[DATA:(.*?)\\]");
            
            //Применяем шаблон(рег.выражение) к сообщению. Matcher = поисковик(ищет совпадение по рег.выражению)
            java.util.regex.Matcher matcher = pattern.matcher(message);


            String typePart = null;
            String typeData = null;

            if(matcher.find()){
                typePart = matcher.group(1).trim();
                typeData = matcher.group(2).trim();
            } else {
                throw new IllegalAccessException("Не удалось найти TYPE или DATA в расшифрованном сообещении: " + message);
            }
            return typeData;
        } catch (Exception err){
            System.err.println("Ошибка при расшифровании и принятии сообщения" + err.getMessage());
            return null;
        }
    }
    //Хэширование Логина или Пароля(и его отправка)
    public void hashPassLogin(String input){
        try{
            //Хэширование сообщения
            String hashMessage = CryptoUtils.hashString(input);
            out.write(hashMessage.getBytes(StandardCharsets.UTF_8));
            out.flush();

            System.out.println("Отправка хэшированного сообщения" + hashMessage);
        } catch(Exception err){
            System.out.println("Ошибка при отправки логина/пароля" + err.getMessage());
        }
    }
}
