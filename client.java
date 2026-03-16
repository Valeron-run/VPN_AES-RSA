import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class client {
    public static void main(String[] args){
        int port = 8080;
        String local = "192.168.122.1";
        String file = "/home/vasta/Project/Java/vpncrypto/text.txt";

        try(Socket socket = new Socket(local, port);
            InputStream in = socket.getInputStream(); //Поток чтения сервера
            OutputStream out = socket.getOutputStream(); //Поток для отправки сообщения на сервер
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in)); //Чтение данных пользователя
            FileInputStream fileInputStream = new FileInputStream(file); //Поток для записи файла в битовое представление
            OutputStream outputStream = socket.getOutputStream();
            DataInputStream dataIn = new DataInputStream(in);
            DataOutputStream dataOut = new DataOutputStream(out)){ //Отправка файла на сервер
            //Инициализация публичного и приватного ключа
            PublicKey publicKey = null;
            PrivateKey privateKey = null; 
            
            //DataInputStream - позволяет читать примитивные типы данных по типу readInt(), readDouble() и т.д.
            

            //Генерация ключей один раз при запуске (Отправка серверу ключа RSA и получение от сервера ключа AES)
            try{
                KeyPair rsaKeyPair = CryptoUtils.generateRSAKeyPair();
                publicKey = CryptoUtils.getPublicKey(rsaKeyPair);
                privateKey = CryptoUtils.getPrivateKey(rsaKeyPair);
            } catch (Exception err){
                System.err.println("Ошибка при генерации ключа");
            }
            //Отправка публичного ключа на сервер(С начало отправляем длину сообщения, только после отправляем само соообщение)
            byte[] publicKeyBytes = publicKey.getEncoded();
            dataOut.writeInt(publicKeyBytes.length);
            dataOut.write(publicKeyBytes);
            dataOut.flush();
            System.out.println("Публичный ключ отправлен на сервер");

            //Принятие  AES ключа и iv от сервера
            int encryptAESKeyIVLen = dataIn.readInt(); //Читаем длину ключа
            byte[] encryptAESKeyIV = new byte[encryptAESKeyIVLen]; //выделяем определенную длину для тения сообщения
            dataIn.readFully(encryptAESKeyIV); //Читаем строго опредленную длину
            System.out.println("Зашифрованный ключ принят от сервера");

            SecretKey key = null;
            IvParameterSpec iv = null;
            try{
                CryptoUtils.DecryptedKeyIv result = CryptoUtils.parseEncryptedData(privateKey, encryptAESKeyIV);
                key = result.getKey();
                iv = result.getIv();
            } catch(Exception err){
                System.err.println("Ошибка при расшифровке ключей" + err.getMessage());
                err.printStackTrace();
            }
            PassLog(reader, dataOut, key, iv, dataIn);
            if (socket.isClosed()) {
                System.out.println("Соединение закрыто из-за неудачной авторизации");
                return;
            }
            System.out.println("Команды: \n1)Send - отправить файл \n2)Exit - выйти с сервера");
                while(true){
                    try{
                        System.out.println("Ввод сообщения:");
                        //Ввод сообщения, зашифровка и отправка на север
                        String message = reader.readLine();
                        if("Exit".equalsIgnoreCase(message)){
                            System.out.println("Закрытие");
                            break;
                        }else if ("Send".equals(message)) {
                            System.out.println("Отправка файла...");
                            SendAccFile.sendFile(file, dataOut, key, iv);
                            continue;
                        } 
                        SendMessage.sendMessage(dataOut, message, key, iv);

                        socket.setSoTimeout(2000);
                        //Принятия сообщения, расшифровка
                        int messageLen = dataIn.readInt(); 
                        byte[] serverWord = new byte[messageLen];
                        dataIn.readFully(serverWord);
                        String serverMessage = new String(serverWord, StandardCharsets.UTF_8);
                        String desServerMesage = CryptoUtils.decrypString(serverMessage, key, iv);
                        System.out.println(SendMessage.receiveMessage(desServerMesage));
                          
                }catch (Exception err){
                    System.err.println(err);
                }
            } 
        } catch (Exception err){
            System.err.println("Error" + err.getMessage());
        }
    }
   private static boolean PassLog(BufferedReader reader, DataOutputStream dataOut, SecretKey key, IvParameterSpec iv, DataInputStream dataIn) {
    while(true){
        try{
            System.out.println("Вход/Регистрация");
            System.out.println("Впишите команду для продолжения");
            String command = reader.readLine();

            String operation = null;
            switch (command.trim().toLowerCase()) {
                case "вход":
                    operation = "validation";
                    break;
                case "регистрация":
                    operation = "registration";
                    break;
                default:
                    System.out.println("Неизвестная команда, попробуйте снова");
                    continue;
            }
            
            // Сбор метаданных
            String data = Valid(reader);
            if (data == null) {
                System.out.println("Ошибка ввода, попробуйте снова");
                continue;
            }
            
            String metaFullData = "[TYPE:"+ operation +"]" + data;
            System.out.println("Отправляемые данные: " + metaFullData);
            
            // Шифрование и отправка
            String encryptMetaData = CryptoUtils.encrypString(metaFullData, key, iv);
            byte[] encryptMetaDataBytes = encryptMetaData.getBytes(StandardCharsets.UTF_8);
            dataOut.writeInt(encryptMetaDataBytes.length);
            dataOut.write(encryptMetaDataBytes);
            dataOut.flush();
            
            System.out.println("Логин и пароль отправлены на сервер");
            
            // ЖДЕМ ОТВЕТ ОТ СЕРВЕРА
            int responseLen = dataIn.readInt();
            byte[] responseBytes = new byte[responseLen];
            dataIn.readFully(responseBytes);
            String serverResponse = new String(responseBytes, StandardCharsets.UTF_8);
            String decryptedResponse = CryptoUtils.decrypString(serverResponse, key, iv);
            
            System.out.println("Ответ сервера: " + decryptedResponse);
            
            // ПРОВЕРЯЕМ УСПЕШНОСТЬ - ИСПРАВЛЕННОЕ РЕГУЛЯРНОЕ ВЫРАЖЕНИЕ
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[TYPE:(.*?)\\]\\s*\\[DATA:(.*?)\\]");
            java.util.regex.Matcher matcher = pattern.matcher(decryptedResponse);

            String typePart = null;
            String input = null;
            if(matcher.find()){
                typePart = matcher.group(1).trim();
                input = matcher.group(2).trim();
                System.out.println("DEBUG: typePart = " + typePart + ", input = " + input);
            } else {
                System.err.println("Не удалось распарсить ответ сервера: " + decryptedResponse);
                continue;
            }
            
            // ИСПРАВЛЕННАЯ ЛОГИКА ПРОВЕРКИ
            if (input.startsWith("SUCCESS:")) {
                System.out.println("Авторизация успешна! " + input.substring(8));
                return true; // ВОЗВРАЩАЕМ true ПРИ УСПЕХЕ
            } else if (input.startsWith("ERROR:")) {
                System.out.println("Ошибка: " + input.substring(6));
                continue; // Остаемся в цикле авторизации
            } else {
                System.out.println("Неизвестный ответ сервера: " + input);
                continue;
            }
            
        } catch(Exception err){
            System.err.println("Ошибка при авторизации: " + err.getMessage());
            err.printStackTrace(); // Добавляем для отладки
            return false;
        }
    }  
}
    private static String Valid(BufferedReader reader){
            try{
                System.out.println("Логин: ");
                String login = reader.readLine();

                // Проверяем, что логин не пустой
                if (login == null || login.trim().isEmpty()) {
                    throw new IllegalArgumentException("Логин не может быть пустым.");
                }
                System.out.println("Пароль: ");
                String password = reader.readLine();
                // Проверяем, что пароль не пустой
                if (password == null || password.trim().isEmpty()) {
                    throw new IllegalArgumentException("Пароль не может быть пустым.");
                }

                if (login == null || login.isEmpty() || password == null || password.isEmpty()) {
                    throw new IllegalArgumentException("Логин и пароль не могут быть пустыми.");
                }
                String metaData = "[LOGIN:" + CryptoUtils.hashString(login) + "]" + "[PASSWORD:" + CryptoUtils.hashString(password) + "]";
                return metaData;
            } catch(Exception err){
                System.out.println("Ошибка при создании метаданных: " + err.getMessage());
                return null;
            }
            
        }
}


