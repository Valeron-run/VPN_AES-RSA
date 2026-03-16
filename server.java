import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Base64;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;

public class server {
    public static Map<String, ClientSession> activeSessions = new ConcurrentHashMap<>();
    
    public static void main(String[] args){
        //Порт прослушивания
        int port = 8080;

        //Выделяем 10 потоков на чтение 
        ExecutorService executor = Executors.newFixedThreadPool(10);

        try(ServerSocket server = new ServerSocket(port)){
            System.out.println("Открытие сервера на порту 8080");
            while(true){
                Socket clientSocket = server.accept();//Подключение клиента
                System.out.println("Клиент подключился: " + clientSocket.getInetAddress());
                executor.execute(new ClientHandler(clientSocket));
            }
        } catch(Exception err){
            System.err.println("Ошибка при открытии сервера" + err.getMessage());
        }

    }
    
    static class ClientHandler implements Runnable{
        private final Socket clientSocket;
        //Инициализация ключей один раз для каждого клиента(в ином случае будут использоваться глобальные ключи)
        private SecretKey key;
        private IvParameterSpec iv;

        public ClientHandler(Socket clientSocket){
            this.clientSocket = clientSocket;
        }
        //Обьядинить хэш сумму + файл (Разбить по индексам)
        //Решить проблему с чтением сообщения
        //Доделать многопоточность
        
        @Override
        public void run() {
            String clientIp = clientSocket.getInetAddress().getHostAddress();
            String fileOutput = "/home/vasta/Project/Java/vpncrypto/output_text.txt";
                try (InputStream in = clientSocket.getInputStream();
                OutputStream out = clientSocket.getOutputStream();
                DataInputStream dataIn = new DataInputStream(in);
                DataOutputStream dataOut = new DataOutputStream(out)) {

                // Получение публичного ключа RSA и отправка AES 
                sendKeyIv(dataIn, dataOut);
                System.out.println("Публичный ключ принят сервером");    
        
                ValidateRegOrAccess(dataIn, dataOut, clientIp);
                 System.out.println("Подключение клиента...");

                while (!clientSocket.isClosed()) {
                    try {
                        // Чтение длины сообщения
                        int messageLen = dataIn.readInt();
                        // Если клиент закрыл соединение, readInt() вернет -1 или выбросит исключение
                        if (messageLen < 0) {
                            break;
                        }
                
                        byte[] clientMessage = new byte[messageLen];
                        dataIn.readFully(clientMessage);
                        String combinedMessage = new String(clientMessage, StandardCharsets.UTF_8);
                        String descyptCombinedMesage = CryptoUtils.decrypString(combinedMessage, key, iv);

                if (descyptCombinedMesage == null || descyptCombinedMesage.isEmpty()) {
                    System.err.println("Расшифрованное сообщение пустое");
                    continue; // Продолжаем цикл вместо выброса исключения
                }
                System.out.println("Расшифрованное сообщение: " + descyptCombinedMesage);

                // Обработка типа сообщения
                String typePart = null;
                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[TYPE:(.*?)\\]");
                java.util.regex.Matcher matcher = pattern.matcher(descyptCombinedMesage);

                if (matcher.find()) {
                    typePart = matcher.group(1).trim();
                    System.out.println("DEBUG: Регулярные выражения - TYPE: " + typePart);
                } else {
                    System.err.println("Не удалось найти TYPE в сообщении: " + descyptCombinedMesage);
                    continue;
                }

                // Обработка команд
                switch (typePart) {
                    case "text":
                        String messageText = SendMessage.receiveMessage(descyptCombinedMesage);
                        System.out.println("Получено сообщение: " + messageText);
                        
                        // ОТПРАВКА ОТВЕТА КЛИЕНТУ
                        String response = "Сервер получил: " + messageText;
                        SendMessage.sendMessage(dataOut, response, key, iv);
                        break;
                    case "file":
                        SendAccFile.acceptFile(fileOutput, descyptCombinedMesage);
                        // ОТПРАВКА ПОДТВЕРЖДЕНИЯ
                        SendMessage.sendMessage(dataOut, "Файл получен", key, iv);
                        break;
                    default:
                        System.out.println("Неправильный тип сообщения");
                        SendMessage.sendMessage(dataOut, "Неизвестный тип сообщения", key, iv);
                        break;
                }

            } catch (EOFException e) {
                System.out.println("Клиент закрыл соединение");
                break;
            } catch (IOException e) {
                System.err.println("Ошибка ввода-вывода: " + e.getMessage());
                break;
            } catch (Exception e) {
                System.err.println("Ошибка обработки сообщения: " + e.getMessage());
                // Продолжаем цикл для обработки следующих сообщений
            }
        }

    } catch (Exception err) {
        System.err.println("Ошибка потока клиента: " + err.getMessage());
    } finally {
        activeSessions.remove(clientIp);
        System.out.println("Обработчик клиента завершил работу" + clientIp);
    }
}
        private void sendKeyIv(DataInputStream dataIn, DataOutputStream dataOut){
            try{
                //Читаем с начало длину сообщения(в байтах)
                int keyLength = dataIn.readInt();
                System.out.println("Длина публичного ключа: " + keyLength);

                //Выделаем определенное кол-во байтов на чтение сообщения
                byte[] publicKeyBytes = new byte[keyLength];

                //Читаем строго определенную длину
                dataIn.readFully(publicKeyBytes);
                PublicKey publicKey = CryptoUtils.extractKeyPub(publicKeyBytes);
                System.out.println("Публичный ключ принят сервером");

                //Генерация key и iv
                this.key = CryptoUtils.generateAESKey();
                this.iv = CryptoUtils.generateIV();
                System.out.println("AES-ключ: " + (this.key != null ? "снегерирован" : "null"));
                System.out.println("IV: " + (this.iv != null ? "снегерирован" : "null"));

                //Сборка key and iv в один массив байтов и последующая отправка
                byte[] sendKeyIV = CryptoUtils.prepareEncryptData(publicKey, this.key, this.iv);
                System.out.println("Длина зашифрованных данных для отправки: " + sendKeyIV.length);

                dataOut.writeInt(sendKeyIV.length);
                dataOut.write(sendKeyIV);
                dataOut.flush();

                System.out.println("Key и IV отправлены клиенту");
            } catch (Exception err){
                System.err.println("Ошибка при отправке AES ключа");
                err.printStackTrace();
            }
        }

        private void ValidateRegOrAccess(DataInputStream dataIn, DataOutputStream dataOut, String clientIp){
            try{
                //Принятие длинные сообщения
                int validLen = dataIn.readInt();
                System.out.println("Длина данных: " + validLen);

                //Выделили определенное кол-во байтов под сообщение + записали его в массив
                byte[] validMas = new byte[validLen];
                dataIn.readFully(validMas);

                //Перевод массива байтов в строку(последующий парс сообщения)
                String validMasStr = new String(validMas, StandardCharsets.UTF_8);
                String validMasStrDes = CryptoUtils.decrypString(validMasStr, this.key, this.iv);
                System.out.println("Расшифрованные данные: " + validMasStrDes);

                String typePart = null;
                String login = null;
                String password = null;

                java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("\\[TYPE:(.*?)\\]\\s*\\[LOGIN:(.*?)\\]\\s*\\[PASSWORD:(.*?)\\]");
                java.util.regex.Matcher matcher = pattern.matcher(validMasStrDes);

                if(matcher.find()){
                    typePart = matcher.group(1).trim();
                    login = matcher.group(2).trim();
                    password = matcher.group(3).trim();
                }

                System.out.println(typePart);
                boolean success = false;
                String response = "";
                //проверка на наличие данных
                if(typePart == null || login == null || password == null){
                    throw new Exception("Не удалось найти typePart, login, password в сообщении");
                }
                switch (typePart) {
                    case "validation":
                        if(ClientSession.validateData(login, password)){
                        System.out.println("Успешный вход!");
                        activeSessions.put(clientIp, new ClientSession(this.key, this.iv));
                        response = "SUCCESS:Успешный вход!";
                        success = true;
                    } else {
                        response = "ERROR:Неверный логин или пароль";
                        success = false;
                    }
                    break;
            
                case "registration":
                    ClientSession.registerUser(login, password);
                    activeSessions.put(clientIp, new ClientSession(this.key, this.iv));
                    response = "SUCCESS:Регистрация успешна";
                    success = true;
                    break;
                default:
                    response = "ERROR:Неизвестный тип операции";
                    success = false;
                    break;
                }
                 SendMessage.sendMessage(dataOut, response, this.key, this.iv);
        
                // ЕСЛИ НЕ УСПЕШНО - ЗАКРЫВАЕМ СОЕДИНЕНИЕ
            if (!success) {
                System.out.println("Авторизация не пройдена, закрываем соединение для: " + clientIp);
                throw new Exception("Authentication failed");
            }
            } catch (Exception err){
                System.err.println("Ошибка при валидации данных входа: " + err.getMessage());
            }
        }
    }
}
