import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.SecretKey;

public class SendAccFile {
    private OutputStream outFile; // Поток для отправки файла
    //Конструктор класса для инициализации OutputStream
    public void SendFile(OutputStream outFile){
        this.outFile = outFile;
        //this.out = out;
    }
    //Метод отправки файла
    public static void sendFile(String inputPath, DataOutputStream dataOut, SecretKey key, IvParameterSpec iv){
        File file = new File(inputPath);
            if (!file.exists()) {
                //throw - выбрасывает исключение внутри метода (Исключения бывают Проверяймые и непроверяймые)
                throw new IllegalArgumentException("Файл не существует: " + inputPath);
            }
        try{
            //Полное чтение файла в байтовом виде
            byte[] fileContent = Files.readAllBytes(file.toPath());
            //Чтение файла в строчном виде(для удобности формирования метаданных)
            String fileBase64 = Base64.getEncoder().encodeToString(fileContent);
           //Вычисление хэш-суммы
            String hashStr = CryptoUtils.hashFile(fileContent);

            /// Формирование сообщения с метаданными
            String metaData = "[TYPE:file][DATA:" + fileBase64 + "][SIZE:" + fileContent.length + "][HASH:" + hashStr + "]";
            
            // Шифрование сообщения
            String encryptedMessage = CryptoUtils.encrypString(metaData, key, iv);
            //Отправка хэш суммы
            dataOut.writeInt(encryptedMessage.getBytes(StandardCharsets.UTF_8).length);
            dataOut.write(encryptedMessage.getBytes(StandardCharsets.UTF_8));
            dataOut.flush();
        } catch (Exception err){
            System.out.println("Ошибка при отправке файла" + err.getMessage());
        }
        
    }

    //Метод для принятия файла и проверки его хэш-суммы. 
    public static void acceptFile(String outputPath, String input){
        try{
            //Сотавили паттерн(рег.выражения) для поиска мета данных
            java.util.regex.Pattern pattern = java.util.regex.Pattern.compile("TYPE:(.*?)\\]\\s*\\[DATA:(.*?)\\]\\s*\\[SIZE:(.*?)\\]\\s*\\[HASH:(.*?)\\]");
            //Применяем шаблон к сообщению
            java.util.regex.Matcher matcher = pattern.matcher(input);

            String typePart = null;
            String typeData = null;
            String typeSize = null;
            String typeHash = null;
            if(matcher.find()){
                typePart = matcher.group(1).trim();
                typeData = matcher.group(2).trim();
                typeSize = matcher.group(3).trim();
                typeHash = matcher.group(4).trim();
            } else {
                throw new IllegalArgumentException("Не удалось найти TYPE или DATA или SIZE или HASH");
            }
            //Декодируем файл из Base64
            byte[] fileBytes = Base64.getDecoder().decode(typeData);

            String computedHash = CryptoUtils.hashFile(fileBytes);
            if (!typeHash.equals(computedHash)) {
                System.err.println("Ошибка: Хэш-суммы не совпадают.");
                return;
            }
            //Проверка целостности веса файла
            long fileSize = Long.parseLong(typeSize);
            if (fileBytes.length != fileSize) {
                System.err.println("Ошибка: Размер файла не совпадает.");
                return;
            }

            // Сохранение файла
            Files.write(Paths.get(outputPath), fileBytes);
            System.out.println("Документ успешно принят и сохранен.");

        } catch(Exception err){
            System.err.println("Ошибка при принятии файла: " + err.getMessage());
        }
            
    }

    //Метод закрытия OutputStream
    public void close() {
        try {
            if (outFile != null) {
                outFile.close();
            }
        } catch (Exception err) {
            System.err.println("Ошибка при закрытии потока: " + err.getMessage());
        }
    }
}
