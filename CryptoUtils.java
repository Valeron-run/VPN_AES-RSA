import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest; //Библеотека для SHA-256
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class CryptoUtils {
    //Метод Хэширование строки (SHA-256)
    public static String hashString(String input){
        try{
            //Инициализируем параметр MessageDigest для алгоритма SHA-256
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            //Преобразуем строку в массив байтов и вычисляем хэш
            byte[] encodedhash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            //Возвращаем 16 ричное представление
            return bytesToHex(encodedhash);
        } catch(Exception err){
            System.err.println("Ошибка при хэшировании строки" + err.getMessage());
            return null;
        }
    }
    //Метод для сравнение хэш-сумм
    //input - строка для проверки
    //storedHash - cохраненный хэш для сравнения
    public static boolean verifyHash(String input, String storedHash){
        String inputHash = hashString(input);
        //Возращаем true или false - при сравнении строки
        return inputHash.equals(storedHash);
    }
        
    //Вспомогательный метод для преобразования байтов в шестнацетиричную строку
    private static String bytesToHex(byte[] bytes){
        StringBuilder sb = new StringBuilder();
        //Проходимся по каждому байту и преобразуем его в 16ричное представление
        for (byte b : bytes){
            sb.append(String.format("%02x", b)); //преобразуем байт как двухзначное 16 ричное число
        }
        return sb.toString();
    }

    //Метод шифрования строки в ширф AES
    //@param data - Входная трока
    //@param key - Секретный ключ
    //@param iv - Ветор инициализации (IV) для режима CBC.
    //throws - возращаем ошибку при шифровании
    public static String encrypString(String data, SecretKey key, IvParameterSpec iv) throws Exception { 
        // Инициализируем обьект Cipher для алгоритма AES в режиме CBC с заполнением PKCS5Padding
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Устанавливаем режим шифрования (ENCRYPT_MODE) и передаем ключ и IV
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        //Преобразуем входную стркоу в байты и шифруем ее
        byte[] encryptedBytes = cipher.doFinal(data.getBytes(StandardCharsets.UTF_8));

        //Клдируем зашифрованные байты в строку Base64 для удобства передачи
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    //Метод дешифрования строки (AES)
    //Тут все примерно тоже самое как и в функции выше, но в обратном порядке
    public static String decrypString(String encryptedData, SecretKey key, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        //Декодируем строку обратно в массив байтов
        byte[] decodeBytes = Base64.getDecoder().decode(encryptedData);

        //Дешифруем массив байтов и преобразуем обратно в строку
        byte[] decryptedBytes = cipher.doFinal(decodeBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    //Хэширование файла
    //Все тоже самое как и со строкой - отличие в том, что не нужно преобразовывать файл в массив байтов, так как он и так передается в ней
    public static String hashFile(byte[] fileContent){
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA256");
            byte[] encodedhash = digest.digest(fileContent);
            return bytesToHex(encodedhash);
        } catch(Exception err){
            System.err.println("Ошибка при хэшировании файла" + err.getMessage());
            return null;
        }
    }

    //Генерация ключа AES
    public static SecretKey generateAESKey(){
        try{

            //Инициализируем обьект KeyGenerator для алгоритма AES
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");

            //Устанавливаем размер ключа в 256 бит
            keyGen.init(256);

            //Генерируем и возращаем ключ
            return keyGen.generateKey();
        } catch (Exception err){
            System.err.println("Ошибка в генерации ключа AES " + err.getMessage());
            return null;
        }
    }

    //Генерация вектора инициализации (IV) для AES
    public static IvParameterSpec generateIV(){

        //Создаем массив байтов размеров в 16 
        byte[] iv = new byte[16];

        // Генерируем случайные байты для IV
        java.security.SecureRandom random = new java.security.SecureRandom();
        random.nextBytes(iv);

        //Возвращаем IV в виде обьекта IvParameterSpec
        return new IvParameterSpec(iv);
    }

    //Генерация пары ключей RSA
    public static KeyPair generateRSAKeyPair() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //Инициализируем саму систему шифрования
        keyPairGenerator.initialize(2048); // Размер ключа
        return keyPairGenerator.generateKeyPair(); //Возвращаем сам ключ
    }
    //Генрация публичного ключа RSA
    public static PublicKey getPublicKey(KeyPair keyPair){
        return keyPair.getPublic();
    }
    //Генерация приватного ключа RSA
    public static PrivateKey getPrivateKey(KeyPair keyPair){
        return keyPair.getPrivate();
    }


    //Шифрования Асинхронным публичным ключем(RSA) синхронного ключа(AES)
    public static byte[] encryptWithPublicKey(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data);
    }
    //Отправка Iv и Key(зашифрованных) одним сообщением (Метаданные)
    public static byte[] prepareEncryptData(PublicKey publicKey, SecretKey key, IvParameterSpec iv) throws Exception{
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        DataOutputStream dataOut = new DataOutputStream(out);

        //Зашифровка key и iv(и отправка)
        byte[] encryptedKey = encryptWithPublicKey(key.getEncoded(), publicKey);
        dataOut.writeInt(encryptedKey.length);
        dataOut.write(encryptedKey);
        byte[] encryptedIv = encryptWithPublicKey(iv.getIV(), publicKey);
        dataOut.writeInt(encryptedIv.length);
        dataOut.write(encryptedIv);

        dataOut.flush();
        return out.toByteArray();
    }

    //Расшифровка приватным ключем ключем(RSA) синхронного ключа(AES)
    public static byte[] decryptWithPrivateKey(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(encryptedData);
    }
    //Воссоздает секретный ключ из массива байтов
    public static SecretKey extractKey(byte[] descryptedKey){
        return new SecretKeySpec(descryptedKey, "AES");
    }
     //Воссоздает секретный ключ из массива байтов
    public static PublicKey extractKeyPub(byte[] publicKeyBytes) throws Exception {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
    return keyFactory.generatePublic(keySpec);
    }
    //Воссоздает iv из массива байтов
    public static IvParameterSpec extractIv(byte[] descryptedIv){
        return new IvParameterSpec(descryptedIv);
    }




    public static class DecryptedKeyIv{

        private final SecretKey key;
        private final IvParameterSpec iv;

        public DecryptedKeyIv(SecretKey key, IvParameterSpec iv){
            this.key = key;
            this.iv = iv;
        }
        //Возвращение результатов функции parseEncryptedData(key и iv)
        public SecretKey getKey(){
            return key;
        }
        public IvParameterSpec getIv(){
            return iv;
        }
    }
    //Прием метаданных, парсиг и расшифровка
    public static DecryptedKeyIv parseEncryptedData(PrivateKey privateKey, byte[] data) throws Exception{
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        DataInputStream dataIn = new DataInputStream(in);

        //Парс метаданных 
        int keyLength = dataIn.readInt();
        byte[] encryptedKey = new byte[keyLength];
        dataIn.readFully(encryptedKey);
        
        int ivLength = dataIn.readInt();
        byte[] encryptedIV = new byte[ivLength];
        dataIn.readFully(encryptedIV);

        SecretKey key = null;
        IvParameterSpec iv = null;
        if(encryptedKey != null && encryptedIV != null){
            //Расшифровка AES-ключа
            byte[] descryptedKey = decryptWithPrivateKey(encryptedKey, privateKey);
            byte[] descryptedIv = decryptWithPrivateKey(encryptedIV, privateKey);

            key = extractKey(descryptedKey);
            iv = extractIv(descryptedIv);

            System.out.println("AES-клюс и IV получены");
            
        } else {
            System.out.println("Неполные данные");
        }
        return new DecryptedKeyIv(key, iv);
    }
    

}

