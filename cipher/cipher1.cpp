#include <cryptopp/aes.h> // шифрования аес, в сочетании с CBC_mode
#include <cryptopp/filters.h> // фильтры Crypto++
#include <cryptopp/modes.h> // режим работы cbc_mode
#include <cryptopp/osrng.h> // генератор случайных чисел
#include <cryptopp/pwdbased.h> // функции для получения ключа из пароля
#include <fstream> // c файлами 
#include <iostream> 
#include <string>
#include <vector>

using namespace CryptoPP;

void encrypt(const std::string& inputFile, const std::string& outputFile, const std::string& psw)
{ // принимает стринг, затем получает путь от входного файла в выходному, и затем пароль для шифра, все этот под константой
    // чтение данных из входного файла
    std::ifstream inFile(inputFile);
    if(!inFile) {
        std::cerr << "Не удалось открыть файл для чтения" << inputFile << std::endl; // если файл не открылся
        return; 
    }
    std::string data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>()); //читает весь файл и записывает в стркоу дата
    inFile.close();

    // шифрование данных
    const int keyLength = AES::DEFAULT_KEYLENGTH; // создается ключ по умолчанию в 256 бит
    const int blockSize = AES::BLOCKSIZE; // создается блок блиной 128 бит
 
    AutoSeededRandomPool prng; // генератор случайных чисел 
    SecByteBlock key(keyLength); // блок для хранения ключа
    PKCS5_PBKDF2_HMAC<SHA224> pbkdf; // объект для генирации ключа из пароля, pbkdf2 - алгоритм шифрования

    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000); // Генерирует ключ key из паполя psw с использованием 1000 итераций(скок раз выполняется операция)

    byte iv[blockSize]; // создается массив для вектора инициализации
    prng.GenerateBlock(iv, sizeof(iv)); //массив случайно заполняется

    CBC_Mode<AES>::Encryption encryptor; // создается объект для шифрование аес в редиме сбс
    encryptor.SetKeyWithIV(key, key.size(), iv); // Генерация случайного iv для уникальности кажого шифрования

    std::vector<byte> cipherText; // вектор для хранения шифрованного текста
    cipherText.resize(blockSize); // выделяется место для iv в начале
    std::copy(iv, iv + blockSize, cipherText.begin()); // кидает iv рядом с зашифрованным текстом для последущего расшифрования

    StringSource ss(data, true, new StreamTransformationFilter(encryptor, new VectorSink(cipherText))); // шифррует данные из дата с помощью енкриптора и сохраняет результат в кипхертекст, true = удаление прикрепленных филтров после работы. 

    std::ofstream outFile(outputFile, std::ios::binary); // открывает файл для записи в бинарном режиме
    if(!outFile) { //  проверка на ошибку открытия файла
        std::cerr << "Не удалось открыть файл для записи" << outputFile << std::endl;
        return;
    }
    outFile.write(reinterpret_cast<const char*>(cipherText.data()), cipherText.size()); // запись данных в зашифрованный файл rein... - преобразует биты в чар данные 
    outFile.close(); // закрывает файл
    std::cout << "Зашифрование завершено " << std::endl;
}

void decrypt(const std::string& inputFile, const std::string& outputFile, const std::string& psw) // дешифрование, открывает указанный файл, и кидает данные в выходной файл
{
    std::ifstream inFile(inputFile, std::ios::binary); // открывает файл в бинарном режиме
    if(!inFile) { // если не открылся 
        std::cerr << "Не удалось открыть файл для чтения" << std::endl;
        return; 
    }
    std::vector<byte> cipherText((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    // читает данные из файла
    inFile.close();

    const int keyLength = AES::DEFAULT_KEYLENGTH; // создает ключ на 256 битов 
    const int blockSize = AES::BLOCKSIZE; // создает размер блока на 128 бит

    SecByteBlock key(keyLength); // блок для хранения ключа
    PKCS5_PBKDF2_HMAC<SHA224> pbkdf; // метод шифровки

    pbkdf.DeriveKey(key, key.size(), 0, reinterpret_cast<const byte*>(psw.data()), psw.size(), nullptr, 0, 1000); // объект для генерации ключа из пароля на 1000 повторений

    byte iv[blockSize]; // Массив iv
    memcpy(iv, cipherText.data(), blockSize); // копируте iv в из начала ciphertxt

    CBC_Mode<AES>::Decryption decryptor; // создает объект для расширофвания
    decryptor.SetKeyWithIV(key, key.size(), iv); // устанавливает iv и ключ для расшифрования

    std::string decryptedText; // хранит расшифрованный текст

    StringSource ss(cipherText.data() + blockSize, cipherText.size() - blockSize, true,
                    new StreamTransformationFilter(decryptor, new StringSink(decryptedText)));
                    // тоже самое что шифрование, шифрует, записывает, удаляет фильтр.

    std::ofstream outFile(outputFile);
    if(!outFile) { // проверка на ошибку открытия файла
        std::cerr << "Не удалось открыть файл для записи" << outputFile << std::endl;
        return;
    }
    outFile << decryptedText; // записывает расшифрованные данные в выходной файл
    outFile.close();
    std::cout << "Расшифрование завершено" << std::endl;
}

int main()
{
    std::string file1, file2, psw;
    int q; 

    std::cout << "Выберите режим для работы: \n";
    std::cout << "Введите один, чтобы зашифровать\n";
    std::cout << "Введите два, чтобы расшифровать\n";
    std::cout << "Ввод: ";
    std::cin >> q;
    

    std::cout << "Введите путь к файлу с исходными данными: ";
    std::cin >> file1;

    std::cout << "Введите путь к файлу для записи: ";
    std::cin >> file2;

    std::cout << "Введите пароль: ";
    std::cin >> psw;

    if(q == 1) {
        encrypt(file1, file2, psw);
    } else if(q == 2){
        decrypt(file1, file2, psw);
     } else {
        std::cout << "Неверный режим.";
    }

    return 0;
}


