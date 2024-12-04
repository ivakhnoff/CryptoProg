#include <cryptopp/files.h> // для работы с файлами крипто 
#include <cryptopp/hex.h> // для кодирование хэша
#include <cryptopp/sha.h> // для использования SHA224 
#include <fstream> 
#include <iostream>
#include <string>
using namespace std;
std::string sha224(string f) 
{
    using namespace CryptoPP; // использование именого простарнаспа крипто++
    SHA224 hash; // создается объект хэш класса SHA224 который будет вычислять хэш
    string new_hash; // сюда будет записан результат 
    FileSource file(f.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(new_hash)))); // читает данный из файла 
// HexFilter - вычисляет хэш sha224 из файла
// HexEncoder - преобразует хэш в 16-чный формат
// StringSink - записывает результат в строку
    return new_hash; // возвращает хешированный результат 
}
int main() {
    int z;
    cout << "Выберите режим для работы: \n";
    cout << "1. Начать работу \n";
    cout << "2. Завершить работу\n";
    cout << "Ввод: ";
    cin >> z;

    if (z == 2) {
        cout << "Работа завершена\n";
        return 0;
    } else if (z != 1) {
        cout << "Неверный ввод\n";
        return 0;
    }

    int q;
    cout << "Введите 1, чтобы зашифровать\n";
    cout << "Введите 2, чтобы завершить работу\n";
    cout << "Ввод: ";
    cin >> q;

    if (q == 2) {
        cout << "Работа завершена\n";
        return 0;
    } else if (q != 1) {
        cout << "Неверный ввод\n";
        return 0;
    } else { /
        string file;
        cout << "Введите имя файла:  ";
        cin >> file;
        string hash = sha224(file);
        cout << hash << endl;
    }

    return 0;
}
