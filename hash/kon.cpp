#include <cryptopp/files.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <fstream>
#include <iostream>
#include <string>
using namespace std;
std::string sha224(string f)
{
    using namespace CryptoPP;
    SHA224 hash;
    string new_hash;
    FileSource file(f.c_str(), true, new HashFilter(hash, new HexEncoder(new StringSink(new_hash))));
    return new_hash;
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
    } else { // q == 1
        string file;
        cout << "Введите имя файла:  ";
        cin >> file;
        string hash = sha224(file);
        cout << hash << endl;
    }

    return 0;
}
