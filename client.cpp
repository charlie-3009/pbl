#include <iostream>
#include <thread>
#include <string>
#include <cstring>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 8080
#define MAX_LEN 1024
#define AES_KEY "1234567890123456"  // 16 bytes key

using namespace std;

AES_KEY enc_key, dec_key;

// --- SHA256 hashing ---
string sha256(const string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)str.c_str(), str.size(), hash);

    char outputBuffer[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    outputBuffer[64] = 0;
    return string(outputBuffer);
}

// --- AES Encrypt ---
string encryptAES(const string& plaintext) {
    unsigned char in[AES_BLOCK_SIZE];
    unsigned char out[AES_BLOCK_SIZE];
    string ciphertext;

    for (size_t i = 0; i < plaintext.size(); i += AES_BLOCK_SIZE) {
        memset(in, 0, AES_BLOCK_SIZE);
        memcpy(in, plaintext.c_str() + i, min(AES_BLOCK_SIZE, plaintext.size() - i));
        AES_encrypt(in, out, &enc_key);
        ciphertext.append((char*)out, AES_BLOCK_SIZE);
    }
    return ciphertext;
}

// --- AES Decrypt ---
string decryptAES(const string& ciphertext) {
    unsigned char in[AES_BLOCK_SIZE];
    unsigned char out[AES_BLOCK_SIZE];
    string plaintext;

    for (size_t i = 0; i < ciphertext.size(); i += AES_BLOCK_SIZE) {
        memcpy(in, ciphertext.c_str() + i, AES_BLOCK_SIZE);
        AES_decrypt(in, out, &dec_key);
        plaintext.append((char*)out, AES_BLOCK_SIZE);
    }
    return plaintext;
}

// --- Receive thread ---
void receiveMessages(int clientSocket) {
    char buffer[MAX_LEN];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int valread = recv(clientSocket, buffer, MAX_LEN, 0);
        if (valread <= 0) break;

        string decrypted = decryptAES(string(buffer, valread));
        cout << "\n[Server]: " << decrypted << endl;
        cout << "You: ";
        cout.flush();
    }
}

int main() {
    struct sockaddr_in serv_addr;
    int clientSocket;
    string server_ip = "127.0.0.1";

    AES_set_encrypt_key((const unsigned char*)AES_KEY, 128, &enc_key);
    AES_set_decrypt_key((const unsigned char*)AES_KEY, 128, &dec_key);

    if ((clientSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "Socket creation error" << endl;
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, server_ip.c_str(), &serv_addr.sin_addr) <= 0) {
        cerr << "Invalid address/ Address not supported" << endl;
        return -1;
    }

    if (connect(clientSocket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "Connection Failed" << endl;
        return -1;
    }

    // --- Login/Register Prompt ---
    int choice;
    cout << "1. Register\n2. Login\nEnter choice: ";
    cin >> choice;
    cin.ignore();

    string username, password, hashedPassword;
    cout << "Username: ";
    getline(cin, username);
    cout << "Password: ";
    getline(cin, password);
    hashedPassword = sha256(password);

    string auth_data = (choice == 1 ? "REGISTER" : "LOGIN") + string(":") + username + ":" + hashedPassword;
    string encrypted_auth = encryptAES(auth_data);
    send(clientSocket, encrypted_auth.c_str(), encrypted_auth.size(), 0);

    // --- Start receiving thread ---
    thread receiver(receiveMessages, clientSocket);

    // --- Sending loop ---
    string msg;
    while (true) {
        cout << "You: ";
        getline(cin, msg);
        if (msg == "exit") break;

        string encrypted = encryptAES(msg);
        send(clientSocket, encrypted.c_str(), encrypted.size(), 0);
    }

    close(clientSocket);
    receiver.join();
    return 0;
}
