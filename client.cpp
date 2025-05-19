// Chat Client with AES Encryption
#include <iostream>
#include <thread>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <openssl/aes.h>

#define PORT 8080
const unsigned char aes_key[] = "1234567890123456"; // 16-byte key

void encrypt_decrypt(char* data, bool encrypt = true) {
    AES_KEY aes;
    if (encrypt)
        AES_set_encrypt_key(aes_key, 128, &aes);
    else
        AES_set_decrypt_key(aes_key, 128, &aes);

    unsigned char out[1024];
    AES_encrypt((unsigned char*)data, out, &aes);
    strcpy(data, (char*)out);
}

void receive_messages(int socket_fd) {
    char buffer[1024];
    while (true) {
        memset(buffer, 0, sizeof(buffer));
        int bytes = recv(socket_fd, buffer, sizeof(buffer), 0);
        if (bytes > 0) {
            encrypt_decrypt(buffer, false);  // Decrypt before display
            std::cout << "\nMessage: " << buffer << "\n> ";
            std::cout.flush();
        }
    }
}

int main() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr);

    connect(sock, (sockaddr*)&serv_addr, sizeof(serv_addr));
    std::cout << "Connected to server.\n";

    std::thread(receiver, receive_messages, sock).detach();

    char buffer[1024];
    while (true) {
        std::cout << "> ";
        std::cin.getline(buffer, sizeof(buffer));
        encrypt_decrypt(buffer);  // Encrypt before sending
        send(sock, buffer, strlen(buffer), 0);
    }
    close(sock);
    return 0;
}
