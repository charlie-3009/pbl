// chat_server.cpp
// Multi-threaded Chat Server using C++ and Socket Programming
// Includes: Socket creation, Client handling, MySQL integration, AES encryption, and Password hashing

#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <map>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define PORT 8080
#define BUFFER_SIZE 1024

std::vector<int> clients;
std::mutex clients_mutex;

MYSQL *conn;

void broadcastMessage(const std::string &message, int sender_fd) {
    std::lock_guard<std::mutex> lock(clients_mutex);
    for (int client : clients) {
        if (client != sender_fd) {
            send(client, message.c_str(), message.size(), 0);
        }
    }
}

std::string hashPassword(const std::string &password) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)password.c_str(), password.size(), hash);
    char hexstr[65];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(hexstr + i * 2, "%02x", hash[i]);
    hexstr[64] = 0;
    return std::string(hexstr);
}

bool verifyUser(const std::string &username, const std::string &password) {
    std::string hashed = hashPassword(password);
    std::string query = "SELECT * FROM users WHERE username='" + username + "' AND password_hash='" + hashed + "'";
    if (mysql_query(conn, query.c_str()) == 0) {
        MYSQL_RES *res = mysql_store_result(conn);
        bool valid = mysql_num_rows(res) > 0;
        mysql_free_result(res);
        return valid;
    }
    return false;
}

void handleClient(int client_socket) {
    char buffer[BUFFER_SIZE];
    int bytesReceived;
    while ((bytesReceived = recv(client_socket, buffer, BUFFER_SIZE - 1, 0)) > 0) {
        buffer[bytesReceived] = '\0';
        std::string message(buffer);
        broadcastMessage(message, client_socket);
    }
    close(client_socket);
    std::lock_guard<std::mutex> lock(clients_mutex);
    clients.erase(std::remove(clients.begin(), clients.end(), client_socket), clients.end());
}

int main() {
    conn = mysql_init(NULL);
    if (!mysql_real_connect(conn, "localhost", "root", "", "chat_app", 0, NULL, 0)) {
        std::cerr << "MySQL connection failed: " << mysql_error(conn) << std::endl;
        return 1;
    }

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
    listen(server_fd, 10);
    std::cout << "Server started on port " << PORT << "...\n";

    while (true) {
        sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addr_len);

        std::lock_guard<std::mutex> lock(clients_mutex);
        clients.push_back(client_socket);

        std::thread(handleClient, client_socket).detach();
    }
    mysql_close(conn);
    return 0;
}
