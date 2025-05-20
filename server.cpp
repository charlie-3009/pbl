
// server.cpp

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <mysql/mysql.h>

#define PORT 8080
#define MAX_CLIENTS 10
#define AES_KEY "thisisasecretkey"  // 16-byte AES key

using namespace std;

int clients[MAX_CLIENTS];
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;

// AES encryption/decryption
void aes_encrypt(const char *input, unsigned char *output) {
    AES_KEY enc_key;
    AES_set_encrypt_key((const unsigned char *)AES_KEY, 128, &enc_key);
    AES_encrypt((const unsigned char *)input, output, &enc_key);
}

void aes_decrypt(const unsigned char *input, char *output) {
    AES_KEY dec_key;
    AES_set_decrypt_key((const unsigned char *)AES_KEY, 128, &dec_key);
    AES_decrypt(input, (unsigned char *)output, &dec_key);
}

// SHA-256 hash for password
string sha256(const string &str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)str.c_str(), str.size(), hash);
    char output[65];
    for (int i = 0; i < 32; i++) sprintf(output + (i * 2), "%02x", hash[i]);
    output[64] = 0;
    return string(output);
}

// MySQL login/register logic
bool handle_auth(MYSQL *conn, const string &username, const string &password, bool isRegister) {
    string hash = sha256(password);
    MYSQL_RES *res;
    MYSQL_ROW row;

    if (isRegister) {
        string checkQuery = "SELECT * FROM users WHERE username = '" + username + "'";
        mysql_query(conn, checkQuery.c_str());
        res = mysql_store_result(conn);
        if (mysql_num_rows(res) > 0) return false; // already exists

        string insertQuery = "INSERT INTO users(username, password) VALUES('" + username + "','" + hash + "')";
        return mysql_query(conn, insertQuery.c_str()) == 0;
    } else {
        string query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + hash + "'";
        mysql_query(conn, query.c_str());
        res = mysql_store_result(conn);
        return mysql_num_rows(res) > 0;
    }
}

void *handle_client(void *arg) {
    int sock = *(int *)arg;
    char buffer[1024];
    MYSQL *conn = mysql_init(NULL);
    mysql_real_connect(conn, "localhost", "root", "password", "chatdb", 0, NULL, 0);

    // Receive auth type
    read(sock, buffer, 1024);
    bool isRegister = strcmp(buffer, "register") == 0;

    // Receive username and password
    read(sock, buffer, 1024);
    string username(buffer);
    read(sock, buffer, 1024);
    string password(buffer);

    if (!handle_auth(conn, username, password, isRegister)) {
        write(sock, "fail", 4);
        close(sock);
        return NULL;
    }

    write(sock, "success", 7);

    // Now enter chat loop
    while (true) {
        unsigned char encrypted[128];
        int bytes = read(sock, encrypted, 128);
        if (bytes <= 0) break;

        char decrypted[128] = {0};
        aes_decrypt(encrypted, decrypted);
        printf("[%s]: %s\n", username.c_str(), decrypted);

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] != 0 && clients[i] != sock) {
                write(clients[i], encrypted, 128);
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    close(sock);
    mysql_close(conn);

    pthread_mutex_lock(&clients_mutex);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] == sock) {
            clients[i] = 0;
            break;
        }
    }
    pthread_mutex_unlock(&clients_mutex);

    return NULL;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    socklen_t addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 5);

    cout << "Server listening on port " << PORT << endl;

    while (true) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, &addrlen);

        pthread_mutex_lock(&clients_mutex);
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (clients[i] == 0) {
                clients[i] = new_socket;
                pthread_t tid;
                pthread_create(&tid, NULL, handle_client, &clients[i]);
                break;
            }
        }
        pthread_mutex_unlock(&clients_mutex);
    }

    return 0;
}
