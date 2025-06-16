<?php
require __DIR__ . '/vendor/autoload.php';
require 'db.php';

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;

class Chat implements MessageComponentInterface {
    protected $clients;

    public function __construct() {
        $this->clients = new \SplObjectStorage;
    }

    public function onOpen(ConnectionInterface $conn) {
        $this->clients->attach($conn);
    }

    public function onMessage(ConnectionInterface $from, $msg) {
        global $conn_db;

        $data = explode(': ', $msg, 2);
        if (count($data) < 2) return;

        $username = $conn_db->real_escape_string($data[0]);
        $message = $conn_db->real_escape_string($data[1]);

        $stmt = $conn_db->prepare("SELECT user_id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->bind_result($sender_id);
        $stmt->fetch();
        $stmt->close();

        if ($sender_id) {
            $stmt = $conn_db->prepare("INSERT INTO messages (sender_id, message) VALUES (?, ?)");
            $stmt->bind_param("is", $sender_id, $message);
            $stmt->execute();
        }

        foreach ($this->clients as $client) {
            $client->send($msg);
        }
    }

    public function onClose(ConnectionInterface $conn) {
        $this->clients->detach($conn);
    }

    public function onError(ConnectionInterface $conn, \Exception $e) {
        $conn->close();
    }
}

use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;

$server = IoServer::factory(
    new HttpServer(new WsServer(new Chat())),
    8080
);

$server->run();
?>
