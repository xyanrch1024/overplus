#pragma once
#include "Log.h"
#include <boost/property_tree/ptree.hpp>
#include <unordered_set>

struct ServerConfig {
    // json format
    /*
    {
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "allowed_password": [
        "password1",
        "password2"
    ],
    #NOTICE DEBUG ERROR
    "log_level": "NOTICE",
    "log_dir":"",
    "ssl": {
        "cert": "/path/to/certificate.crt",
        "key": "/path/to/private.key",
    }
    }
    */
    std::string local_addr;
    std::string local_port;
    std::unordered_set<std::string> allowed_passwords;
    //
    Loglevel log_level;
    std::string log_dir;
    std::string certificate_chain;
    std::string server_private_key;
    //
    //websocket
    bool websocketEnabled = false;
    bool websocketNoSSL = false;
    //
    // dtls
    bool dtls_enabled = false;
    std::string dtls_port;
    //
    time_t dns_cache_ttl = 600;
    time_t dns_cleanup_interval = 600;
    size_t thread_count = 0;
    void populate(boost::property_tree::ptree&);
};
struct ClientConfig {
    // json format
    /*
    {
    "run_type": "client",
    "local_addr": "0.0.0.0",
    "local_port": 1080,
     "remote_addr": "1.2.3.4",
     "remote_port": 443,
     "user_name":"user1",
     "password": "password1",
     "udp_enabled": true,
     "dtls_port": "8443"

    #NOTICE DEBUG ERROR
    "log_level": "NOTICE",
    }
    */
    std::string local_addr;
    std::string local_port;
    std::string remote_addr;
    std::string remote_port;
    std::string password;
    std::string user_name;
    std::string text_password;
    bool udp_enabled = false;
    std::string dtls_port;
    bool useWebSocket = false;

    void populate(boost::property_tree::ptree&);
    void setPassword(std::string&psswd);

};
class ConfigManage : private boost::noncopyable {

public:
    enum ConfigType {
        Server,
        Client

    };

    void load_config(const std::string&, ConfigType);
    static ConfigManage& instance();

public:
    ClientConfig client_cfg;
    ServerConfig server_cfg;
    bool loaded=false;

private:
    ConfigManage() = default;
};
