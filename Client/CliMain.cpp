#include "Server.h"
#include "Shared/ConfigManage.h"
#include "Shared/Version.h"
#include <iostream>
#include <string>

int main()
{
    std::cout << "Overplus " << OVERPLUS_VERSION_STR << std::endl;
    ConfigManage::instance().load_config("client.json", ConfigManage::Client);
    auto& config = ConfigManage::instance().client_cfg;
    Server server(config.local_addr, config.local_port);
    server.run();

    return 0;
}