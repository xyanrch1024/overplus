#include "Server.h"
#include "Shared/ConfigManage.h"
#include "Shared/LogFile.h"
#include "Shared/Log.h"
#include "Shared/Version.h"
#include <iostream>
#include <string>

int main()
{
    std::cout << "Overplus " << OVERPLUS_VERSION_STR << std::endl;
    ConfigManage::instance().load_config("client.json", ConfigManage::Client);
    auto& config = ConfigManage::instance().client_cfg;

    LogFile logfile_("overplus", 10 * 1024 * 1024, true, 3, 1024, 30);
    logger::set_log_level(L_NOTICE);
    logger::set_log_destination(Destination::D_STDOUT);
    logger::setOutput([&](std::string&& buf) {
        std::cout << buf << std::endl;
    });

    auto server = std::make_shared<Server>(config.local_addr, config.local_port);
    server->start_dtls();
    server->start_accept();
    server->run();

    return 0;
}