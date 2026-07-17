#include "Server/Service.h"
#include "Shared/ConfigManage.h"
#include "Shared/DnsCache.h"
// #include<string.h>
#include "Shared/Log.h"
#include "Shared/LogFile.h"
#include "Shared/Version.h"
#include <boost/program_options.hpp>
#include <exception>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
namespace po = boost::program_options;

static void SetupUTF8Console()
{
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}
int main(int argc, char* argv[])
{
    SetupUTF8Console();
    try {
        std::string config_file;
        po::options_description desc("Allowed options");
        desc.add_options()                        //
            ("version,v", "print version string") //
            ("help,h", "print help message")    //
            ("config,c", po::value<std::string>(&config_file)->default_value("server.json"), "config file path");
        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
        if (vm.count("help")) {
            std::cout << desc << std::endl;
            return 0;
        }
        if (vm.count("version")) {
            std::cout << OVERPLUS_VERSION_STR << std::endl;
            return 0;
        }
        auto& config = ConfigManage::instance();
        config.load_config(config_file, ConfigManage::Server);
        DnsCacheManager::instance().set_default_ttl(config.server_cfg.dns_cache_ttl);
        std::unique_ptr<LogFile> logfile_;

        logger::set_log_level(config.server_cfg.log_level);
        if (!config.server_cfg.log_dir.empty()) {
            logfile_.reset(new LogFile("server", 10 * 1024 * 1024, true, 3, 1024, 30));
            logger::set_log_destination(Destination::D_FILE);
            logger::setOutput([&](std::string&& buf) {
                logfile_->append(std::move(buf));
            });
            logger::setFlush([&]() {
                logfile_->flush();
            });
        }

        NOTICE_LOG << "overplus " << OVERPLUS_VERSION_STR << " will start..." << std::endl;
        Service server;
        server.run();
    } catch (const std::exception& e) {
        ERROR_LOG << "server exception, exiting: " << e.what();
    }
    NOTICE_LOG << "server stopped, exiting";

    return 0;
}
