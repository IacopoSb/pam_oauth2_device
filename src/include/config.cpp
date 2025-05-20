#include <fstream>
#include <set>

#include "config.hpp"
#include "nlohmann/json.hpp"

using json = nlohmann::json;

void Config::load(const char *path)
{
    std::ifstream config_fstream(path);
    json j;
    config_fstream >> j;

    client_id = j.at("oauth").at("client").at("id").get<std::string>();
    client_secret = j.at("oauth").at("client").at("secret").get<std::string>();
    scope = j.at("oauth").at("scope").get<std::string>();
    device_endpoint = j.at("oauth").at("device_endpoint").get<std::string>();
    token_endpoint = j.at("oauth").at("token_endpoint").get<std::string>();
    userinfo_endpoint = j.at("oauth").at("userinfo_endpoint").get<std::string>();
    username_attribute = j.at("oauth").at("username_attribute").get<std::string>();
    groups = j.at("oauth").at("groups").get<std::vector<std::string>>();

    qr_error_correction_level = (j.find("qr") != j.end()) ?
        j.at("qr").at("error_correction_level").get<int>() : -1;

    enable_email =  (j.find("enable_email") != j.end()) ?
        j.at("enable_email").get<bool>() : false;   

    if (enable_email) {
        smtp_server_url = j.at("send_mail").at("smtp_server_url").get<std::string>();
        smtp_insecure = j.at("send_mail").at("smtp_insecure").get<bool>();
        smtp_ca_path = j.at("send_mail").at("smtp_ca_path").get<std::string>();
        smtp_username = j.at("send_mail").at("smtp_username").get<std::string>();
        smtp_password = j.at("send_mail").at("smtp_password").get<std::string>();
        mail_from = j.at("send_mail").at("from_address").get<std::string>();
        mail_cc = j.at("send_mail").at("cc_address").get<std::string>();
        mail_from_username = j.at("send_mail").at("from_username").get<std::string>();
    }        debug = (j.find("debug") != j.end()) ? j.at("debug").get<bool>() : false;

    http_basic_auth = (j.find("http_basic_auth") != j.end()) ?
        j.at("http_basic_auth").get<bool>() : true;

    use_default_user = (j.find("use_default_user") != j.end()) ?
        j.at("use_default_user").get<bool>() : false;

    default_user = (j.find("default_user") != j.end()) ?
        j.at("default_user").get<std::string>() : "";
}
