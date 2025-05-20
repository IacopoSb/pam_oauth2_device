#ifndef PAM_OAUTH2_DEVICE_CONFIG_HPP
#define PAM_OAUTH2_DEVICE_CONFIG_HPP

#include <map>
#include <set>
#include <string>
#include <vector>

class Config
{
public:
    void load(const char *path);    std::string client_id,
        client_secret,
        scope,
        device_endpoint,
        token_endpoint,
        userinfo_endpoint,
        username_attribute,
        default_user,
        smtp_server_url,
        smtp_username,
        smtp_password,
        smtp_ca_path,
        mail_from,
        mail_from_username,
        mail_cc;
    int qr_error_correction_level;
    bool enable_email,
         smtp_insecure,
         http_basic_auth,
         debug,
         use_default_user;
    std::vector<std::string> groups;
};

#endif // PAM_OAUTH2_DEVICE_CONFIG_HPP
