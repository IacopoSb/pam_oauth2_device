#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include <chrono>
#include <sstream>
#include <thread>
#include <vector>
#include <iterator>
#include <iostream>
#include <iomanip>
#include <string>
#include <regex>

#include "include/config.hpp"
#include "include/send_mail.hpp"
#include "include/nayuki/QrCode.hpp"
#include "include/nlohmann/json.hpp"
#include "pam_oauth2_device.hpp"


using json = nlohmann::json;

std::string url_encode(const std::string &value) {
    std::ostringstream escaped;
    escaped.fill('0');
    escaped << std::hex;

    for (const auto c : value) {

        // Keep alphanumeric and other accepted characters intact
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << std::uppercase;
        escaped << '%' << std::setw(2) << int((unsigned char) c);
        escaped << std::nouppercase;
    }

    return escaped.str();
}

class BaseError : public std::exception
{
public:
    const char *what() const throw()
    {
        printf("Base error\n");
        return "Base Error";
    }
};

class PamError : public BaseError
{
public:
    const char *what() const throw()
    {
        printf("PAM error\n");
        return "PAM Error";
    }
};

class NetworkError : public BaseError
{
public:
    const char *what() const throw()
    {
        printf("Network error\n");
        return "Network Error";
    }
};

class TimeoutError : public NetworkError
{
public:
    const char *what() const throw()
    {
        printf("Timeout error\n");
        return "Timeout Error";
    }
};

class ResponseError : public NetworkError
{
public:
    const char *what() const throw()
    {
        printf("Response error\n");
        return "Response Error";
    }
};

std::string getQr(const char *text, const int ecc = 0, const int border = 1)
{
    qrcodegen::QrCode::Ecc error_correction_level;
    switch (ecc)
    {
    case 1:
        error_correction_level = qrcodegen::QrCode::Ecc::MEDIUM;
        break;
    case 2:
        error_correction_level = qrcodegen::QrCode::Ecc::HIGH;
        break;
    default:
        error_correction_level = qrcodegen::QrCode::Ecc::LOW;
        break;
    }
    qrcodegen::QrCode qr = qrcodegen::QrCode::encodeText(
        text, error_correction_level);

    std::ostringstream oss;
    int i, j, size, top, bottom;
    size = qr.getSize();
    for (j = -border; j < size + border; j += 2)
    {
        for (i = -border; i < size + border; ++i)
        {
            top = qr.getModule(i, j);
            bottom = qr.getModule(i, j + 1);
            if (top && bottom)
            {
                oss << "\033[40;97m \033[0m";
            }
            else if (top && !bottom)
            {
                oss << "\033[40;97m\u2584\033[0m";
            }
            else if (!top && bottom)
            {
                oss << "\033[40;97m\u2580\033[0m";
            }
            else
            {
                oss << "\033[40;97m\u2588\033[0m";
            }
        }

        oss << std::endl;
    }
    return oss.str();
}

std::string DeviceAuthResponse::get_prompt(const bool print_hit_enter = false, const int qr_ecc = 0)
{
    bool complete_url = !verification_uri_complete.empty();
    std::ostringstream prompt;
    prompt << "Please authenticate at\n-----------------\n"
           << (complete_url ? verification_uri_complete : verification_uri)
           << "\n-----------------\n";
    if (!complete_url)
    {
        prompt << "With code " << user_code
               << "\n-----------------\n";
    }

    if (qr_ecc >= 0) {
        prompt << "Or scan the QR code to authenticate with a mobile device"
               << std::endl
               << std::endl
               << getQr((complete_url ? verification_uri_complete : verification_uri).c_str(), qr_ecc)
               << std::endl;
    } 
    
    if (print_hit_enter)
    {
        prompt << "Hit enter when you authenticate\n";
    }
    return prompt.str();
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

void make_authorization_request(const Config config,
                                const char *client_id,
                                const char *client_secret,
                                const char *scope,
                                const char *device_endpoint,
                                DeviceAuthResponse *response)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl)
        throw NetworkError();
    std::string params = std::string("client_id=") + client_id + "&scope=" + scope;
    if (config.http_basic_auth) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, client_id);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret);
    } else {
        params += std::string("&client_secret=") + client_secret;
    }
    curl_easy_setopt(curl, CURLOPT_URL, device_endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
        throw NetworkError();
    try
    {
        if (config.debug) printf("Response to authorizaation request: %s\n", readBuffer.c_str());
        auto data = json::parse(readBuffer);
        response->user_code = data.at("user_code");
        response->device_code = data.at("device_code");
        response->verification_uri = data.at("verification_uri");
        if (data.find("verification_uri_complete") != data.end())
        {
            response->verification_uri_complete = data.at("verification_uri_complete");
        }
    }
    catch (json::exception &e)
    {
        throw ResponseError();
    }
}

void poll_for_token(const Config config,
                    const char *client_id,
                    const char *client_secret,
                    const char *token_endpoint,
                    const char *device_code,
                    std::string &access_token,
                    std::string &id_token)
{
    int timeout = 300,
        interval = 3;
    CURL *curl;
    CURLcode res;
    json data;
    std::ostringstream oss;
    std::string params;

    oss << "grant_type=urn:ietf:params:oauth:grant-type:device_code"
        << "&device_code=" << url_encode(device_code)
        << "&client_id=" << url_encode(client_id);
    if (config.http_basic_auth)
        oss << "&client_secret=" << client_secret;
        //
    params = oss.str();

    while (true)
    {
        timeout -= interval;
        if (timeout < 0)
        {
            throw TimeoutError();
        }
        std::string readBuffer;
        std::this_thread::sleep_for(std::chrono::seconds(interval));
        curl = curl_easy_init();
        if (!curl)
            throw NetworkError();
        curl_easy_setopt(curl, CURLOPT_URL, token_endpoint);
        if (config.http_basic_auth) {
            curl_easy_setopt(curl, CURLOPT_USERNAME, client_id);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, client_secret);
        }
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        if (res != CURLE_OK)
            throw NetworkError();
        try
        {
            if (config.debug) printf("Response from token poll: %s\n", readBuffer.c_str());
            data = json::parse(readBuffer);
            if (data["error"].empty())
            {
                access_token = data.at("access_token");
                // Also retrieve the ID token if available
                if (data.find("id_token") != data.end()) {
                    id_token = data.at("id_token");
                    if (config.debug) printf("ID token received\n");
                } else {
                    if (config.debug) printf("No ID token in response\n");
                }
                break;
            }
            else if (data["error"] == "authorization_pending")
            {
                // Do nothing
            }
            else if (data["error"] == "slow_down")
            {
                ++interval;
            }
            else
            {
                throw ResponseError();
            }
        }
        catch (json::exception &e)
        {
            throw ResponseError();
        }
    }
}

void get_userinfo(const Config &config,
                  const char *userinfo_endpoint,
                  const char *access_token,
                  const std::string &id_token,
                  const char *username_attribute,
                  Userinfo *userinfo)
{
    CURL *curl;
    CURLcode res;
    std::string readBuffer;

    curl = curl_easy_init();
    if (!curl)
        throw NetworkError();
    curl_easy_setopt(curl, CURLOPT_URL, userinfo_endpoint);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

    std::string auth_header = "Authorization: Bearer ";
    auth_header += access_token;
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, auth_header.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    if (res != CURLE_OK)
        throw NetworkError();
    try
    {
        if (config.debug) printf("Userinfo response: %s\n", readBuffer.c_str());
        auto data = json::parse(readBuffer);
        userinfo->sub = data.at("sub");
        userinfo->username = data.at(username_attribute);
        userinfo->name = data.at("name");
        
        // Try to get groups from userinfo endpoint first
        bool groups_from_userinfo = false;
        try {
            if (data.find("groups") != data.end()) {
                userinfo->groups = data.at("groups").get<std::vector<std::string>>();
                groups_from_userinfo = true;
                if (config.debug) printf("Groups successfully retrieved from userinfo endpoint\n");
            }
        } catch (json::exception &e) {
            if (config.debug) printf("No groups in userinfo response, will try ID token\n");
        }
        
        // If we couldn't get groups from userinfo, try the ID token
        if (!groups_from_userinfo && !id_token.empty()) {
            parse_id_token(config, id_token, userinfo);
        }
        
        if (userinfo->groups.empty() && config.debug) {
            printf("Warning: No groups found in either userinfo or ID token\n");
        }
    }
    catch (json::exception &e)
    {
        throw ResponseError();
    }
}

void show_prompt(pam_handle_t *pamh,
                 int qr_error_correction_level,
                 DeviceAuthResponse *device_auth_response)
{
    int pam_err;
    char *response;
    struct pam_conv *conv;
    struct pam_message msg;
    const struct pam_message *msgp;
    struct pam_response *resp;
    std::string prompt;

    pam_err = pam_get_item(pamh, PAM_CONV, (const void **)&conv);
    if (pam_err != PAM_SUCCESS)
        throw PamError();
    prompt = device_auth_response->get_prompt(true, qr_error_correction_level);
    msg.msg_style = PAM_PROMPT_ECHO_OFF;
    msg.msg = (char *)prompt.c_str();
    msgp = &msg;
    response = NULL;
    pam_err = (*conv->conv)(1, &msgp, &resp, conv->appdata_ptr);
    if (resp != NULL)
    {
        if (pam_err == PAM_SUCCESS)
        {
            response = resp->resp;
        }
        else
        {
            free(resp->resp);
        }
        free(resp);
    }
    if (response)
        free(response);
}

void notify_user( const char *user,
                  const Config &config,
                  DeviceAuthResponse *device_auth_response,
                  int qr_error_correction_level = -1)
{
    Email mail = Email(user, config.mail_from, config.mail_from_username, "VPN Authentication Request", device_auth_response->get_prompt(false, qr_error_correction_level), config.mail_cc);
    CURLcode ret = mail.send(config.smtp_server_url, config.smtp_insecure, config.smtp_ca_path, config.smtp_username, config.smtp_password);
    
    if (ret != CURLE_OK) {
        printf("notify_user() failed: %s\n", curl_easy_strerror(ret));
        throw NetworkError();    
    }   
}                  

bool is_authorized(Config *config,
                   Userinfo *userinfo)
{
    if (config->groups.size() == 0) {
        return true;
    }
    std::vector<std::string> groups_intsec;
    std::sort(userinfo->groups.begin(), userinfo->groups.end());
    std::sort(config->groups.begin(), config->groups.end());

    std::set_intersection(userinfo->groups.begin(), userinfo->groups.end(),
                          config->groups.begin(), config->groups.end(),
                          std::back_inserter(groups_intsec));

    bool ret = groups_intsec.size() != 0; 
    if (config->debug) {
        if (ret){
            std::ostringstream oss;
            for (auto &group: groups_intsec)
                oss << group << ", "; 
            printf("User authorized due to group(s) membership: %s\n", oss.str().c_str());            
        }
        else printf("User unauthorized.\n");                   
    }              

    return ret;   
}

static bool isEmailAddress(const std::string& str)
{
    // Locate '@'
    auto at = std::find(str.begin(), str.end(), '@');
    // Locate '.' after '@'
    auto dot = std::find(at, str.end(), '.');
    // make sure both characters are present
    return (at != str.end()) && (dot != str.end());
}

/* expected hook */
PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    return PAM_SUCCESS;
}

/* expected hook, custom logic */
PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    const char *username_local;
    std::string access_token;
    std::string id_token;
    Config config;
    DeviceAuthResponse device_auth_response;
    Userinfo userinfo;

    try
    {
        (argc > 0) ? config.load(argv[0]) : config.load("/etc/pam_oauth2_device/config.json");
    }
    catch (json::exception &e)
    {
        printf("Failed to load config: %s.\n", e.what());
        return PAM_AUTH_ERR;
    }

    try
    {
	    if (pam_get_user(pamh, &username_local, "Username: ") != PAM_SUCCESS)
            throw PamError();

        printf("pam_sm_authenticate() called. Username: %s\n", username_local);   

        if (config.enable_email && ! isEmailAddress(username_local)){
            printf("pam_sm_authenticate(): Invalid email\n");	
            throw PamError();
        }    
        
        make_authorization_request(
            config,
            config.client_id.c_str(), config.client_secret.c_str(),
            config.scope.c_str(), config.device_endpoint.c_str(),
            &device_auth_response);
        if (config.enable_email){
            notify_user(username_local, config, &device_auth_response);    
        }
        else {
            show_prompt(pamh, config.qr_error_correction_level, &device_auth_response);
        }    
        poll_for_token(config, config.client_id.c_str(), config.client_secret.c_str(),
                       config.token_endpoint.c_str(),
                       device_auth_response.device_code.c_str(), access_token, id_token);        get_userinfo(config, config.userinfo_endpoint.c_str(), access_token.c_str(), 
                     id_token, config.username_attribute.c_str(), &userinfo);
        // Set PAM_USER to configured default_user or to username from userinfo depending on configuration
        const char* user_to_set = (config.use_default_user && !config.default_user.empty()) ? 
                                  config.default_user.c_str() : userinfo.username.c_str();
        if (config.debug) {
            printf("Setting PAM_USER to %s%s\n", user_to_set, 
                  (config.use_default_user && !config.default_user.empty()) ? " (default user from config)" : "");
        }
        if (pam_set_item(pamh, PAM_USER, user_to_set) != PAM_SUCCESS)
            throw PamError();
    }
    catch (PamError &e)
    {
        return PAM_SYSTEM_ERR;
    }
    catch (TimeoutError &e)
    {
        return PAM_AUTH_ERR;
    }
    catch (NetworkError &e)
    {
        return PAM_AUTH_ERR;
    }

    
    if (is_authorized(&config, &userinfo))
        return PAM_SUCCESS;	
    return PAM_AUTH_ERR;
}

/* Decode base64url encoded string */
std::string base64url_decode(const std::string &input) {
    std::string base64 = input;

        printf("Base64URL input: %s\n", input.c_str());
    

    // Convert from Base64URL to Base64
    std::replace(base64.begin(), base64.end(), '-', '+');
    std::replace(base64.begin(), base64.end(), '_', '/');    

    // Add padding if necessary
    while (base64.size() % 4 != 0) {
        base64 += '=';
    }    

    // Decode Base64
    std::string decoded;
    static const std::string base64_chars = 
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    for (size_t i = 0; i < base64.size(); i += 4) {
        char a = base64_chars.find(base64[i]);
        char b = base64_chars.find(base64[i + 1]);
        char c = base64[i + 2] == '=' ? 0 : base64_chars.find(base64[i + 2]);
        char d = base64[i + 3] == '=' ? 0 : base64_chars.find(base64[i + 3]);

        decoded.push_back((a << 2) | (b >> 4));
        if (base64[i + 2] != '=') {
            decoded.push_back((b << 4) | (c >> 2));
        }
        if (base64[i + 3] != '=') {
            decoded.push_back((c << 6) | d);
        }
    }

    return decoded;
}

void parse_id_token(const Config &config, const std::string &id_token, Userinfo *userinfo) {
    if (id_token.empty()) {
        if (config.debug) printf("ID token is empty, can't extract groups\n");
        return;
    }

    try {
        if (config.debug) printf("Parsing ID token to extract groups\n");

        // Split token by dots
        std::string::size_type first_dot = id_token.find('.');
        std::string::size_type second_dot = id_token.find('.', first_dot + 1);

        if (first_dot != std::string::npos && second_dot != std::string::npos) {
            // Extract payload (second part)
            std::string payload = id_token.substr(first_dot + 1, second_dot - first_dot - 1);

            // Debug log for raw payload before decoding
            if (config.debug) {
                printf("Raw payload before Base64URL decoding: %s\n", payload.c_str());
            }

            // Base64url decode
            std::string decoded_payload = base64url_decode(payload);

            // Check if decoded payload is empty
            if (decoded_payload.empty()) {
                if (config.debug) {
                    printf("Decoded payload is empty, skipping JSON parsing.\n");
                }
                return;
            }

            // Parse JSON
            try {
                auto data = json::parse(decoded_payload);

                // Extract groups if available
                if (data.contains("groups")) {
                    userinfo->groups = data["groups"].get<std::vector<std::string>>();
                    if (config.debug) {
                        printf("Groups extracted from ID token: ");
                        for (const auto &group : userinfo->groups) {
                            printf("%s ", group.c_str());
                        }
                        printf("\n");
                    }
                } else if (config.debug) {
                    printf("No groups found in the ID token payload.\n");
                }
            } catch (const json::exception &e) {
                if (config.debug) {
                    printf("Error parsing decoded payload as JSON: %s\n", e.what());
                }
            }
        } else {
            if (config.debug) printf("ID token does not have the expected format (missing dots)\n");
        }
    } catch (std::exception &e) {
        if (config.debug) printf("Unexpected error while parsing ID token: %s\n", e.what());
    }
}
