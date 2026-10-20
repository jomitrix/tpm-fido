#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <security/pam_appl.h>

#define MAX_PASS_LEN 512

struct pam_conv_data {
    char password[MAX_PASS_LEN];
};

static int pam_conversation(int num_msg, const struct pam_message **msg,
                            struct pam_response **resp, void *appdata_ptr) {
    if (num_msg <= 0 || num_msg > PAM_MAX_NUM_MSG) {
        return PAM_CONV_ERR;
    }

    struct pam_response *reply = calloc(num_msg, sizeof(struct pam_response));
    if (!reply) {
        return PAM_BUF_ERR;
    }

    struct pam_conv_data *data = (struct pam_conv_data *)appdata_ptr;

    for (int i = 0; i < num_msg; i++) {
        switch (msg[i]->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
            case PAM_PROMPT_ECHO_ON:
                reply[i].resp = strdup(data->password);
                reply[i].resp_retcode = 0;
                break;
            case PAM_ERROR_MSG:
            case PAM_TEXT_INFO:
                reply[i].resp = NULL;
                reply[i].resp_retcode = 0;
                break;
            default:
                for (int j = 0; j < num_msg; j++) {
                    if (reply[j].resp) {
                        explicit_bzero(reply[j].resp, strlen(reply[j].resp));
                        free(reply[j].resp);
                    }
                }
                free(reply);
                return PAM_CONV_ERR;
        }
    }

    *resp = reply;
    return PAM_SUCCESS;
}

static int pam_service_exists(const char *service) {
    char path[256];
    int n = snprintf(path, sizeof(path), "/etc/pam.d/%s", service);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return 0;
    }
    return (access(path, R_OK) == 0);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <username> [service]\n", argv[0]);
        return 2;
    }

    const char *username = argv[1];

    // Security check: only allow verifying current user account unless caller is root
    uid_t uid = getuid();
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        return 1; // User does not exist
    }
    if (uid != 0 && pw->pw_uid != uid) {
        fprintf(stderr, "Security violation: cannot verify authentication of another user\n");
        return 2;
    }

    // Read password from stdin until newline or EOF
    char buf[MAX_PASS_LEN];
    explicit_bzero(buf, sizeof(buf));
    size_t total = 0;
    while (total < sizeof(buf) - 1) {
        ssize_t n = read(STDIN_FILENO, buf + total, sizeof(buf) - 1 - total);
        if (n <= 0) {
            break;
        }
        total += n;
        if (buf[total - 1] == '\n' || buf[total - 1] == '\r') {
            break;
        }
    }

    // Strip trailing newlines/carriage returns
    while (total > 0 && (buf[total - 1] == '\n' || buf[total - 1] == '\r')) {
        buf[--total] = '\0';
    }
    buf[total] = '\0';

    struct pam_conv_data conv_data;
    explicit_bzero(&conv_data, sizeof(conv_data));
    memcpy(conv_data.password, buf, total);
    conv_data.password[total] = '\0';
    // Erase initial buffer immediately
    explicit_bzero(buf, sizeof(buf));

    struct pam_conv conv = {
        .conv = pam_conversation,
        .appdata_ptr = &conv_data,
    };

    // Services to attempt:
    // 1. "tpm-fido" dedicated service (if installed)
    // 2. "vlock" interactive screen lock service (standard on Linux, uses pam_unix without faillock lockout)
    // 3. "sudo" / "system-auth" fallbacks
    const char *default_services[] = { "tpm-fido", "vlock", "sudo", "system-auth", "login" };
    const char **services = default_services;
    int service_count = sizeof(default_services) / sizeof(default_services[0]);

    const char *explicit_service[1];
    if (argc >= 3 && argv[2][0] != '\0') {
        explicit_service[0] = argv[2];
        services = explicit_service;
        service_count = 1;
    }

    int final_ret = PAM_AUTH_ERR;
    for (int i = 0; i < service_count; i++) {
        // Skip service if /etc/pam.d/<service> does not exist,
        // otherwise PAM falls back to /etc/pam.d/other which always rejects.
        if (!pam_service_exists(services[i])) {
            continue;
        }

        pam_handle_t *pamh = NULL;
        int ret = pam_start(services[i], username, &conv, &pamh);
        if (ret != PAM_SUCCESS) {
            continue;
        }

        ret = pam_authenticate(pamh, PAM_SILENT);

        if (ret == PAM_SUCCESS) {
            // Check account validity
            int acct_ret = pam_acct_mgmt(pamh, PAM_SILENT);
            if (acct_ret == PAM_SUCCESS || acct_ret == PAM_NEW_AUTHTOK_REQD) {
                final_ret = PAM_SUCCESS;
            } else {
                final_ret = acct_ret;
            }
            pam_end(pamh, final_ret);
            break;
        }

        final_ret = ret;
        pam_end(pamh, ret);
        break;
    }

    // Scrub secret memory before exiting
    explicit_bzero(&conv_data, sizeof(conv_data));

    if (final_ret == PAM_SUCCESS) {
        return 0; // Authenticated
    } else {
        return 1; // Incorrect password or auth failure
    }
}
