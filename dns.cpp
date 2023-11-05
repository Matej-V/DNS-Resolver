/**
 * @file dns.cpp
 * @brief This file contains the implementation of the DNS resolver.
 * @author Vadovič Matej, xvadov01
 *
 */

#include "dns.hpp"
using namespace std;

const map<int, string> dns_reply_codes = {
    {0x0, "No error occurred"},
    {0x1, "Format error"},
    {0x2, "Server failure"},
    {0x3, "Name error"},
    {0x4, "Unimplemented"},
    {0x5, "Operation refused"},
    {0x6, "Name exists"},
    {0x7, "RRset exists"},
    {0x8, "RRset does not exist"},
    {0x9, "Not authoritative for zone"},
    {0x10, "Zone of record different from zone section"}};

/*Map for types of records*/
const map<int, string> dns_record_types = {
    {1, "A"},
    {2, "NS"},
    {5, "CNAME"},
    {6, "SOA"},
    {12, "PTR"},
    {28, "AAAA"}};

const map<int, string> dns_classes = {
    {1, "IN"}}; // Internet

/* Main program */
int main(const int argc, char **argv) {
    s_arguments *args;
    try {
        args = process_arguments(argc, argv);

        // Get IP addresses of the DNS server
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC;     // Allow both IPv4 and IPv6
        hints.ai_socktype = SOCK_DGRAM;  // Datagram socket
        hints.ai_protocol = IPPROTO_UDP; // UDP protocol

        int status = getaddrinfo((const char *)args->server, std::to_string(args->port).c_str(), &hints, &res);
        if (status != 0) {
            throw ResolverException(HOSTNAME_FAILURE, "Error: " + std::string(gai_strerror(status)));
        }

        // Copy the first available address to 'server_address'
        struct sockaddr_storage server_address;
        socklen_t server_address_len;
        memcpy(&server_address, res->ai_addr, res->ai_addrlen);
        server_address_len = res->ai_addrlen;

        freeaddrinfo(res); // Free the linked list of addresses

        // Create socket
        int client_socket;
        if ((client_socket = socket(server_address.ss_family, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Socket creation failed");
        }

        // Set socket timeout, so that the program doesn't hang when the server doesn't respond, 3 seconds
        struct timeval timeout;
        timeout.tv_sec = 3;
        timeout.tv_usec = 0;
        if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Setsockopt failed");
        }

        char buf[BUFSIZE];
        int size_of_query = create_DNS_query(args, (unsigned char *)buf);

        if (sendto(client_socket, buf, size_of_query, 0, (struct sockaddr *)&server_address, server_address_len) < 0) {
            printf("Send to error: %s\n", strerror(errno));
            throw ResolverException(SOCKET_FAILURE, "Error: Sendto failed");
        }

        // Receive the answer
        server_address_len = sizeof(server_address);
        if (recvfrom(client_socket, buf, BUFSIZE, 0, (struct sockaddr *)&server_address, &server_address_len) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Recvfrom failed");
        }

        // Parse DNS response
        parse_DNS_response((unsigned char *)buf);

        // Close the socket
        close(client_socket);

        delete args;
    } catch (const ResolverException &e) {
        delete args;
        if (e.returnCode != OK) {
            fprintf(stderr, "%s\n", e.what());
        }
        return e.returnCode;
    }

    return OK;
}

/**
 * @brief Processes command line arguments and returns them in a structure.
 *
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @return Pointer to the structure with command line arguments
 */
s_arguments *process_arguments(int argc, char *argv[]) {
    s_arguments *args = new s_arguments;

    /* Process arguments*/
    int opt;
    int port;
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            printf("Usage: %s [-r] [-x] [-6] -s server [-p port] adresa\n", argv[0]);
            exit(OK);
        case 'r':
            args->recursion_desired = 1;
            break;
        case 'x':
            args->inverse_query = 1;
            break;
        case '6':
            args->record_type = 28;
            break;
        case 's':
            args->server = (unsigned char *)optarg;
            break;
        case 'p':
            // check if port is between 0 and 65535
            port = atoi(optarg);
            if (port < 0 || port > 65535 || !isdigit(optarg[0])) {
                throw ResolverException(INVALID_ARGUMENT, "Error: Invalid port number: " + string(optarg));
            }
            args->port = port;

            break;
        default:
            throw ResolverException(INVALID_ARGUMENT, "Usage: " + string(argv[0]) + " [-r] [-x] [-6] -s server [-p port] adresa");
        }
    }

    // Check if the required argument (-s) is provided
    if (args->server == NULL) {
        throw ResolverException(MISSING_ARGUMENT, "Error: -s option (server address/hostname) is required.");
    }

    // If -x is provided, the -6 option is ignored
    if (args->inverse_query && args->record_type == 28) {
        args->record_type = 12;
        fprintf(stderr, "Warning: -6 option is ignored when -x is used.\n");
    }

    // Get query and check that no other arguments are provided
    if (optind < argc) {
        args->query = (unsigned char *)argv[optind];
        if (optind + 1 < argc) {
            throw ResolverException(INVALID_ARGUMENT, "Error: Too many arguments.");
        }
    }

    // Check if the query is provided
    if (args->query == NULL) {
        throw ResolverException(MISSING_ARGUMENT, "Error: Query is missing.");
    }

    return args;
}

/**
 * @brief Parse section of the DNS response, e.g. answer section, suports only A, AAAA, CNAME, SOA and PTR records
 *
 * @param section_start Pointer to the start of the section
 * @param buffer Pointer to the buffer with the DNS response, used for DNS Compression pointer
 * @param n Number of records in the section
 */
unsigned char *parse_section(unsigned char *section_start, unsigned char *buffer, size_t n) {
    unsigned char *rdata;
    // Start of the answer section
    unsigned char *answer_start = section_start;

    if (section_start == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < n; i++) {
        Hostname_Result *result = qname_to_hostname((unsigned char *)(answer_start), buffer);
        int offset = result->offset;
        unsigned char *name = result->hostname;

        DNS_resource_record *answer = (DNS_resource_record *)(answer_start + offset);
        rdata = ((unsigned char *)answer + sizeof(DNS_resource_record));
        const char *type = (dns_record_types.find(ntohs(answer->type))->second).c_str();
        const char *class_ = (dns_classes.find(ntohs(answer->_class))->second).c_str();
        SOA_record *soa;

        Hostname_Result *mname_result = NULL;
        Hostname_Result *mailbox_result = NULL;

        Hostname_Result *rdata_result = qname_to_hostname(rdata, buffer);
        switch (ntohs(answer->type)) {
        case 1: // A
            char ip_buf[INET_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET, rdata, ip_buf, INET_ADDRSTRLEN));
            break;
        case 2: // NS
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), rdata_result->hostname);
            break;
        case 5: // CNAME
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), rdata_result->hostname);
            break;
        case 6: // SOA
            printf("%s, %s, %s, %d\n", name, type, class_, ntohl(answer->ttl));
            mname_result = qname_to_hostname((unsigned char *)rdata, buffer);
            mailbox_result = qname_to_hostname((unsigned char *)(rdata + mname_result->offset), buffer);
            soa = (SOA_record *)(rdata + mname_result->offset + mailbox_result->offset);
            printf("%s, %s, %d, %d, %d, %d, %d\n", mname_result->hostname, mailbox_result->hostname, ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry), ntohl(soa->expire), ntohl(soa->minimum));
            free(mname_result->hostname);
            free(mname_result);
            free(mailbox_result->hostname);
            free(mailbox_result);

            break;
        case 12: // PTR
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), rdata_result->hostname);
            break;
        case 28: // AAAA
            char ip6_buf[INET6_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET6, rdata, ip6_buf, INET6_ADDRSTRLEN));
            break;
        default:
            fprintf(stderr, "Error: Unsupported record type: %d\n", ntohs(answer->type));
            break;
        }

        // Move to the next answer
        answer_start = (unsigned char *)answer + sizeof(DNS_resource_record) + ntohs(answer->data_len);
        // Now free all the allocated memory
        free(result->hostname);
        free(result);
        free(rdata_result->hostname);
        free(rdata_result);
    }

    // Return the pointer to the start of the next section
    return answer_start;
}

/**
 * @brief Parse DNS response
 *
 * @param buffer Buffer with the DNS response
 */
void parse_DNS_response(unsigned char *buffer) {
    if (buffer == NULL) {
        return;
    }
    // Print flag values
    DNS_header *dns = (DNS_header *)buffer;
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->aa ? "Yes" : "No", dns->rd ? "Yes" : "No", dns->tc ? "Yes" : "No");

    // Print reply code
    if (dns->rcode != 0) {
        printf("Reply code: %s\n", (dns_reply_codes.find(dns->rcode))->second.c_str());
    }

    // Print question section
    printf("Question section (%d)\n", ntohs(dns->q_count));

    Hostname_Result *result = qname_to_hostname((unsigned char *)(buffer + sizeof(DNS_header)), buffer);
    DNS_question *qinfo = (DNS_question *)(buffer + sizeof(DNS_header) + result->offset);
    unsigned char *domain_name = result->hostname;
    int offset = result->offset;
    const char *type = (dns_record_types.find(ntohs(qinfo->qtype))->second).c_str();
    const char *class_ = (dns_classes.find(ntohs(qinfo->qclass))->second).c_str();
    printf("%s, %s, %s\n", domain_name, type, class_);
    free(domain_name);

    // Print answer section
    unsigned char *next_start = buffer + sizeof(DNS_header) + offset + sizeof(DNS_question);
    if (ntohs(dns->ans_count) > 0) {
        printf("Answer section (%d)\n", ntohs(dns->ans_count));
        next_start = parse_section(next_start, buffer, ntohs(dns->ans_count));
    }
    // Print authority section
    if (ntohs(dns->auth_count) > 0) {
        printf("Authority section (%d)\n", ntohs(dns->auth_count));
        next_start = parse_section(next_start, buffer, ntohs(dns->auth_count));
    }

    // Print additional section
    if (ntohs(dns->add_count) > 0) {
        printf("Additional section (%d)\n", ntohs(dns->add_count));
        next_start = parse_section(next_start, buffer, ntohs(dns->add_count));
    }
    free(result);
}

/**
 * @brief Fill the buffer with the DNS query
 *
 * @param args Pointer to the structure with command line arguments
 * @param buf_ptr Pointer to the buffer that will be sent to the server
 * @return Size of the created query
 */
int create_DNS_query(s_arguments *args, unsigned char *buf_ptr) {
    DNS_header *dns = (DNS_header *)buf_ptr;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;
    dns->opcode = 0; // This is a standard query
    dns->aa = 0;
    dns->tc = 0;
    dns->rd = args->recursion_desired; // Recursion Desired
    dns->ra = 0;
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char *QNAME;
    if (args->inverse_query) {
        unsigned char *ptr_domain = reverse_ip_address(args->query);
        QNAME = hostname_to_qname(ptr_domain);
        free(ptr_domain);
    } else {
        QNAME = hostname_to_qname(args->query);
    }
    if (QNAME == NULL) {
        throw ResolverException(OTHER_FAILURE, "QNAME creation failed. Check domain name format or IPv4/IPv6 address format.");
    }
    unsigned char *QNAME_ptr = buf_ptr + sizeof(DNS_header);
    memcpy(QNAME_ptr, QNAME, strlen((const char *)QNAME) + 1); // Include the null-terminator

    DNS_question *qinfo = (DNS_question *)(buf_ptr + sizeof(DNS_header) + strlen((const char *)QNAME) + 1);

    qinfo->qtype = args->inverse_query ? htons(12) : htons(args->record_type);
    qinfo->qclass = htons(1);

    int size_of_query = sizeof(DNS_header) + strlen((const char *)QNAME) + 1 + sizeof(DNS_question);

    free(QNAME);

    return size_of_query;
}

/**
 * @brief Create a DNS-style QNAME from a query.
 *
 * This function takes a query and converts it into a DNS-style QNAME,
 * which is a sequence of labels separated by dots. Returns a pointer
 * to the newly created QNAME.
 *
 * @param query A null-terminated string containing the query to be converted.
 * @return A pointer to the newly created QNAME, or NULL if an error occurs.
 * @throws ResolverException
 */
unsigned char *hostname_to_qname(unsigned char *input) {
    // Check if the input is valid
    if (input == NULL) return NULL;

    const char delimiter[] = ".";
    unsigned char *input_copy = input; // Create a copy because strtok modifies the input
    int qname_length = strlen((const char *)input_copy);
    unsigned char *token;

    // Allocate memory for the qname
    unsigned char *result = (unsigned char *)calloc(qname_length + 2, sizeof(unsigned char *)); // +2 for the null-terminator and the first length byte
    if (result == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }

    unsigned char *result_ptr = result;

    input_copy = input;
    token = (unsigned char *)strtok((char *)input_copy, delimiter);

    while (token != NULL) {
        int char_count = strlen((char *)token);
        *result_ptr++ = (char)char_count;
        memcpy(result_ptr, token, char_count);
        result_ptr += char_count;
        token = (unsigned char *)strtok(NULL, delimiter);
    }

    *result_ptr = '\0'; // Null-terminate the qname

    return result;
}

/**
 * @brief Convert a DNS-style QNAME to a hostname string.
 *
 * Takes a DNS-style QNAME and converts it into a hostname. Supports DNS Compression pointer.
 *
 * @param qname_start A pointer to the DNS-style QNAME to be converted.
 * @param buf_ptr Pointer to the buffer that contains the DNS response, used for DNS Compression pointer
 * @return A pointer to the newly created Hostname_Result structure
 * @throws ResolverException
 */
Hostname_Result * qname_to_hostname(unsigned char *qname_start, unsigned char *buf_ptr) {
    unsigned char *hostname = (unsigned char *)calloc(256,  sizeof(unsigned char));
    if (hostname == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }
    unsigned char *hostname_ptr = hostname;
    unsigned char *ptr = qname_start;
    int offset = 0;

    int in_compression_flag = 0;
    while (*ptr != '\0') {
        if ((*ptr & 0xC0) == 0xC0) { // Check for DNS compression pointer
            int pointer_offset = ((int)(*ptr & 0x3F) << 8) + *(ptr + 1);
            ptr = buf_ptr + pointer_offset;

            if (!in_compression_flag) offset += 1;
            in_compression_flag = 1;
        } else {
            int label_len = *ptr;
            ptr++;

            if (!in_compression_flag) offset++;

            strncpy((char *)hostname_ptr, (char *)ptr, label_len);
            hostname_ptr += label_len;
            ptr += label_len;
            if (!in_compression_flag) offset += label_len;
            ;

            if (*ptr != '\0') {
                *hostname_ptr = '.';
                hostname_ptr++;
            }
        }
    }

    *hostname_ptr++ = '.';
    *hostname_ptr = '\0';
    offset++;

    Hostname_Result *result = (Hostname_Result *)malloc(sizeof(Hostname_Result));
    if (result == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }
    result->hostname = hostname;
    result->offset = offset;

    return result;
}

/**
 * @brief Reverse IPv4 address to create PTR record domain name
 *
 * @param ipv4_address A null-terminated string containing the IPv4 address in textual format.
 * @return A pointer to the reversed IPv4 address
 */
unsigned char *reverse_ipv4_address(unsigned char *ipv4_address) {
    char reversed_ip[INET_ADDRSTRLEN];
    unsigned char *ptr_domain = (unsigned char *)malloc(sizeof(char) * 64);

    // Split the IPv4 address into octets
    unsigned int octet1, octet2, octet3, octet4;
    if (sscanf((const char *)ipv4_address, "%u.%u.%u.%u", &octet4, &octet3, &octet2, &octet1) != 4) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv4 address format: " + string((char *)ipv4_address));
    }

    // Reverse the octets to create the PTR record domain name
    snprintf(reversed_ip, sizeof(reversed_ip), "%u.%u.%u.%u", octet1, octet2, octet3, octet4);
    snprintf((char *)ptr_domain, 64, "%s.in-addr.arpa", reversed_ip);

    return ptr_domain;
}

/**
 * @brief Reverse IPv6 address to create PTR record domain name.
 *
 * This function reverses the IPv6 address to create the PTR record domain name together with adding dots after each hex digit and the in-addr.arpa suffix.
 *
 * @param ipv6_address A null-terminated string containing the IPv6 address in textual format.
 * @return A pointer to the reversed IPv6 address
 */
unsigned char *reverse_ipv6_address(unsigned char *ipv6_address) {
    uint8_t i6_addr[16];
    unsigned char *ptr_domain = (unsigned char *)calloc(73, sizeof(char)); // 32 hex digits + 31 dots + 10 chars for the .ip6.arpa. suffix + 1 null-terminator

    if (inet_pton(AF_INET6, (const char *)ipv6_address, i6_addr) != 1) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv6 address format: " + string((char *)ipv6_address));
    }

    int offset = 62;

    char *reversed_ip = (char *)calloc(64, sizeof(char)); // 32 hex digits + 31 dots + 1 null-terminator
    for (int i = 0; i < 16; i++) {
        reversed_ip[offset--] = hex_to_char[i6_addr[i] >> 4];
        reversed_ip[offset--] = '.';
        reversed_ip[offset--] = hex_to_char[i6_addr[i] & 0x0F];
        if (i != 15) reversed_ip[offset--] = '.';
    }

    // Add the .ip6.arpa suffix and copy reversed_ip to ptr_domain
    snprintf((char *)ptr_domain, 73, "%s.ip6.arpa.", reversed_ip);

    free(reversed_ip);

    return ptr_domain;
}

/**
 * @brief Reverse IPv4/IPv6 address to create PTR record domain name. Uses separate functions for IPv4 and IPv6 addresses.
 *
 * @param ip_address A null-terminated string containing the IP address in textual format.
 * @return A pointer to the reversed IP address
 */
unsigned char *reverse_ip_address(unsigned char *ip_address) {

    struct in6_addr ipv6;
    struct in_addr ipv4;

    if (inet_pton(AF_INET6, (const char *)ip_address, &ipv6) == 1) {
        return reverse_ipv6_address(ip_address);
    } else if (inet_pton(AF_INET, (const char *)ip_address, &ipv4) == 1) {
        return reverse_ipv4_address(ip_address);
    } else {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IP address format: " + string((char *)ip_address));
    }
}

/**
 * @brief Print the hexadecimal representation of the data
 *
 * Used for debugging purposes.
 *
 * @param data Pointer to the data
 * @param data_size Size of the data
 */
void print_hex(unsigned char *data, size_t data_size) {
    for (size_t i = 0; i < data_size; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    printf("\n");
}

// Compile this file with the following command:
// g++ -std=c++11 -Wall -Wextra -pedantic -o dns dns.cpp