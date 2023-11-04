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
    {5, "CNAME"},
    {6, "SOA"},
    {12, "PTR"},
    {28, "AAAA"}};

const map<int, string> dns_classes = {
    {1, "IN"}}; // Internet

/* Main program */
int main(const int argc, char **argv) {
    try {
        s_arguments *args = process_arguments(argc, argv);
        int client_socket;
        struct hostent *host;
        struct sockaddr_in server_address; // Address of the DNS server

        // Get IP address of DNS server
        if ((host = gethostbyname((char *)args->server)) == NULL) {
            throw ResolverException(HOSTNAME_FAILURE, "Error: Unknown DNS server host: " + string((char *)args->server));
        }

        server_address.sin_family = AF_INET; // IPv4
        server_address.sin_port = htons(args->port);
        memcpy(&server_address.sin_addr, host->h_addr, host->h_length);

        // Create socket
        if ((client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Socket creation failed");
        }

        char buf[BUFSIZE];
        int size_of_query = create_DNS_query(args, (unsigned char *)buf);

        if (sendto(client_socket, (char *)buf, size_of_query, 0, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Sendto failed");
        }

        // Receive the answer
        int i = sizeof(server_address);
        if (recvfrom(client_socket, (char *)buf, BUFSIZE, 0, (struct sockaddr *)&server_address, (socklen_t *)&i) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Recvfrom failed");
        }

        // Parse DNS response
        parse_DNS_response((unsigned char *)buf);
        
        delete (args);
    } catch (const ResolverException &e) {
        fprintf(stderr, "%s\n", e.what());
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
    while ((opt = getopt_long(argc, argv, short_options, long_options, NULL)) != -1) {
        switch (opt) {
        case 'h':
            throw ResolverException(OK, "Usage: " + string(argv[0]) + " [-r] [-x] [-6] -s server [-p port] adresa");
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
            if (atoi(optarg) < 0 || atoi(optarg) > 65535) {
                throw ResolverException(INVALID_ARGUMENT, "Error: Invalid port number: " + string(optarg));
            }
            args->port = atoi(optarg);

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
        Hostname_Result result = qname_to_hostname((unsigned char *)(answer_start), buffer);
        int offset = result.offset;
        unsigned char *name = result.hostname;

        DNS_resource_record *answer = (DNS_resource_record *)(answer_start + offset);
        rdata = ((unsigned char *)answer + sizeof(DNS_resource_record));
        const char *type = (dns_record_types.find(ntohs(answer->type))->second).c_str();
        const char *class_ = (dns_classes.find(ntohs(answer->_class))->second).c_str();
        unsigned char *mname;
        unsigned char *mailbox;
        SOA_record *soa;

        int mname_offset;
        int mailbox_offset;

        switch (ntohs(answer->type)) {
        case 1: // A
            char ip_buf[INET_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET, rdata, ip_buf, INET_ADDRSTRLEN));
            break;
        case 5: // CNAME
            result = qname_to_hostname(rdata, buffer);
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), result.hostname);
            break;
        case 6: // SOA
            printf("%s, %s, %s, %d\n", name, type, class_, ntohl(answer->ttl));
            result = qname_to_hostname((unsigned char *)rdata, buffer);
            mname_offset = result.offset;
            mname = result.hostname;
            result = qname_to_hostname((unsigned char *)(rdata + mname_offset), buffer);
            mailbox_offset = result.offset;
            mailbox = result.hostname;

            soa = (SOA_record *)(rdata + mname_offset + mailbox_offset);
            printf("%s, %s, %d, %d, %d, %d, %d\n", mname, mailbox, ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry), ntohl(soa->expire), ntohl(soa->minimum));
            break;
        case 12: // PTR
            result = qname_to_hostname(rdata, buffer);
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), result.hostname);
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
        free(name);
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
    // Print flag values
    DNS_header *dns = (DNS_header *)buffer;
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->aa ? "Yes" : "No", dns->rd ? "Yes" : "No", dns->tc ? "Yes" : "No");

    // Print reply code
    if (dns->rcode != 0) {
        printf("Reply code: %s\n", (dns_reply_codes.find(dns->rcode))->second.c_str());
    }

    // Print question section
    printf("Question section (%d)\n", ntohs(dns->q_count));

    Hostname_Result result = qname_to_hostname((unsigned char *)(buffer + sizeof(DNS_header)), buffer);
    DNS_question *qinfo = (DNS_question *)(buffer + sizeof(DNS_header) + result.offset);
    unsigned char *domain_name = result.hostname;
    int offset = result.offset;
    printf("%s, %s, %d\n", domain_name, (dns_record_types.find(ntohs(qinfo->qtype))->second).c_str(), ntohs(qinfo->qclass));
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

    return sizeof(DNS_header) + strlen((const char *)QNAME) + 1 + sizeof(DNS_question);
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
 * @return A pointer to the newly created hostname string.
 * @throws ResolverException
 */
Hostname_Result qname_to_hostname(unsigned char *qname_start, unsigned char *buf_ptr) {
    unsigned char *hostname = (unsigned char *)malloc(256 * sizeof(unsigned char));
    if (hostname == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }
    unsigned char *hostname_ptr = hostname;
    unsigned char *ptr = qname_start;
    int offset = 0;

    int in_compression_flag = 0;
    while (*ptr != 0) {
        if ((*ptr & 0xC0) == 0xC0) { // Check for DNS compression pointer
            int pointer_offset = ((int)(*ptr & 0x3F) << 8) + *(ptr + 1);
            ptr = buf_ptr + pointer_offset;

            offset += 1;
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

            if (*ptr != 0) {
                *hostname_ptr = '.';
                hostname_ptr++;
            }
        }
    }

    *hostname_ptr++ = '.';
    *hostname_ptr = '\0';
    offset++;

    Hostname_Result result;
    result.hostname = hostname;
    result.offset = offset;

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
    unsigned char *ptr_domain = (unsigned char *)calloc(73, sizeof(char)); // 32 hex digits + 31 dots + 9 chars for the .ip6.arpa suffix + 1 null-terminator

    if (inet_pton(AF_INET6, (const char *)ipv6_address, i6_addr) != 1) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv6 address format: " + string((char *)ipv6_address));
    }

    int offset = 62;
    char *reversed_ip = (char *)calloc(64, sizeof(char)); // 32 hex digits + 31 dots + 1 null-terminator
    for (int i = 0; i < 16; i++) {
        reversed_ip[offset--] = hex_to_char[i6_addr[i] >> 4];
        reversed_ip[offset--] = '.';
        reversed_ip[offset--] = hex_to_char[i6_addr[i] & 0x0F];
        reversed_ip[offset--] = '.';
    }

    // Add the .ip6.arpa suffix
    snprintf((char *)ptr_domain, 73, "%s.ip6.arpa", reversed_ip);

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