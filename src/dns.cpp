/**
 * @file dns.cpp
 * @brief This file contains the implementation of the DNS resolver.
 * @author Vadovič Matej xvadov01
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
        S_Arguments *args = processArguments(argc, argv);
        int client_socket;
        struct hostent *host;              // host structure
        struct sockaddr_in server_address; // server address structure

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
        int size_of_query = createDNSQuery(args, (unsigned char *)buf);

        if (sendto(client_socket, (char *)buf, size_of_query, 0, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Sendto failed");
        }

        // Receive the answer
        int i = sizeof(server_address);
        if (recvfrom(client_socket, (char *)buf, BUFSIZE, 0, (struct sockaddr *)&server_address, (socklen_t *)&i) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Recvfrom failed");
        }

        // Parse DNS response
        parseDNSResponse((unsigned char *)buf);
        delete (args);
    } catch (const ResolverException &e) {
        if (e.returnCode != OK) {
            cerr << e.what() << endl;
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
S_Arguments *processArguments(int argc, char *argv[]) {
    S_Arguments *args = new S_Arguments;

    /* Process arguments*/
    int opt;
    while ((opt = getopt(argc, argv, "rx6s:p:")) != -1) {
        switch (opt) {
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
            args->port = atoi(optarg);
            break;
        default:
            throw ResolverException(INVALID_ARGUMENT, "Usage: " + string(argv[0]) + " [-r] [-x] [-6] -s server [-p port] adresa");
        }
    }

    // Get query
    if (optind < argc) {
        args->query = (unsigned char *)argv[optind];
    }

    // Check if the required argument (-s) is provided
    if (args->server == nullptr) {
        throw ResolverException(MISSING_ARGUMENT, "Error: -s option (server address/hostname) is required.");
    }

    // Check if the query is provided
    if (args->query == nullptr) {
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
unsigned char *parseSection(unsigned char *section_start, unsigned char *buffer, size_t n) {
    unsigned char *rdata;
    // Start of the answer section
    unsigned char *answer_start = section_start;

    if (n == 0 || section_start == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < n; i++) {
        unsigned char *qname = (unsigned char *)(answer_start);
        // Check for DNS Compression pointer - RFC 1035 4.1.4 Message compression
        int qname_length = 0;
        if ((qname[0] & 0xC0) == 0xC0) {
            qname = (unsigned char *)(buffer + (qname[0] & 0x3F) * 256 + qname[1]);
            qname_length = 2;
        } else {
            qname_length = strlen((const char *)qname) + 1;
        }

        struct dns_resource_record *answer = (struct dns_resource_record *)(answer_start + qname_length);
        rdata = ((unsigned char *)answer + sizeof(struct dns_resource_record));
        const char *type = (dns_record_types.find(ntohs(answer->type))->second).c_str();
        const char *class_ = (dns_classes.find(ntohs(answer->_class))->second).c_str();
        unsigned char *name = qname_to_hostname(qname);
        unsigned char *mname;
        unsigned char *mailbox;
        soa_record *soa;

        switch (ntohs(answer->type)) {
        case 1: // A
            char ip_buf[INET_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET, rdata, ip_buf, INET_ADDRSTRLEN));
            break;
        case 5: // CNAME
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), qname_to_hostname(rdata));
            break;
        case 6: // SOA
            printf("%s, %s, %s, %d\n", name, type, class_, ntohl(answer->ttl));
            mname = (unsigned char *)rdata;
            mailbox = mname + strlen((const char *)mname) + 1;
            soa = (soa_record *)(rdata + strlen((const char *)mname) + 1 + strlen((const char *)mailbox) + 1);
            printf("%s, %s, %d, %d, %d, %d, %d\n", qname_to_hostname(mname), qname_to_hostname(mailbox), ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry), ntohl(soa->expire), ntohl(soa->minimum));
            break;
        case 12: // PTR
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), qname_to_hostname(rdata));
            break;
        case 28: // AAAA
            char ip6_buf[INET6_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET6, rdata, ip6_buf, INET6_ADDRSTRLEN));
            break;
        default:
            throw ResolverException(OTHER_FAILURE, "Error: Unknown record type");
            break;
        }

        // Move to the next answer
        answer_start = (unsigned char *)answer + sizeof(struct dns_resource_record) + ntohs(answer->data_len);
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
void parseDNSResponse(unsigned char *buffer) {
    // Print flag values
    struct dns_header *dns = (struct dns_header *)buffer;
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->aa ? "Yes" : "No", dns->rd ? "Yes" : "No", dns->tc ? "Yes" : "No");

    // Print question section
    printf("Question section (%d)\n", ntohs(dns->q_count));
    unsigned char *qname = (unsigned char *)(buffer + sizeof(struct dns_header));
    struct dns_question *qinfo = (struct dns_question *)(buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1);
    unsigned char *domain_name = qname_to_hostname(qname);
    printf("%s, %s, %d\n", domain_name, (dns_record_types.find(ntohs(qinfo->qtype))->second).c_str(), ntohs(qinfo->qclass));
    free(domain_name);

    // Print answer section
    unsigned char *next_start = buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct dns_question);
    if (ntohs(dns->ans_count) > 0) {
        printf("Answer section (%d)\n", ntohs(dns->ans_count));
        next_start = parseSection(buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct dns_question), buffer, ntohs(dns->ans_count));
    }
    // Print authority section
    if (ntohs(dns->auth_count) > 0) {
        printf("Authority section (%d)\n", ntohs(dns->auth_count));
        next_start = parseSection(next_start, buffer, ntohs(dns->auth_count));
    }
    // Print additional section
    if (ntohs(dns->add_count) > 0) {
        printf("Additional section (%d)\n", ntohs(dns->add_count));
        next_start = parseSection(next_start, buffer, ntohs(dns->add_count));
    }
}

/**
 * @brief Fill the buffer with the DNS query
 *
 * @param args Pointer to the structure with command line arguments
 * @param buf_ptr Pointer to the buffer that will be sent to the server
 * @return Size of the created query
 */
int createDNSQuery(S_Arguments *args, unsigned char *buf_ptr) {
    struct dns_header *dns = (struct dns_header *)buf_ptr;

    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;     // This is a query
    dns->opcode = 0; // This is a standard query
    dns->aa = 0;     // Not Authoritative
    dns->tc = 0;     // This message is not truncated
    dns->rd = 1;     // Recursion Desired
    dns->ra = 0;     // Recursion not available
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // We have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    unsigned char *qname;
    if (args->inverse_query) {
        unsigned char *ptrDomain = reverse_ip_address(args->query);
        qname = createQname(ptrDomain);
        free(ptrDomain);
    } else {
        qname = createQname(args->query);
    }
    if (qname == NULL) {
        throw ResolverException(OTHER_FAILURE, "Qname creation failed. Check domain name format or IPv4/IPv6 address format.");
    }
    unsigned char *qname_ptr = buf_ptr + sizeof(struct dns_header);
    memcpy(qname_ptr, qname, strlen((const char *)qname) + 1); // Include the null-terminator

    struct dns_question *qinfo = (struct dns_question *)(buf_ptr + sizeof(struct dns_header) + strlen((const char *)qname) + 1);

    qinfo->qtype = args->inverse_query ? htons(12) : htons(args->record_type);
    qinfo->qclass = htons(1); // It's the internet

    return sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct dns_question);
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
unsigned char *createQname(unsigned char *input) {
    // Check if the input is valid
    if (input == NULL) return NULL;

    const char delimiter[] = ".";
    unsigned char *inputCopy = input; // Create a copy because strtok modifies the input
    int qnameLength = strlen((const char *)inputCopy);
    unsigned char *token;

    // Allocate memory for the qname
    unsigned char *result = (unsigned char *)calloc(qnameLength + 2, sizeof(unsigned char *)); // +2 for the null-terminator and the first length byte
    if (result == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }

    unsigned char *resultPtr = result;

    inputCopy = input;
    token = (unsigned char *)strtok((char *)inputCopy, delimiter);

    while (token != NULL) {
        int charCount = strlen((char *)token);
        *resultPtr++ = (char)charCount;
        memcpy(resultPtr, token, charCount);
        resultPtr += charCount;
        token = (unsigned char *)strtok(NULL, delimiter);
    }

    *resultPtr = '\0'; // Null-terminate the qname

    return result;
}

/**
 * @brief Convert a DNS-style QNAME to a hostname string.
 *
 * Takes a DNS-style QNAME and converts it into a hostname
 * string. Returns a pointer to the newly created hostname string.
 *
 * @param qname A pointer to the DNS-style QNAME to be converted.
 * @return A pointer to the newly created hostname string, or NULL if an error occurs.
 * @throws ResolverException
 */
unsigned char *qname_to_hostname(unsigned char *qname) {
    int qname_len = strlen((const char *)qname);
    unsigned char *domain_name = (unsigned char *)malloc(qname_len + 1); // +1 for the null-terminator
    if (domain_name == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }

    unsigned char *current = domain_name;
    unsigned char *qname_end = qname + qname_len;

    while (qname < qname_end) {
        int label_len = *qname;
        qname++; // Move past the label length byte

        if (current != domain_name) {
            // If not the first label, add a dot
            *current = '.';
            current++;
        }

        for (int i = 0; i < label_len; i++) {
            *current = *qname;
            current++;
            qname++;
        }
    }

    *current = '\0'; // Null-terminate the domain name

    return domain_name;
}

/**
 * @brief Expands compressed IPv6 address
 *
 * The IPv6 address is expanded to the full 128-bit representation. (e.g. 2001:db8::1 -> 2001:0db8:0000:0000:0000:0000:0000:0001)
 *
 * @param compressed Compressed IPv6 address
 * @return A pointer to the expanded IPv6 address
 */
unsigned char *expand_ipv6_address(unsigned char *compressed) {
    unsigned char *decompressed = (unsigned char *)malloc(40 * sizeof(char)); // 32 characters + 7 colons + 1 null-terminator
    char temp[5];
    temp[0] = '\0';

    // printHex(compressed, strlen((const char *)compressed));

    int num_groups = 0;
    int end_of_address = 0;
    int colon_flag = 0;

    while (*compressed != '\0' && !end_of_address) {
        int i = 0;

        while (*compressed != ':') {
            colon_flag = 1;
            if (*compressed == '\0') {
                end_of_address = 1;
                break;
            }
            temp[i++] = *compressed++;
        }

        if (i == 0) {
            if (colon_flag) {
                // Count how many more colons are in the address
                unsigned char *colon_ptr = compressed;
                int num_colons = 0;
                while (*colon_ptr != '\0') {
                    if (*colon_ptr == ':') {
                        num_colons++;
                    }
                    colon_ptr++;
                }
                // Check if it is the end of address

                int remaining_groups = 8 - num_groups - num_colons;
                unsigned char *end_ptr = compressed;
                if (*++end_ptr == '\0') {
                    end_of_address = 1;
                    remaining_groups++;
                }
                for (int j = 0; j < remaining_groups; j++) {
                    strcat((char *)decompressed, "0000");
                    num_groups++;
                    if (num_groups != 8) {
                        strcat((char *)decompressed, ":");
                    }
                }
            } else {
                colon_flag = 1;
                printf("Adding 4 zeros\n");
                temp[0] = '0';
                temp[1] = '0';
                temp[2] = '0';
                temp[3] = '0';
            }
        } else if (i == 1) {
            // shift 3 zeroes to the right
            temp[3] = temp[0];
            temp[0] = '0';
            temp[1] = '0';
            temp[2] = '0';
        } else if (i == 2) {
            // shift 2 zeroes to the right
            temp[3] = temp[1];
            temp[2] = temp[0];
            temp[0] = '0';
            temp[1] = '0';
        } else if (i == 3) {
            // shift 1 zero to the right
            temp[3] = temp[2];
            temp[2] = temp[1];
            temp[1] = temp[0];
            temp[0] = '0';
        }

        strcat((char *)decompressed, temp);

        if (num_groups != 8 && temp[0] != '\0') {
            strcat((char *)decompressed, ":");
        }
        num_groups++;

        temp[0] = '\0';

        compressed++; // Move the pointer to the next character
    }
    printf("Decompressed: %s\n", decompressed);
    return decompressed;
}

/**
 * @brief Reverse IPv4 address to create PTR record domain name
 *
 * @param ipv4_address A null-terminated string containing the IPv4 address in textual format.
 * @return A pointer to the reversed IPv4 address
 */
unsigned char *reverse_ipv4_address(unsigned char *ipv4_address) {
    char reversedIp[INET_ADDRSTRLEN];
    unsigned char *ptrDomain = (unsigned char *)malloc(sizeof(char) * 64);

    // Split the IPv4 address into octets
    unsigned int octet1, octet2, octet3, octet4;
    if (sscanf((const char *)ipv4_address, "%u.%u.%u.%u", &octet4, &octet3, &octet2, &octet1) != 4) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv4 address format: " + string((char *)ipv4_address));
    }

    // Reverse the octets to create the PTR record domain name
    snprintf(reversedIp, sizeof(reversedIp), "%u.%u.%u.%u", octet1, octet2, octet3, octet4);
    snprintf((char *)ptrDomain, 64, "%s.in-addr.arpa", reversedIp);

    return ptrDomain;
}

/**
 * @brief Reverse IPv6 address to create PTR record domain name
 *
 * @param ipv6_address A null-terminated string containing the IPv6 address in textual format.
 * @return A pointer to the reversed IPv6 address
 */
unsigned char *reverse_ipv6_address(unsigned char *ipv6_address) {
    unsigned char *reversedIPv6 = (unsigned char *)calloc(64, sizeof(char)); // 32 characters + 31 dots + 1 null-terminator
    unsigned char *ptrDomain = (unsigned char *)calloc(74, sizeof(char));    // 63 characters + 10 .ip6.arpa. + 1 null-terminator

    struct in6_addr addr;
    if (inet_pton(AF_INET6, (const char *)ipv6_address, &addr) != 1) {
        return NULL;
    }

    // Reverse the IPv6 address and insert dots after each 4 bits (nibble)
    int offset = 0;
    for (int i = 15; i >= 0; i--) {
        unsigned char byte = addr.s6_addr[i];
        sprintf((char *)reversedIPv6 + offset, "%02x.", byte);
        offset += 3; // Move the offset by 3 characters for each byte
    }

    // Remove the trailing dot and null-terminate the string
    reversedIPv6[offset - 1] = '\0';

    // Create the PTR record domain name
    int a = snprintf((char *)ptrDomain, 74, "%s.ip6.arpa", reversedIPv6);
    if (a < 0 || a >= 74) {
        throw ResolverException(OTHER_FAILURE, "Error: Creating PTR record domain name failed. Insufficient buffer size.");
    }
    free(reversedIPv6);
    free(ipv6_address);

    return ptrDomain;
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
        unsigned char *expanded = (unsigned char *)malloc(INET6_ADDRSTRLEN * sizeof(char));
        inet_ntop(AF_INET6, &ipv6, (char *)expanded, INET6_ADDRSTRLEN);
        printHex(expanded, strlen((const char *)expanded));
        return reverse_ipv6_address(expanded);
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
 * @param dataSize Size of the data
 */
void printHex(unsigned char *data, size_t dataSize) {
    for (size_t i = 0; i < dataSize; i++) {
        printf("%02X ", (unsigned char)data[i]);
    }
    printf("\n");
}

// Compile this file with the following command:
// g++ -std=c++11 -Wall -Wextra -pedantic -o dns dns.cpp