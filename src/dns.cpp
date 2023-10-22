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
    {2, "NS"},
    {5, "CNAME"},
    {6, "SOA"},
    {11, "WKS"},
    {12, "PTR"},
    {13, "HINFO"},
    {15, "MX"},
    {16, "TXT"},
    {28, "AAAA"}};

const map<int, string> dns_classes = {
    {1, "IN"}}; // Internet

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

        printf("\nSending Packet...");
        if (sendto(client_socket, (char *)buf, size_of_query, 0, (struct sockaddr *)&server_address, sizeof(server_address)) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Sendto failed");
        }
        printf("Done\n");

        // Receive the answer
        int i = sizeof(server_address);
        printf("Receiving answer...");
        if (recvfrom(client_socket, (char *)buf, BUFSIZE, 0, (struct sockaddr *)&server_address, (socklen_t *)&i) < 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Recvfrom failed");
        }
        printf("Done\n\n");

        // Parse DNS response
        parseDNSResponse((unsigned char *)buf, args);
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
        printHex(answer_start, sizeof(struct dns_resource_record) + ntohs(answer->data_len));
        const char *type = (dns_record_types.find(ntohs(answer->type))->second).c_str();
        const char *class_ = (dns_classes.find(ntohs(answer->_class))->second).c_str();
        unsigned char *name = addDotsToName(qname);
        unsigned char *mname;
        unsigned char *mailbox;
        soa_record *soa;

        printf("Type: %d\n", ntohs(answer->type));
        switch (ntohs(answer->type)) {
        case 1: // A
            char ip_buf[INET_ADDRSTRLEN];
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET, rdata, ip_buf, INET_ADDRSTRLEN));
            break;
        case 5: // CNAME
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), addDotsToName(rdata));
            break;
        case 6: // SOA
            printf("%s, %s, %s, %d\n", name, type, class_, ntohl(answer->ttl));
            mname = (unsigned char *)rdata;
            mailbox = mname + strlen((const char *)mname) + 1;
            soa = (soa_record *)(rdata + strlen((const char *)mname) + 1 + strlen((const char *)mailbox) + 1);
            printf("%s, %s, %d, %d, %d, %d, %d\n", addDotsToName(mname), addDotsToName(mailbox), ntohl(soa->serial), ntohl(soa->refresh), ntohl(soa->retry), ntohl(soa->expire), ntohl(soa->minimum));
            break;
        case 12: // PTR
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), addDotsToName(rdata));
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
 * @param buffer Buffer with the DNS response
 * @param args Pointer to the structure with command line arguments
 */
void parseDNSResponse(unsigned char *buffer, S_Arguments *args) {
    // Print flag values
    struct dns_header *dns = (struct dns_header *)buffer;
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->aa ? "Yes" : "No", dns->rd ? "Yes" : "No", dns->tc ? "Yes" : "No");

    // Print question section
    printf("Question section (%d)\n", ntohs(dns->q_count));
    unsigned char *qname = (unsigned char *)(buffer + sizeof(struct dns_header));
    struct dns_question *qinfo = (struct dns_question *)(buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1);
    unsigned char *domain_name = addDotsToName(qname);
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
        printf("PTR domain: %s\n", ptrDomain);
        qname = createQname(ptrDomain);
        free(ptrDomain);
    } else {
        qname = createQname(args->query);
    }
    if (qname == NULL) {
        throw ResolverException(OTHER_FAILURE, "Qname creation failed");
    }
    unsigned char *qname_ptr = buf_ptr + sizeof(struct dns_header);
    memcpy(qname_ptr, qname, strlen((const char *)qname) + 1); // Include the null-terminator

    struct dns_question *qinfo = (struct dns_question *)(buf_ptr + sizeof(struct dns_header) + strlen((const char *)qname) + 1);

    qinfo->qtype = args->inverse_query ? htons(12) : htons(args->record_type);
    qinfo->qclass = htons(1); // It's the internet

    return sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct dns_question);
}

/**
 * @brief Create qname. Converts query to qname. Example: www.fit.vutbr.cz -> \3www\3fit\5vutbr\2cz\0
 * https://stackoverflow.com/questions/34841206/why-is-the-content-of-qname-field-not-the-original-domain-in-a-dns-message
 * @param query Convert this address to qname
 * @return String with qname
 */
unsigned char *createQname(unsigned char *input) {
    printf("In createQname\n");
    printf("Query is: %s\n", input);

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

    // DEBUG
    printf("Qname is: %s\n", result);

    return result;
}

/**
 * @brief Add dots to the domain name, reverse function to createQname
 * @param qname Name with labels without dots
 * @return Name with dots between labels
 */
unsigned char *addDotsToName(unsigned char *qname) {
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
 * @brief Simpe check if the address is IPv6
 * @param address Address to check
 * @return 1 if the address is IPv6, 0 otherwise
 */
int isIPv6(unsigned char *address) {
    return (strchr((const char *)address, ':') != NULL);
}

/**
 * @brief Simpe check if the address is IPv4
 * @param address Address to check
 * @return 1 if the address is IPv4, 0 otherwise
 */
int isIPv4(unsigned char *address) {
    return (strchr((const char *)address, '.') != NULL);
}

/**
 * @brief Expand compressed IPv6 address (e.g. 2001:db8::1 -> 2001:0db8:0000:0000:0000:0000:0000:0001)
 * @param address Address to expand
 * @return Expanded address
 */

unsigned char *expand_ipv6_address(unsigned char *compressed) {
    unsigned char *decompressed = (unsigned char *)calloc(MAX_IPV6_LENGTH, sizeof(char));
    char temp[5];
    temp[0] = '\0';

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

        printf("i: %d\n", i);

        if (i == 0) {
            printf("i == 0\n");
            printf("Colon flag: %d\n", colon_flag);
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

                printf("Num colons: %d\n", num_colons);
                int remaining_groups = 8 - num_groups - num_colons;
                unsigned char *end_ptr = compressed;
                if (*++end_ptr == '\0') {
                    end_of_address = 1;
                    remaining_groups++;
                }
                printf("Remaining groups: %d\n", remaining_groups);
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
        printf("Temp: %s\n", temp);

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

unsigned char *reverse_ipv4_address(unsigned char *ipv4_address) {
    char reversedIp[INET_ADDRSTRLEN];
    unsigned char *ptrDomain = (unsigned char *)malloc(sizeof(char) * 64);

    // Split the IPv4 address into octets
    unsigned int octet1, octet2, octet3, octet4;
    if (sscanf((const char *)ipv4_address, "%u.%u.%u.%u", &octet4, &octet3, &octet2, &octet1) != 4) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv4 address format" + string((char *)ipv4_address));
    }

    // Reverse the octets to create the PTR record domain name
    snprintf(reversedIp, sizeof(reversedIp), "%u.%u.%u.%u", octet1, octet2, octet3, octet4);
    snprintf((char *)ptrDomain, 64, "%s.in-addr.arpa", reversedIp);

    return ptrDomain;
}

unsigned char *reverse_ipv6_address(unsigned char *ipv6_address) {
    unsigned char *reversedIPv6 = (unsigned char *)calloc(64, sizeof(char)); // 32 characters + 31 dots + 1 null-terminator
    unsigned char *ptrDomain = (unsigned char *)calloc(74, sizeof(char));    // 63 characters + 10 .ip6.arpa. + 1 null-terminator
    ipv6_address = expand_ipv6_address(ipv6_address);
    // create copy of the ipv6 address
    unsigned char *ipv6_address_copy = ipv6_address;
    printHex(ipv6_address, strlen((char *)ipv6_address));

    // Split the IPv6 address into characters
    unsigned char *tmp_ptr = reversedIPv6;
    for (int i = 31; *ipv6_address_copy != '\0'; i--) {
        printf("i: %d\n", i);
        if (*ipv6_address_copy == ':') {
            ipv6_address_copy++;
            i++; // skip the colon, no character is added
            continue;
        }
        *tmp_ptr++ = *ipv6_address_copy++;
        if (i != 0) {
            *tmp_ptr++ = '.';
        }
    }
    *tmp_ptr = '\0';

    printf("Reversed IPv6: %s\n", reversedIPv6);

    // Create the PTR record domain name
    int a = snprintf((char *)ptrDomain, 74, "%s.ip6.arpa", reversedIPv6);
    printf("returned %d\n", a);
    free(reversedIPv6);
    free(ipv6_address);

    return ptrDomain;
}

unsigned char *reverse_ip_address(unsigned char *ip_address) {
    if (ip_address == NULL) {
        // Handle invalid IP address
        return NULL;
    }

    if (isIPv4(ip_address)) {
        return reverse_ipv4_address(ip_address);
    } else if (isIPv6(ip_address)) {
        return reverse_ipv6_address(ip_address);
    } else {
        // Handle invalid IP address format
        return NULL;
    }
    printf("Exiting reverse_ip_address\n");
}

/**
 * @brief Print the hexadecimal representation of the data
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