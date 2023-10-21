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
    try{
        S_Arguments *args = processArguments(argc, argv);
        int client_socket;
        struct hostent *host;              // host structure
        struct sockaddr_in server_address; // server address structure

        // Get IP address of DNS server
        if ((host = gethostbyname(args->server)) == NULL) {
            throw ResolverException(HOSTNAME_FAILURE, "Error: Unknown DNS server host: " + string(args->server));
        }

        server_address.sin_family = AF_INET; // IPv4
        server_address.sin_port = htons(args->port);
        memcpy(&server_address.sin_addr, host->h_addr, host->h_length);

        // Create socket
        if ((client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) <= 0) {
            throw ResolverException(SOCKET_FAILURE, "Error: Socket creation failed");
        }

        char buf[BUFSIZE];
        int size_of_query = createDNSQuery(args, buf);

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
        printf("Done\n");

        // Parse DNS response
        parseDNSResponse((char *)buf, args);
    } catch (const ResolverException &e) {
        if (e.returnCode != OK) {
            cerr << e.what() << endl;
        }
        return e.returnCode;
    }

    return OK;
}

/**
 * @brief Print the hexadecimal representation of the data
 * @param data Pointer to the data
 * @param dataSize Size of the data
 */
void printHex(const char *data, size_t dataSize) {
    for (size_t i = 0; i < dataSize; i++) {
        printf("%02X ", data[i]);
    }
    printf("\n");
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
            args->server = optarg;
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
        args->query = argv[optind];
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
 * @brief Parse DNS response
 * @param buffer Buffer with the DNS response
 * @param args Pointer to the structure with command line arguments
 */
void parseDNSResponse(char *buffer, S_Arguments *args) {
    // Print flag values
    struct dns_header *dns = (struct dns_header *)buffer;
    printf("Authoritative: %s, Recursive: %s, Truncated: %s\n", dns->aa ? "Yes" : "No", dns->rd ? "Yes" : "No", dns->tc ? "Yes" : "No");

    // Print question section
    printf("Question section (%d)\n", ntohs(dns->q_count));
    char *qname = (char *)(buffer + sizeof(struct dns_header));
    struct dns_question *qinfo = (struct dns_question *)(buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1);
    printf("%s, %s, %d\n", addDotsToName(qname), (dns_record_types.find(ntohs(qinfo->qtype))->second).c_str(), ntohs(qinfo->qclass));

    // Print answer section
    printf("Answer section (%d)\n", ntohs(dns->ans_count));
    char *rdata;

    // Start of the answer section
    char *answer_start = (char *)(buffer + sizeof(struct dns_header) + strlen((const char *)qname) + 1 + sizeof(struct dns_question));
    // printHex((const char*)answer_start, 122);

    for (int i = 0; i < ntohs(dns->ans_count); i++) {
        qname = (char *)(answer_start);
        struct dns_resource_record *answer = (struct dns_resource_record *)(answer_start + (strlen((const char *)qname) + 1));
        rdata = (char *)((char *)answer + sizeof(struct dns_resource_record));
        const char *type = (dns_record_types.find(ntohs(answer->type))->second).c_str();
        const char *class_ = (dns_classes.find(ntohs(answer->_class))->second).c_str();
        const char *name = addDotsToName(qname);

        char *ip_buf;

        switch (ntohs(answer->type)) {
        case 1: // A
            ip_buf = (char *)malloc(INET_ADDRSTRLEN);
            if (ip_buf == NULL) {
                throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
            }
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET, rdata, ip_buf, INET_ADDRSTRLEN));
            break;
        case 5: // CNAME
            // printHex(rdata, 16);
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), addDotsToName(rdata));
            break;
        case 12: // PTR
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), addDotsToName(rdata));
            break;
        case 28: // AAAA
            ip_buf = (char *)malloc(INET_ADDRSTRLEN);
            if (ip_buf == NULL) {
                throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
            }
            printf("%s, %s, %s, %d, %s\n", name, type, class_, ntohl(answer->ttl), inet_ntop(AF_INET6, rdata, ip_buf, INET6_ADDRSTRLEN));
            break;
        default:
            throw ResolverException(OTHER_FAILURE, "Error: Unknown record type");
            break;
        }

        // Move to the next answer
        answer_start += strlen((const char *)qname) + 1 + 10 + ntohs(answer->data_len);
    }
}

/**
 * @brief Fill the buffer with the DNS query
 * @param args Pointer to the structure with command line arguments
 * @param buf_ptr Pointer to the buffer that will be sent to the server
 * @return Size of the created query
 */
int createDNSQuery(S_Arguments *args, char *buf_ptr) {
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

    char *qname;
    if (args->inverse_query) {
        qname = createQname(reverse_ip_address(args->query));
    } else {
        qname = createQname(args->query);
    }
    if (qname == NULL) {
        throw ResolverException(OTHER_FAILURE, "Qname creation failed");
    }
    char *qname_ptr = buf_ptr + sizeof(struct dns_header);
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
char *createQname(char *input) {
    printf("In createQname\n");
    printf("Query is: %s\n", input);

    // Check if the input is valid
    if (input == NULL) return NULL;

    const char delimiter[] = ".";
    char *inputCopy = strdup(input); // Create a copy because strtok modifies the input
    int qnameLength = 0;
    char *token;

    // Calculate the length of the qname as the sum of the lengths of the labels + 1 byte for each label's length byte
    token = strtok(inputCopy, delimiter); // Get the first token
    while (token != NULL) {
        qnameLength += strlen(token) + 1;
        token = strtok(NULL, delimiter);
    }

    // Allocate memory for the qname
    char *result = (char *)malloc(qnameLength + 1); // Add 1 byte for the null terminator
    if (result == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }

    char *resultPtr = result;

    inputCopy = strdup(input);
    token = strtok(inputCopy, delimiter);

    while (token != NULL) {
        int charCount = strlen(token);
        *resultPtr++ = (char)charCount;
        memcpy(resultPtr, token, charCount);
        resultPtr += charCount;
        token = strtok(NULL, delimiter);
    }

    free(inputCopy);

    *resultPtr = '\0'; // Null-terminate the qname

    // DEBUG
    printf("Qname is: ");
    for (int i = 0; result[i] != '\0'; i++) {
        printf("\\x%02X", result[i]);
    }
    printf("\n");

    return result;
}

/**
 * @brief Add dots to the domain name, reverse function to createQname
 * @param qname Name with labels without dots
 * @return Name with dots between labels
 */
char *addDotsToName(char *qname) {
    int qname_len = strlen((const char *)qname);
    char *domain_name = (char *)malloc(qname_len + 1); // +1 for the null-terminator
    if (domain_name == NULL) {
        throw ResolverException(MEMORY_ALLOCATION_FAILURE, "Memory allocation failed");
    }

    char *current = domain_name;
    const char *qname_end = qname + qname_len;

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
int isIPv6(const char *address) {
    return (strchr(address, ':') != NULL);
}

/**
 * @brief Simpe check if the address is IPv4
 * @param address Address to check
 * @return 1 if the address is IPv4, 0 otherwise
 */
int isIPv4(const char *address) {
    return (strchr(address, '.') != NULL);
}

/**
 * @brief Reverse IPv4/IPv6 address to create PTR record domain name (e.g. 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
 * @param ip_address IP address to reverse
 * @return Reversed IP address
 */
char *reverse_ip_address(char *ip_address) {
    if (ip_address == NULL) {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IP address format");
    }
    // IPv4
    if (isIPv4(ip_address)) {
        char reversedIp[16]; // Max length of an IPv4 address is 15 characters
        char ptrDomain[64];  // Max length of a PTR domain name

        // Split the IPv4 address into octets
        unsigned int octet1, octet2, octet3, octet4;
        if (sscanf(ip_address, "%u.%u.%u.%u", &octet4, &octet3, &octet2, &octet1) != 4) {
            throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv4 address format" + string(ip_address));
        }

        // Reverse the octets to create the PTR record domain name
        snprintf(reversedIp, sizeof(reversedIp), "%u.%u.%u.%u", octet1, octet2, octet3, octet4);
        snprintf(ptrDomain, sizeof(ptrDomain), "%s.in-addr.arpa", reversedIp);

        return strdup(ptrDomain);
    } else if (isIPv6(ip_address)) {
        char reversedIp[INET6_ADDRSTRLEN];
        char ptrDomain[128]; // Max length of a PTR domain name

        // If the IPv6 address is compresed (e.g. 2001:db8::1), expand it (e.g. 2001:0db8:0000:0000:0000:0000:0000:0001)
        // TODO

        // Split the IPv6 address into 8 groups of 4 hexadecimal digits
        unsigned int hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8;
        if (sscanf(ip_address, "%x:%x:%x:%x:%x:%x:%x:%x", &hextet8, &hextet7, &hextet6, &hextet5, &hextet4, &hextet3, &hextet2, &hextet1) != 8) {
            throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IPv6 address format" + string(ip_address));
        }

        // Reverse the hextets to create the PTR record domain name
        snprintf(reversedIp, sizeof(reversedIp), "%x.%x.%x.%x.%x.%x.%x.%x", hextet1, hextet2, hextet3, hextet4, hextet5, hextet6, hextet7, hextet8);
        snprintf(ptrDomain, sizeof(ptrDomain), "%s.ip6.arpa", reversedIp);

        return strdup(ptrDomain);
    } else {
        throw ResolverException(INVALID_ADDRESS_FORMAT, "Error: Invalid IP address format");
    }
}

// Compile this file with the following command:
// g++ -std=c++11 -Wall -Wextra -pedantic -o dns dns.cpp