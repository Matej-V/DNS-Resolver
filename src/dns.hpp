/**
 * @file dns.hpp
 * @brief Header file for the dns resolver application. It contains the definitions of classes and functions.
 * @author Vadovič Matej xvadov01
 *
 */

#include <cstring> // std::strerror
#include <getopt.h>
// #include <iomanip>
#include <iostream>
// #include <stdio.h>
#include <map>      // map header
#include <string>   // std::string
#include <unistd.h> // getopt

// #include <ctime>
// #include <arpa/nameser.h> // DNS header, reply codes, etc.
#include <libnet.h>       // libnet
#include <netdb.h>        // gai_strerror
#include <pcap.h>

#define BUFSIZE 65536
#define MAX_IPV6_LENGTH 40


/* Return codes */
enum return_codes {
    OK,                     // Everything is OK
    INVALID_ARGUMENT,       // Invalid command line argument
    MISSING_ARGUMENT,       // Missing command line argument
    HOSTNAME_FAILURE,       // Hostname failure
    SOCKET_FAILURE,         // Socket failure
    NO_SPACE_FOR_HEADER,    // Not enough space for the new header
    INVALID_ADDRESS_FORMAT ,
    MEMORY_ALLOCATION_FAILURE,
    OTHER_FAILURE,
};

/* Data structure to hold command line arguments */
typedef struct arguments {
    int recursion_desired = 0; // recursion desired flag, 0 = no recursion, 1 = recursion
    int inverse_query = 0;     // inverse query flag, 0 = normal query, 1 = inverse query
    int record_type = 1;       // record type, 1 for A(default), 28 for AAAA
    unsigned char *server;              // IP address or hostname of the queried server
    int port = 53;             // port number of the queried server, default 53
    unsigned char *query;               // query
} S_Arguments;

#pragma pack(1) // pack structure tightly to avoid padding
/* DNS question structure */
typedef struct dns_question {
    uint16_t qtype;
    uint16_t qclass;
} DNS_QUESTION;
#pragma pack()

#pragma pack(1) // pack structure tightly to avoid padding
/* DNS header structure */
typedef struct dns_header {
    uint16_t id;         // identification number
    uint8_t rd : 1;      // recursion desired
    uint8_t tc : 1;      // truncated message
    uint8_t aa : 1;      // authoritive answer
    uint8_t opcode : 4;  // purpose of message
    uint8_t qr : 1;      // query/response flag
    uint8_t rcode : 4;   // response code
    uint8_t cd : 1;      // checking disabled
    uint8_t ad : 1;      // authenticated data
    uint8_t z : 1;       // its z! reserved
    uint8_t ra : 1;      // recursion available
    uint16_t q_count;    // number of question entries
    uint16_t ans_count;  // number of answer entries
    uint16_t auth_count; // number of authority entries
    uint16_t add_count;  // number of resource entries
} DNS_HEADER;
#pragma pack()

#pragma pack(1) // pack structure tightly to avoid padding
/* DNS resource record structure */
typedef struct dns_resource_record {
    uint16_t type;
    uint16_t _class;
    uint32_t ttl;
    uint16_t data_len;
} DNS_RECORD;
#pragma pack()

/* SOA record sctructure*/
typedef struct soa_record{
	uint32_t serial;
	uint32_t refresh;
	uint32_t retry;
	uint32_t expire;
	uint32_t minimum;
} SOA_RECORD;

/**
 * @class
 * @brief Exception class for handling errors
 * @details Used for handling errors. It contains return code and a message.
 */
class ResolverException : public std::exception {
  public:
    const int returnCode;
    const std::string msg;
    ResolverException(int returnCode, const std::string &msg) : returnCode(returnCode), msg(msg) {}
    virtual const char *what() const throw() {
        return msg.c_str();
    }
};


/**
 * @brief Processes command line arguments and returns them in a structure.
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @return Pointer to the structure with command line arguments
 */
S_Arguments *processArguments(int argc, char *argv[]);

/**
 * @brief Parse section of the DNS response, e.g. answer section, suports only A, AAAA, CNAME, SOA and PTR records
 * @param section_start Pointer to the start of the section
 * @param buffer Pointer to the buffer with the DNS response, used for DNS Compression pointer
 * @param n Number of records in the section
*/
unsigned char * parseSection(unsigned char* section_start, unsigned char* buffer, size_t n);

/**
 * @brief Parse DNS response
 * @param buffer Buffer with the DNS response
 * @param args Pointer to the structure with command line arguments
 */
void parseDNSResponse(unsigned char *buffer, S_Arguments *args);

/**
 * @brief Fill the buffer with the DNS query
 * @param args Pointer to the structure with command line arguments
 * @param buf_ptr Pointer to the buffer that will be sent to the server
 * @return Size of the created query
 */
int createDNSQuery(S_Arguments *args, unsigned char *buf);

/**
 * @brief Create qname. Converts query to qname. Example: www.fit.vutbr.cz -> \3www\3fit\5vutbr\2cz\0
 * https://stackoverflow.com/questions/34841206/why-is-the-content-of-qname-field-not-the-original-domain-in-a-dns-message
 * @param query Convert this address to qname
 * @return String with qname
 */
unsigned char *createQname(unsigned char *query);

/**
 * @brief Add dots to the domain name, reverse function to createQname
 * @param qname Name with labels without dots
 * @return Name with dots between labels
 */
unsigned char *addDotsToName(unsigned char *qname);

/**
 * @brief Simpe check if the address is IPv6
 * @param address Address to check
 * @return 1 if the address is IPv6, 0 otherwise
 */
int isIPv6(const unsigned char *address);

/**
 * @brief Simpe check if the address is IPv4
 * @param address Address to check
 * @return 1 if the address is IPv4, 0 otherwise
 */
int isIPv4(const unsigned char *address);

/**
 * @brief Reverse IPv4/IPv6 address to create PTR record domain name (e.g. 1.2.3.4 -> 4.3.2.1.in-addr.arpa)
 * @param ip_address IP address to reverse
 * @return Reversed IP address
 */
unsigned char * reverse_ip_address(unsigned char *ip_address);

/**
 * @brief Print the hexadecimal representation of the data
 * @param data Pointer to the data
 * @param dataSize Size of the data
 */
void printHex(unsigned char *data, size_t dataSize);

