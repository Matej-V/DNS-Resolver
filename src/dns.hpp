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
#include <libnet.h> // libnet
#include <netdb.h>  // gai_strerror
#include <pcap.h>

#define BUFSIZE 65536
#define MAX_IPV6_LENGTH 40

/* Return codes */
enum return_codes {
    OK,
    INVALID_ARGUMENT,
    MISSING_ARGUMENT,
    HOSTNAME_FAILURE,
    SOCKET_FAILURE,
    INVALID_ADDRESS_FORMAT,
    MEMORY_ALLOCATION_FAILURE,
    OTHER_FAILURE,
};

/* Data structure to hold command line arguments */
typedef struct arguments {
    int recursion_desired = 0; // recursion desired flag, 0 = no recursion, 1 = recursion
    int inverse_query = 0;     // inverse query flag, 0 = normal query, 1 = inverse query
    int record_type = 1;       // record type, 1 for A(default), 28 for AAAA
    unsigned char *server;     // IP address or hostname of the queried server
    int port = 53;             // port number of the queried server, default 53
    unsigned char *query;      // query
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
    uint8_t opcode : 4;  // purpose of message, 4 = standard query
    uint8_t qr : 1;      // query/response flag
    uint8_t rcode : 4;   // response code
    uint8_t cd : 1;      // checking disabled
    uint8_t ad : 1;      // authenticated data
    uint8_t z : 1;
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
    uint16_t type;      // type of resource
    uint16_t _class;    // class of resource
    uint32_t ttl;       // time to live
    uint16_t data_len;  // length of data field
} DNS_RECORD;
#pragma pack()

/* SOA record sctructure*/
typedef struct soa_record {
    uint32_t serial;    // serial number
    uint32_t refresh;   // refresh interval
    uint32_t retry;     // retry interval
    uint32_t expire;    // expire interval
    uint32_t minimum;   // minimum TTL
} SOA_RECORD;

/**
 * @class
 * @brief Exception class for handling errors
 * 
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
 * 
 * @param argc Number of arguments
 * @param argv Array of arguments
 * @return Pointer to the structure with command line arguments
 */
S_Arguments *processArguments(int argc, char *argv[]);

/**
 * @brief Parse section of the DNS response, suports only A, AAAA, CNAME, SOA and PTR records
 * 
 * @param section_start Pointer to the start of the section
 * @param buffer Pointer to the buffer with the DNS response, used for DNS Compression pointer
 * @param n Number of records in the section
 */
unsigned char *parseSection(unsigned char *section_start, unsigned char *buffer, size_t n);

/**
 * @brief Parse DNS response
 * 
 * @param buffer Buffer with the DNS response
 */
void parseDNSResponse(unsigned char *buffer);

/**
 * @brief Fill the buffer with the DNS query
 * 
 * @param args Pointer to the structure with command line arguments
 * @param buf_ptr Pointer to the buffer that will be sent to the server
 * @return Size of the created query
 */
int createDNSQuery(S_Arguments *args, unsigned char *buf_ptr);

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
unsigned char *createQname(unsigned char *query);

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
unsigned char *qname_to_hostname(unsigned char *qname);

/**
 * Check if the given string represents a valid IPv6 address.
 *
 * This function checks whether the provided string is a valid
 * textual representation of an IPv6 address using the inet_pton function.
 * 
 * @param address A pointer to a null-terminated string containing
 * the IPv6 address in textual format.
 * @return 1 if the address is IPv6, 0 otherwise
 */
int isIPv6(const unsigned char *address);

/**
 * Check if the given string represents a valid IPv4 address.
 *
 * This function checks whether the provided string is a valid
 * textual representation of an IPv4 address using the inet_pton function.
 * 
 * @param address A pointer to a null-terminated string containing
 * the IPv4 address in textual format.
 * @return 1 if the address is IPv6, 0 otherwise
 */
int isIPv4(const unsigned char *address);

/**
 * @brief Expands compressed IPv6 address
 * 
 * The IPv6 address is expanded to the full 128-bit representation. (e.g. 2001:db8::1 -> 2001:0db8:0000:0000:0000:0000:0000:0001)
 * 
 * @param compressed Compressed IPv6 address
 * @return A pointer to the expanded IPv6 address
 */
unsigned char *expand_ipv6_address(unsigned char *compressed);

/**
 * @brief Reverse IPv4 address to create PTR record domain name
 * 
 * @param ipv4_address A null-terminated string containing the IPv4 address in textual format.
 * @return A pointer to the reversed IPv4 address
*/
unsigned char *reverse_ipv4_address(unsigned char *ipv4_address);

/**
 * @brief Reverse IPv6 address to create PTR record domain name
 * 
 * @param ipv6_address A null-terminated string containing the IPv6 address in textual format.
 * @return A pointer to the reversed IPv6 address
*/
unsigned char *reverse_ipv6_address(unsigned char *ipv6_address);

/**
 * @brief Reverse IPv4/IPv6 address to create PTR record domain name. Uses separate functions for IPv4 and IPv6 addresses.
 * 
 * @param ip_address A null-terminated string containing the IP address in textual format.
 * @return A pointer to the reversed IP address
*/
unsigned char *reverse_ip_address(unsigned char *ip_address);

/**
 * @brief Print the hexadecimal representation of the data
 * 
 * Used for debugging purposes.
 * 
 * @param data Pointer to the data
 * @param dataSize Size of the data
 */
void printHex(unsigned char *data, size_t dataSize);
