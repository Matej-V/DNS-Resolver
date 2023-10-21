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
    char *server;              // IP address or hostname of the queried server
    int port = 53;             // port number of the queried server, default 53
    char *query;               // query
} S_Arguments;

/* DNS question structure */
typedef struct dns_question {
    unsigned short qtype;
    unsigned short qclass;
} DNS_QUESTION;

/* DNS header structure */
typedef struct dns_header {
    unsigned short id;         // identification number
    unsigned char rd : 1;      // recursion desired
    unsigned char tc : 1;      // truncated message
    unsigned char aa : 1;      // authoritive answer
    unsigned char opcode : 4;  // purpose of message
    unsigned char qr : 1;      // query/response flag
    unsigned char rcode : 4;   // response code
    unsigned char cd : 1;      // checking disabled
    unsigned char ad : 1;      // authenticated data
    unsigned char z : 1;       // its z! reserved
    unsigned char ra : 1;      // recursion available
    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
} DNS_HEADER;

#pragma pack(1) // pack structure tightly to avoid padding
/* DNS resource record structure */
typedef struct dns_resource_record {
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
} DNS_RECORD;
#pragma pack()

/**
 * @brief Processes command line arguments and returns them in a structure.
 */
S_Arguments *processArguments(int argc, char *argv[]);

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

int createDNSQuery(S_Arguments *args, char *buf);

char *createQname(char *query);

char *addDotsToName(char *qname);

void parseDNSResponse(char *buffer, S_Arguments *args);

char *reverse_ip_address(char *ip_address);
