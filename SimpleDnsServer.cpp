/*
Copyright (c) 2022 Rahul Sreeram.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

*/


#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/types.h>
#include <unistd.h>

namespace
{
    uint32_t _DEF_DNS_PORT = 53;

/*
Query header format
 0  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     ID                        |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   OPCODE  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  QDCOUNT                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  ANCOUNT                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  NSCOUNT                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                  ARCOUNT                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                                               /
/                  HOSTNAME                     /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   QTYPE                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                   QCLASS                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/

// Disable padding
#pragma pack(push, 1)
    struct DnsHeader
    {
        uint16_t id;
        union
        {
            uint16_t flag_code;
            struct
            {
#if __BYTE_ORDER == __BIG_ENDIAN
                uint8_t qr :1;
                uint8_t opcode :4;
                uint8_t aa :1;
                uint8_t tc :1;
                uint8_t rd :1;
                uint8_t ra :1;
                uint8_t zero :3;
                uint8_t rcode :4;
#elif __BYTE_ORDER == __LITTLE_ENDIAN
                uint8_t rcode :4;
                uint8_t zero :3;
                uint8_t ra :1;
                uint8_t rd :1;
                uint8_t tc :1;
                uint8_t aa :1;
                uint8_t opcode :4;
                uint8_t qr :1;
#else
#error "Endian?"
#endif
            } fc_bits;
        } fc;
        uint16_t quest_count;
        uint16_t ans_count;
        uint16_t auth_rec_count;
        uint16_t addl_rec_count;

        // Network to host
        void NtoH()
        {
            id = ntohs(id);
            fc.flag_code = ntohs(fc.flag_code);
            quest_count = ntohs(quest_count);
            ans_count = ntohs(ans_count);
            auth_rec_count = ntohs(auth_rec_count);
            addl_rec_count = ntohs(addl_rec_count);
        }

        // Host to network
        void HtoN()
        {
            id = htons(id);
            fc.flag_code = htons(fc.flag_code);
            quest_count = htons(quest_count);
            ans_count = htons(ans_count);
            auth_rec_count = htons(auth_rec_count);
            addl_rec_count = htons(addl_rec_count);
        }

        bool IsQuery()
        {
            return (fc.fc_bits.qr == 0) && (fc.fc_bits.opcode == 0);
        }

        friend std::ostream& operator<<(std::ostream& ostr, const DnsHeader& h)
        {
            ostr << std::hex;
            ostr << "Id=0x" << h.id
                 << ", Flags/Code=0x" << h.fc.flag_code
                 << std::dec
                 << ", query=" << +h.fc.fc_bits.qr
                 << ", quest_count=" << h.quest_count
                 << ", ans_count=" << h.ans_count
                 << ", auth_rec_count=" << h.auth_rec_count
                 << ", addl_rec_count=" << h.addl_rec_count;

            return ostr;
        }
    };

    struct DnsQuery
    {
        // name is of variable. so, not part of the struct
        uint16_t qtype;
        uint16_t qclass;

        // Network to host
        void NtoH()
        {
            qtype = ntohs(qtype);
            qclass = ntohs(qclass);
        }

        // IPv4 query
        bool IsA()
        {
            return (qtype == 1);
        }

        // IPv6 query
        bool IsAAAA()
        {
            return (qtype == 28);
        }

        // reverse lookup query
        bool IsPTR()
        {
            return (qtype == 12);
        }

        bool IsInet()
        {
            return (qclass == 1);
        }

        friend std::ostream& operator<<(std::ostream& ostr, const DnsQuery& q)
        {
            ostr << std::hex
                 << "qtype=" << q.qtype
                 << ", qclass=" << q.qclass;

            return ostr;
        }
    };

    // resource record
    struct DnsRr
    {
        // Use pointer method to reuse the hostname from query
        uint16_t name_ptr = 0xC00C;
        uint16_t type = 1;
        uint16_t dclass = 1;
        uint32_t ttl = 100;
        uint16_t rdlength = 0;
        // data follows length

        // Host to network
        void HtoN()
        {
            name_ptr = htons(name_ptr);
            type = htons(type);
            dclass = htons(dclass);
            ttl = htonl(ttl);
            rdlength = htons(rdlength);
        }
    };
#pragma pack(pop)

    struct BufSizePair
    {
        uint8_t* ptr;
        int size;
    };

    bool _verb = false;
    using RawData = std::vector<uint8_t>;
    std::unordered_map<std::string, RawData> _dns_a_map; // v4
    std::unordered_map<std::string, RawData> _dns_aaaa_map; // v6
    std::unordered_map<std::string, RawData> _dns_ptr_map; // reverse lookup
}

bool HandleATypeQuery(const std::string& name, struct BufSizePair& res, int type)
{
    if (type == AF_INET)
    {
        // IPv4
        auto itr = _dns_a_map.find(name);
        if (itr != _dns_a_map.end())
        {
            res.ptr = itr->second.data();
            res.size = itr->second.size();
            return true;
        }
    }
    else
    {
        // IPv6
        auto itr = _dns_aaaa_map.find(name);
        if (itr != _dns_aaaa_map.end())
        {
            res.ptr = itr->second.data();
            res.size = itr->second.size();
            return true;
        }
    }
    if (_verb)
    {
        std::cout << "Unable to find address for type: " << type
                  << ", name: " << name << "\n";
    }

    return false;
}

bool HandlePtrQuery(const std::string& name, struct BufSizePair& res)
{
    auto itr = _dns_ptr_map.find(name);
    if (itr == _dns_ptr_map.end())
    {
        if (_verb)
        {
            std::cout << "PTR lookup failed for " << name << "\n";
        }
        return false;
    }

    res.ptr = itr->second.data();
    res.size = itr->second.size();

    return true;
}

std::string ExtractHostname(uint8_t*& ptr)
{
    // hostname is separated into labels using "."
    // Length byte specifies till "." and "." is skipped.
    // 0 length specifies end.
    std::string host;
    int len = 0;
    while (*ptr != 0)
    {
        // get length of first part
        len = *ptr++;
        host.append((const char *)ptr, len);
        ptr += len;
        if (*ptr == 0)
        {
            break;
        }
        // more parts to hostname.
        host.append(".");
    }

    // Consume the last 0
    ++ptr;

    return host;
}

RawData EncodeHostname(const std::string& name)
{
    // Need 2 more than length: 1 to store size of first label
    // 1 to store the null terminator
    RawData vec(name.length() + 2);

    std::istringstream iss(name);
    std::string label;
    uint8_t *ptr = vec.data();
    while (std::getline(iss, label, '.'))
    {
        // store the size of the label
        auto len = label.length();
        *ptr++ = len;
        // copy the label
        memcpy(ptr, label.c_str(), len);
        ptr += len;
    }
    // store the null term
    *ptr = 0;

    return vec;
}

std::unique_ptr<uint8_t> ParseMsg(uint8_t* a_SourcePtr, int& ans_size)
{
    uint8_t* ptr = a_SourcePtr;
    // Start with header
    struct DnsHeader head = *(struct DnsHeader *)ptr;
    head.NtoH();
    // std::cout << head << "\n";

    // Check if its a query
    if (!head.IsQuery())
    {
        if (_verb)
        {
            std::cout << "Not a query. Dropping msg:" << head.id << "\n";
        }
        return nullptr;
    }

    // Right now, only one question at a time
    if (head.quest_count > 1)
    {
        if (_verb)
        {
            std::cout << "Single question query only!\n";
        }
        return nullptr;
    }

    // extract hostname
    ptr += sizeof(DnsHeader);
    auto host = ExtractHostname(ptr);
    if (_verb)
    {
        std::cout << "Querying hostname: " << host << "\n";
    }

    // ptr has been moved ahead of the name by ExtractHostname()
    struct DnsQuery query = *(struct DnsQuery *)ptr;
    query.NtoH();
    ptr += sizeof(DnsQuery);

    if (!query.IsInet())
    {
        if (_verb)
        {
            std::cout << "Non Internet queries not supported " << query.qclass << "\n";
        }
        return nullptr;
    }

    // Calculate query size
    int q_size = ptr - a_SourcePtr;
    struct DnsRr rr;
    int af_type = 0;
    if (query.IsA())
    {
        af_type = AF_INET;
    }
    else if (query.IsAAAA())
    {
        af_type = AF_INET6;
    }
    else if (!query.IsPTR())
    {
        if (_verb)
        {
            std::cout << "Non A/AAAA/PTR queries not supported\n";
        }
        return nullptr;
    }

    rr.type = query.qtype;
    // use same buffer for both A and AAAA
    struct BufSizePair b_pair;
    bool valid = false;
    if (af_type)
    {
        valid = HandleATypeQuery(host, b_pair, af_type);
    }
    else
    {
        valid = HandlePtrQuery(host, b_pair);
    }

    if (!valid)
    {
        // no record found
        head.fc.fc_bits.rcode = 2;
        ans_size = q_size;
    }
    else
    {
        rr.rdlength = b_pair.size;
        head.ans_count = 1;
        // ans size = sizeof original query + sizeof DnsRr + rdata
        ans_size = q_size + sizeof(DnsRr) + rr.rdlength;
    }
    head.fc.fc_bits.qr = 1;
    head.fc.fc_bits.aa = 1;
    rr.HtoN();
    head.HtoN();
    std::unique_ptr<uint8_t> ans(new uint8_t[ans_size]);
    uint8_t* ans_buf = ans.get();
    // copy the updated header
    memcpy(ans_buf, &head, sizeof(DnsHeader));
    // copy the name from original buffer
    memcpy(ans_buf+sizeof(DnsHeader), a_SourcePtr+sizeof(DnsHeader), q_size - sizeof(DnsHeader));
    if (valid)
    {
        // copy the resource record
        uint8_t *rr_ptr = ans_buf + q_size;
        memcpy(rr_ptr, &rr, sizeof(DnsRr));
        rr_ptr += sizeof(DnsRr);
        // copy the resource data
        memcpy(rr_ptr, b_pair.ptr, ntohs(rr.rdlength));
    }

    return ans;
}

void Server(int servfd)
{
    fd_set fds;
    FD_ZERO(&fds);

    if (_verb)
    {
        std::cout << "Starting to listen on " << servfd << "\n";
    }

    uint8_t buffer[500];
    while (1)
    {
        FD_SET(servfd, &fds);
        int ret = select(servfd+1, &fds, NULL, NULL, NULL);
        if (ret < 1)
        {
            perror("Select didnt return 1");
            exit(1);
        }

        // check for our fd
        if (!FD_ISSET(servfd, &fds))
        {
            std::cout << "fd not set!\n";
            exit(1);
        }

        memset(&buffer, 0, sizeof buffer);
        struct sockaddr_in6 saddr;
        memset(&saddr, 0, sizeof saddr);
        socklen_t saddr_size =  sizeof(saddr);
        int bytes = recvfrom(servfd, &buffer[0], sizeof buffer, 0, (struct sockaddr *)&saddr, &saddr_size);
        if (bytes < 1)
        {
            perror("Failed to receive data");
            exit(1);
        }

        if (_verb)
        {
            char client_ip[INET6_ADDRSTRLEN] = {0};
            if (inet_ntop(AF_INET6, &(saddr.sin6_addr), client_ip, sizeof(client_ip)) != NULL)
            {
                std::cout << "Received message from: " << client_ip << "\n";
            }
        }


        int ans_size = 0;
        std::unique_ptr<uint8_t> reply = ParseMsg(buffer, ans_size);
        if (reply)
        {
            sendto(servfd, reply.get(), ans_size, 0, (struct sockaddr *)&saddr, sizeof saddr);
        }
    }
}

int CreateSocketAndBind(uint16_t port)
{
    int s = socket(AF_INET6, SOCK_DGRAM, 0);
    if (!s)
    {
        perror("Unable to create socket");
        exit(1);
    }

    // dual stack is supported by default on Linux. Set again just in case its not
    int off = 0;
    setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));

    struct sockaddr_in6 saddr;
    memset(&saddr, 0, sizeof saddr);

    saddr.sin6_family = AF_INET6;
    saddr.sin6_addr = in6addr_any;
    saddr.sin6_port = htons(port);

    if (bind(s, (struct sockaddr *)&saddr, sizeof saddr) != 0)
    {
        perror("Bind failed for port");
        if (errno == EACCES)
        {
            std::cout << "If port number below 1024, then need root permissions\n";
        }
        exit(1);
    }

    if (_verb)
    {
        std::cout << "Socket " << s << " created for port " << port << "\n";
    }

    return s;
}

// p contains ip in network format
std::string ReverseIp(const uint8_t *p, int af_type)
{
    /*
     * Handle IPv4 and IPv6 differently
     * IPv4: 1.2.3.4 -> 4.3.2.1.in-addr.arpa
     * IPv6: 2001:db8::567:89ab -> b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
     */

    // IPv4
    if (af_type == AF_INET)
    {
        // make a copy
        int v4 = *(int*) p;
        uint8_t* ptr = (uint8_t *)&v4;
        // need to swap the array elements
        std::swap(ptr[0], ptr[3]);
        std::swap(ptr[1], ptr[2]);
        char buf[INET_ADDRSTRLEN] = {0};
        if (inet_ntop(af_type, &v4, buf, sizeof(buf)) == NULL)
        {
            std::cout << "Failed to reverse convert: 0x" << std::hex << v4 << "\n";
            return std::string();
        }
        std::string v4_s(buf);
        v4_s.append(".in-addr.arpa");
        if (_verb)
        {
            std::cout << "RevIp = " << v4_s << "\n";
        }
        return v4_s;
    }

    // IPv6
    // Convert to hex ascii and add . between each nibble value
    std::ostringstream ostr;
    ostr << std::hex;
    for (size_t i = 0; i < sizeof(in6_addr); ++i)
    {
        // get the higher nibble and convert to hex
        // then get lower
        ostr << "." << ((p[i] & 0xF0) >> 4) << "." << (p[i] & 0xF);
    }
    std::string v6ip = ostr.str();
    std::reverse(v6ip.begin(), v6ip.end());
    v6ip.append("ip6.arpa");
    if (_verb)
    {
        std::cout << "RevIp = " << v6ip << "\n";
    }
    return v6ip;
}

void PopulateDnsMap(const std::string& confFile)
{
    std::ifstream ifs(confFile);
    if (!ifs.is_open())
    {
        std::cout << "Failed to open file: " << confFile << "\n";
        exit(1);
    }

    if (_verb)
    {
        std::cout << "Reading entires from file: " << confFile << "\n";
    }
    std::string line, word, name, type, ip;
    while (std::getline(ifs, line))
    {
        // hostname<space>IP
        // use istringstream so that it can be expanded in future if needed
        // Lines starting with # are skipped
        if (line[0] == '#')
        {
            continue;
        }
        std::istringstream iss(line);
        std::vector<std::string> words;
        while (std::getline(iss, word, ' '))
        {
            words.push_back(word);
        }
        if (words.size() != 2)
        {
            std::cout << "Num of args wrong: " << line << "\n";
        }
        else
        {
            name = words[0];
            ip = words[1];
            if (_verb)
            {
                std::cout << "Name: " << name << ", IP: " << ip << "\n";
            }

            struct addrinfo hints, *result;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC; // v4 + v6
            hints.ai_socktype = SOCK_DGRAM;
            hints.ai_flags = AI_NUMERICHOST;
            int gres = getaddrinfo(ip.c_str(), NULL, &hints, &result);
            if (gres != 0)
            {
                std::cout << "Error in parsing IP: " << ip << ", err: " << gai_strerror(gres) << "\n";
                continue;
            }

            // Save the network format into the map
            int size = 0;
            uint8_t *ptr = nullptr;
            if (result->ai_family == AF_INET)
            {
                size = sizeof(struct in_addr);
                auto itr_pair = _dns_a_map.emplace(std::make_pair(name, RawData(size)));
                if (itr_pair.second == true)
                {
                    ptr = itr_pair.first->second.data();
                    struct sockaddr_in *sock = (struct sockaddr_in *) result->ai_addr;
                    memcpy(ptr, &(sock->sin_addr.s_addr), size);
                }
                else
                {
                    std::cout << "Insertion failed for: " << name << "\n";
                    continue;
                }
            }
            else
            {
                size = sizeof(struct in6_addr);
                auto itr_pair = _dns_aaaa_map.emplace(std::make_pair(name, RawData(size)));
                if (itr_pair.second == true)
                {
                    ptr = itr_pair.first->second.data();
                    struct sockaddr_in6 *sock = (struct sockaddr_in6 *) result->ai_addr;
                    memcpy(ptr, &(sock->sin6_addr), size);
                }
                else
                {
                    std::cout << "Insertion failed for: " << name << "\n";
                    continue;
                }
            }

            // save to the reverse lookup map
            _dns_ptr_map.emplace(std::make_pair(ReverseIp(ptr, result->ai_family), EncodeHostname(name)));
        }
    }

    if (_verb)
    {
        std::cout << "Finished parsing file\n\n";
    }
}

int main(int argc, char** argv)
{
    // Args parsing
    const char *file = nullptr;
    uint32_t port = _DEF_DNS_PORT;

    int opt = 0;
    while ((opt = getopt(argc, argv, "vp:f:")) != -1)
    {
        switch (opt)
        {
            case 'v':
                _verb = true;
                break;
            case 'f':
                file = optarg;
                break;
            case 'p':
                port = strtoul(optarg, NULL, 10);
                if (!port || (port > 65535))
                {
                    std::cout << "Port argument invalid/out of range: "
                              << optarg << "\n";
                    exit(1);
                }
                break;
            default:
                std::cout << "Usage:\n" << argv[0]
                          << " <-f conf_file> [-p port_num] [-v]\n";
                exit(1);
        }
    }

    if (!file)
    {
        std::cout << "Must specify a entries file (-f option)\n";
        exit(1);
    }


    PopulateDnsMap(file);
    int servfd = CreateSocketAndBind((uint16_t) port);
    Server(servfd);
    return 0;
}
