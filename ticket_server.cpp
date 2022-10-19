#include <iostream>
#include <unistd.h>
#include <cstdlib>
#include <cstdarg>
#include <cerrno>
#include <cstring>
#include <unordered_map>
#include <queue>
#include <fstream>
#include <utility>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <variant>
#include <unordered_set>

#ifndef NDEBUG
const bool debug = true;
#else
const bool debug = false;
#endif

#define PORT_DEFAULT 2022
#define TIMEOUT_DEFAULT 5

#define RESERVATION_ID_START 1000000

#define DATAGRAM_CAPACITY 65507

#define COOKIE_LEN 48
#define TICKET_LEN 7

#define GET_EVENTS_LEN 1
#define GET_RESERVATION_LEN 7
#define GET_TICKETS_LEN 53

#define GET_EVENTS_ID 1
#define EVENTS_ID 2
#define GET_RESERVATION_ID 3
#define RESERVATION_ID 4
#define GET_TICKETS_ID 5
#define TICKETS_ID 6
#define BAD_REQUEST_ID 255

void fatal(const char *fmt, ...) {
    va_list fmt_args;

    fprintf(stderr, "[SERVER] Error: ");
    va_start(fmt_args, fmt);
    vfprintf(stderr, fmt, fmt_args);
    va_end(fmt_args);
    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}


// Abstraction for buffer.
class Buffer {
private:
    char buffer[DATAGRAM_CAPACITY];
    size_t len;
    size_t read_it;

public:
    Buffer() : len(0), read_it(0) {};

    char* get_content() {
        return buffer;
    }

    void set_len(size_t len_) {
        len = len_;
        read_it = 0;
    }
    
    void reset() {
        set_len(0);
    }

    size_t get_len() {
        return len;
    }

    uint8_t get_message_id() {
        return (uint8_t) buffer[0];
    }

    // Reads and returns next variable of type T placed in the buffer.
    template<typename T>
    T read_primitive() {
        T val;
        memcpy(&val, buffer + read_it, sizeof(T));
        read_it += sizeof(T);
        return val;
    }

    void read_str(char *str, size_t str_len) {
        for (size_t i = 0; i < str_len; i++) {
            str[i] = buffer[read_it + i];
        }
        read_it += str_len;
    }

    // Writes variable of type T in the next bytes of the buffer.
    template<typename T>
    void write_primitive(T val) {
        memcpy(buffer + len, &val, sizeof(T));
        len += sizeof(T);
    }
    
    void write_str(std::string &str, size_t str_len) {
        for (size_t i = 0; i < str_len; i++) {
            buffer[len + i] = str[i];
        }
        len += str_len;
    }
    
    void write_cstr(const char *str, size_t str_len) {
        for (size_t i = 0; i < str_len; i++) {
            buffer[len + i] = str[i];
        }
        len += str_len;
    }
};

// Abstract wrapper class for client's queries.
class Query {
private:
    uint8_t message_id;

public:
    Query(uint8_t message_id_) : message_id(message_id_) {};

    uint8_t get_message_id() {
        return message_id;
    }
};

class GetEvents : public Query {
public:
    GetEvents() : Query(GET_EVENTS_ID) {};
};

class GetReservation : public Query {
private:
    uint32_t event_id;
    uint16_t ticket_count;

public:
    GetReservation(Buffer &buffer) : Query(GET_RESERVATION_ID) {
        event_id = ntohl(buffer.read_primitive<uint32_t>());
        ticket_count = ntohs(buffer.read_primitive<uint16_t>());
    }

    [[nodiscard]] uint32_t get_event_id() const {
        return event_id;
    }

    [[nodiscard]] uint16_t get_ticket_count() const {
        return ticket_count;
    }
};

class GetTickets : public Query {
private:
    uint32_t reservation_id;
    char cookie[COOKIE_LEN + 1];

public:
    GetTickets(Buffer &buffer) : Query(GET_TICKETS_ID) {
        reservation_id = ntohl(buffer.read_primitive<uint32_t>());
        buffer.read_str(cookie, COOKIE_LEN);
        cookie[COOKIE_LEN] = '\0';
    };

    [[nodiscard]] uint32_t get_reservation_id() const {
        return reservation_id;
    }

    char* get_cookie() {
        return cookie;
    }

};

using QueryVariant = std::variant<GetEvents, GetReservation, GetTickets>;

// Handles parsing program arguments and client's queries.
class Parser {
private:
    static uint16_t get_port(char *arg) {
        errno = 0;
        char *end_ptr = arg;
        unsigned long port = strtoul(arg, &end_ptr, 10);

        if (errno != 0 || port > UINT16_MAX || *end_ptr != '\0') {
            fatal("Invalid port number.");
        }

        return (uint16_t) port;
    }

    static uint32_t get_timeout(char *arg) {
        errno = 0;
        unsigned long timeout = strtoul(arg, nullptr, 10);

        if (errno != 0 || timeout < 1 || timeout > 86400) {
            fatal("Invalid timeout argument.");
        }

        return (uint32_t) timeout;
    }

public:
    Parser() = default;

    static void parse_arguments(int argc, char **argv, std::string &filename, uint16_t &port, uint32_t &timeout) {
        if (argc < 3) {
            std::cerr << "Usage: " << argv[0] << " -f 'filename' [-p 'port'] [-t 'timeout']\n";
            std::cerr << "   'filename' - name of the file which contains info about events.\n";
            std::cerr << "   'port' - number of the port (0 - 65535).\n";
            std::cerr << "   'timeout' - number from 1 to 86400 inclusive.\n";
            exit(1);
        }

        bool fflag = false, pflag = false, tflag = false;
        int c;
        int count = 0;

        while ((c = getopt(argc, argv, ":f:p:t:")) != -1) {
            count += 2;
            switch(c) {
                case 'f':
                    fflag = true;
                    filename = optarg;
                    if (filename.empty()) {
                        fatal("Filename cannot be an empty string.\n");
                    }
                    break;

                case 'p':
                    pflag = true;
                    port = get_port(optarg);
                    break;

                case 't':
                    tflag = true;
                    timeout = get_timeout(optarg);
                    break;

                case ':':
                    fatal("Option -%c needs a value.", optopt);

                case '?':
                    fatal("Unknown option -%c.", optopt);

                default:
                    exit(1);
            }
        }

        if (!fflag)
            fatal ("-f 'filename' option required.");
        if (argc - 1 != count)
            fatal("Invalid options and/or arguments.");
        if (!pflag)
            port = PORT_DEFAULT;
        if (!tflag)
            timeout = TIMEOUT_DEFAULT;
    }

    static std::optional<QueryVariant> parse_query(Buffer &buffer) {
        auto message_id = buffer.read_primitive<uint8_t>();

        switch(message_id) {
            case 1:
                if (buffer.get_len() == GET_EVENTS_LEN)
                    return GetEvents{};
            case 3:
                if (buffer.get_len() == GET_RESERVATION_LEN)
                    return GetReservation(buffer);
            case 5:
                if (buffer.get_len() == GET_TICKETS_LEN)
                    return GetTickets(buffer);
            default:
                return {};
        }
    }
};

// Local 'database' of the server. Stores the data and handles creating responses to the clients.
class ServerDatabase {
private:

    // {description, ticket_count}
    using event_t = std::pair<std::string, uint16_t>;

    // event_id -> {description, ticket_count}
    using events_info_t = std::unordered_map<uint32_t, event_t>;

    // {expiration_time, reservation_id}
    using expiration_t = std::pair<int64_t, uint32_t>;

    // Priority queue used for checking if any reservation expired.
    using expiration_q = std::priority_queue<expiration_t , std::vector<expiration_t>, std::greater<>>;

    // reservation_id -> {event_id, ticket_count}
    using reservation_t = std::unordered_map<uint32_t, std::pair<uint32_t, uint16_t>>;

    // reservation_id -> cookie
    using authentication_t = std::unordered_map<uint32_t, std::string>;

    // reservation_id -> {sequence of tickets, whether tickets are collected}
    using tickets_t = std::unordered_map<uint32_t, std::pair<std::vector<std::string>, bool>>;

    events_info_t events_info;
    expiration_q expiration_times;
    reservation_t reservations;
    authentication_t authentication;
    tickets_t tickets;

    uint32_t cur_event_id = 0;
    uint32_t cur_reservation_id = RESERVATION_ID_START;
    uint32_t timeout;
    std::string filename;

    // To create unique ticket codes.
    std::unordered_set<std::string> used_tickets;

    void add_event(std::pair<std::string, int> &&event_info) {
        events_info[cur_event_id] = event_info;
        cur_event_id = (cur_event_id + 1) % RESERVATION_ID_START;
    }

    uint64_t get_expiration_time() const {
        time_t current = time(nullptr);
        return current + this->timeout;
    }

    // Generates new ticket. Adds it to the vector of client's tickets.
    void gen_ticket(std::vector<std::string> &t) {
        static const char alphanum[] = {
                "1234567890QWERTYUIOPASDFGHJKLZXCVBNM"
        };

        std::string cur_ticket;
        cur_ticket.resize(TICKET_LEN);
        do {
            for (uint32_t j = 0; j < TICKET_LEN; j++) {
                cur_ticket[j] = alphanum[random() % (sizeof(alphanum) - 1)];
            }
        } while(used_tickets.count(cur_ticket) > 0); // Check whether created ticket already exists.

        used_tickets.insert(cur_ticket);
        t.push_back(cur_ticket);
    }

    void generate_tickets(uint32_t reservation_id, uint16_t ticket_count) {
        tickets[reservation_id] = {{}, false};
        std::vector<std::string> &cur_tickets = tickets[reservation_id].first;

        for (uint32_t i = 0; i < ticket_count; i++) {
            gen_ticket(cur_tickets);
        }
    }

    void bad_request_response(Buffer &buffer, uint32_t id) {
        buffer.write_primitive<uint8_t>(BAD_REQUEST_ID);
        buffer.write_primitive<uint32_t>(htonl(id));
    }
    
    void events_response(Buffer &buffer) {

        if (debug) {
            printf("[SERVER] Received GET_EVENTS. Writing response...\n");
        }

        // Write message_id.
        buffer.write_primitive<uint8_t>(EVENTS_ID);
        
        for (auto & it : events_info) {
            uint32_t event_id = it.first;
            std::string description = it.second.first;
            uint16_t ticket_count = it.second.second;
            uint8_t description_length = description.size();

            size_t event_size = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint8_t) + description_length;
            if (buffer.get_len() + event_size > DATAGRAM_CAPACITY) {
                break;
            }

            buffer.write_primitive<uint32_t>(htonl(event_id));
            buffer.write_primitive<uint16_t>(htons(ticket_count));
            buffer.write_primitive<uint8_t>(description_length);
            buffer.write_str(description, description_length);
        }
    }

    void gen_cookie(char* cookie) {
        for (size_t i = 0; i < COOKIE_LEN; i++) {
            cookie[i] = (char) (random() % 94 + 33);
        }
    }

    // Update database after receiving correct reservation request.
    void reservation_update_db(uint32_t ev_id, uint32_t res_id, uint16_t ticket_count, 
                               char *cookie, uint64_t exp_time) {
        
        events_info[ev_id].second -= ticket_count;
        reservations[res_id] = {ev_id, ticket_count};
        expiration_times.emplace(exp_time, res_id);

        cookie[COOKIE_LEN] = '\0';
        authentication[res_id] = cookie;
        generate_tickets(res_id, ticket_count);
    }

    // Write tickets, assigned to given reservation_id, to the buffer.
    void write_tickets(Buffer &buffer, uint32_t reservation_id) {
        tickets[reservation_id].second = true;
        std::vector<std::string> cur_tickets = tickets[reservation_id].first;

        for (auto &ticket : cur_tickets) {
            buffer.write_str(ticket, ticket.size());
        }
    }
    
    void reservation_response(GetReservation &query, Buffer &buffer) {
        uint64_t exp_time = get_expiration_time();

        uint32_t ev_id = query.get_event_id();
        uint16_t ticket_count = query.get_ticket_count();

        if (debug) {
            printf("[SERVER] Received GET_RESERVATION event_id=%d ticket_count=%d. Writing response...\n",
                   ev_id, ticket_count);
        }

        if (events_info.count(ev_id) == 0
            || ticket_count == 0
            || events_info[ev_id].second < ticket_count
            || 1 + 4 + 2 + ticket_count * TICKET_LEN > DATAGRAM_CAPACITY) {

            bad_request_response(buffer, ev_id);

            if (debug) {
                printf("[SERVER] Written response: BAD_REQUEST event_id=%d.\n", ev_id);
            }
            return;
        }

        uint32_t res_id = cur_reservation_id++;
        buffer.write_primitive<uint8_t>(RESERVATION_ID);
        buffer.write_primitive<uint32_t>(htonl(res_id));
        buffer.write_primitive<uint32_t>(htonl(ev_id));
        buffer.write_primitive<uint16_t>(htons(ticket_count));
        
        char cookie[COOKIE_LEN + 1];
        gen_cookie(cookie);

        buffer.write_cstr(cookie, COOKIE_LEN);
        buffer.write_primitive<uint64_t>(htobe64(exp_time));

        if (debug) {
            printf("[SERVER] Written response: RESERVATION reservation_id=%d event_id=%d "
                   "ticket_count=%d <cookie> expiration_time=%lu.\n", res_id, ev_id, ticket_count, exp_time);
        }

        reservation_update_db(ev_id, res_id, ticket_count, cookie, exp_time);
    }
    
    void tickets_response(GetTickets &query, Buffer &buffer) {

        uint32_t res_id = query.get_reservation_id();

        // Conversion from char* to std::string works fine since query.get_cookie() is null-terminated.
        std::string cookie = query.get_cookie();

        if (debug) {
            printf("[SERVER] Received GET_TICKETS reservation_id=%d <cookie>. Writing response...\n", res_id);
        }

        if (reservations.count(res_id) == 0
            || cookie != authentication[res_id]) {

            bad_request_response(buffer, res_id);

            if (debug) {
                printf("[SERVER] Written response: BAD_REQUEST reservation_id=%d.\n", res_id);
            }
            return;
        }

        uint16_t ticket_count = reservations[res_id].second;

        buffer.write_primitive<uint8_t>(TICKETS_ID);
        buffer.write_primitive<uint32_t>(htonl(res_id));
        buffer.write_primitive<uint16_t>(htons(ticket_count));
        write_tickets(buffer, res_id);

        if (debug) {
            printf("[SERVER] Written response: TICKETS reservation_id=%d ticket_count=%d <tikets>.\n",
                   res_id, ticket_count);
        }
    }

    void remove_reservation_info(uint32_t res_id) {
        auto it = reservations.find(res_id);
        if (it != reservations.end()) {
            uint32_t ev_id = it->second.first;
            uint16_t ticket_count = it->second.second;
            events_info[ev_id].second += ticket_count;
            reservations.erase(it);
        }

        authentication.erase(res_id);
        std::vector<std::string> &tickets_rem = tickets[res_id].first;
        for (auto &ticket : tickets_rem) {
            used_tickets.erase(ticket);
        }
        tickets.erase(res_id);
    }

public:

    ServerDatabase(uint32_t _timeout, std::string _filename)
            : timeout(_timeout), filename(std::move(_filename)) {};

    void process_events_file() {

        std::ifstream events_file(filename);

        if (!events_file.is_open()) {
            fatal("Non-existent file.\n");
        }

        std::string event_name;
        uint16_t ticket_count;

        while (!events_file.eof()) {
            std::getline(events_file, event_name);
            events_file >> ticket_count;
            events_file.ignore(80, '\n');

            if (events_file.good()) {
                add_event({event_name, ticket_count});
            }
        }
        events_file.close();
    }

    void construct_response(QueryVariant query, Buffer &buffer) {
        buffer.reset();
        
        if (std::holds_alternative<GetEvents>(query)) {
            events_response(buffer);
        }
        else if (std::holds_alternative<GetReservation>(query)) {
            reservation_response(std::get<GetReservation>(query), buffer);
        }
        else {
            tickets_response(std::get<GetTickets>(query), buffer);
        }
    }

    void check_if_expired() {
        time_t current = time(nullptr);

        while (!expiration_times.empty() && expiration_times.top().first <= current) {
            expiration_t exp = expiration_times.top();
            expiration_times.pop();

            uint32_t res_id = exp.second;

            if (!tickets[res_id].second) {
                if(debug) {
                    printf("[SERVER] Reservation id=%d expired. Tickets were not collected."
                           "Returning tickets to the pool...", exp.second);
                }
                remove_reservation_info(res_id);
            }
        }
    }
};

// Wrapper class for socket.
class Socket {
private:
    int socket_fd;
    int flags;
    struct sockaddr_in cur_client_address;

    void bind_socket(uint16_t port) {
        socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (socket_fd <= 0)
            fatal("socket");

        struct sockaddr_in server_address {};
        server_address.sin_family = AF_INET;
        server_address.sin_addr.s_addr = htonl(INADDR_ANY);
        server_address.sin_port = htons(port);

        errno = 0;
        int err = bind(socket_fd, (struct sockaddr *) &server_address, (socklen_t) sizeof(server_address));

        if (errno != 0 || err != 0)
            fatal("bind");
    }

public:
    Socket(uint16_t port, int flags_) {
        bind_socket(port);
        flags = flags_;
    }

    ~Socket() {
        close(socket_fd);
    }

    void read_message(Buffer &buffer) {
        auto address_length = (socklen_t) sizeof(cur_client_address);
        errno = 0;

        ssize_t len = recvfrom(socket_fd, buffer.get_content(), DATAGRAM_CAPACITY, flags,
                               (struct sockaddr *) &cur_client_address, &address_length);

        if (len < 0)
            fatal("recvfrom");

        if(debug) {
            printf("[SERVER] Received %lu bytes from client %s:%d.\n",
                   len, inet_ntoa(cur_client_address.sin_addr), cur_client_address.sin_port);
        }

        buffer.set_len(len);
    }

    [[maybe_unused]] void ignore_message_log() const {
        if(debug) {
            printf("[SERVER] Client %s:%d sent incorrect message. Ignoring...",
                   inet_ntoa(cur_client_address.sin_addr), cur_client_address.sin_port);
        }
    }

    void write_message(Buffer &buffer) {
        auto address_length = (socklen_t) sizeof(cur_client_address);
        ssize_t sent_length = sendto(socket_fd, buffer.get_content(), buffer.get_len(), flags,
                                     (struct sockaddr *) &cur_client_address, address_length);

        if (sent_length != (ssize_t) buffer.get_len())
            fatal("sendto");

        if (debug) {
            printf("[SERVER] Sent %lu bytes to client %s:%d.\n",
                   sent_length, inet_ntoa(cur_client_address.sin_addr), cur_client_address.sin_port);
        }
    }
};

int main(int argc, char **argv) {
    std::string filename;
    uint16_t port;
    uint32_t timeout;

    Parser::parse_arguments(argc, argv, filename, port, timeout);

    ServerDatabase server_db(timeout, filename);
    server_db.process_events_file();

    Socket socket_handler(port, 0);
    Buffer buffer;

    for(;;) {
        socket_handler.read_message(buffer);
        server_db.check_if_expired();
        std::optional<QueryVariant> query = Parser::parse_query(buffer);
        if (query) {
            server_db.construct_response(query.value(), buffer);
            socket_handler.write_message(buffer);
        }
        else if (debug) {
            socket_handler.ignore_message_log();
        }
    }
}
