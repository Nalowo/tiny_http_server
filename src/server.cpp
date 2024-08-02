#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <zlib.h>

#include <memory>
#include <unordered_map>
#include <functional>
#include <optional>
#include <thread>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <filesystem>
#include <fstream>
#include <algorithm>

using namespace std::literals;

class HttpRqNode
{
public:
    enum class Method : char
    {
        Unknown,
        GET,
        POST
    };

    HttpRqNode(std::string &&rqBody)
        : _reqestBody(std::move(rqBody))
    {
        std::string_view rq = _reqestBody;
        if (auto it = _methods.find(ParseMethod(rq)); it != _methods.end())
        {
            _method = it->second;
        }
        else
            _method = Method::Unknown;

        _url = ParseUrl(rq);
        _httpType = ParseHttpType(rq);

        ParseHeader(rq);
        ParsePayload(rq);
    }

    std::string_view GetUrl() const noexcept
    {
        return _url;
    }

    Method GetMethod() const noexcept
    {
        return _method;
    }

    std::string_view GetHttpType() const noexcept
    {
        return _httpType;
    }

    const std::vector<std::string_view> *GetHeader(std::string_view key) const
    {
        if (auto it = _headers.find(key); it != _headers.end())
            return &it->second;
        return nullptr;
    }

    std::string_view GetPayload() const
    {
        return _payLoad;
    }

private:
    std::string_view ParseHttpType(std::string_view &rq)
    {
        auto pos = rq.find('\r');
        std::string_view rez = rq.substr(0, pos);
        rq = rq.substr(pos + 1);
        return rez;
    }
    std::string_view ParseUrl(std::string_view &rq)
    {
        auto pos = rq.find(' ');
        std::string_view rez = rq.substr(0, pos);
        rq = rq.substr(pos + 1);
        return rez;
    }

    std::string_view ParseMethod(std::string_view &rq)
    {
        auto pos = rq.find(' ');
        std::string_view rez = rq.substr(0, pos);
        rq = rq.substr(pos + 1);
        return rez;
    }

    void ParseHeader(std::string_view &rq)
    {
        while (!rq.empty())
        {
            std::string_view header;

            auto startPos = rq.find_first_not_of("\r\n ");
            auto endPos = rq.find_first_of(':', startPos);
            if (startPos == std::string_view::npos || endPos == std::string_view::npos)
                break;

            header = rq.substr(startPos, endPos - startPos);
            rq = rq.substr(endPos + 1, rq.size() - 1);

            std::vector<std::string_view> values;
            startPos = rq.find_first_not_of("\r\n ");
            endPos = rq.find_first_of("\r\n", startPos);
            std::string_view subStrProc = rq.substr(startPos, endPos - startPos);
            rq = rq.substr(subStrProc.size() + 2, rq.size() - 1);

            endPos = subStrProc.find_first_of(',');
            do
            {
                startPos = subStrProc.find_first_not_of("\r\n ");
                endPos = subStrProc.find_first_of(',');
                values.push_back(subStrProc.substr(startPos, endPos - startPos));
                subStrProc = subStrProc.substr(endPos + 1, subStrProc.size() - 1);
            } while (endPos != std::string_view::npos);

            _headers.emplace(header, std::move(values));
        }
    }

    void ParsePayload(std::string_view &rq)
    {
        size_t contectLength = 0;
        if (auto it = _headers.find("Content-Length"); it != _headers.end())
        {
            contectLength = std::stoi(std::string(it->second[0]));
            rq = rq.substr(rq.find_last_of("\r\n\r\n") + 1, rq.size() - 1);
            _payLoad = rq.substr(0, contectLength);
        }
    }

    static const std::unordered_map<std::string_view, Method> _methods;
    std::unordered_map<std::string_view, std::vector<std::string_view>> _headers;
    std::string _reqestBody;
    std::string_view _httpType;
    std::string_view _url;
    std::string_view _payLoad;
    Method _method;
}; // end struct HttpRqNode

const std::unordered_map<std::string_view, HttpRqNode::Method> HttpRqNode::_methods = {
    {"GET"sv, HttpRqNode::Method::GET},
    {"POST"sv, HttpRqNode::Method::POST}};

class HttpHandler
{
public:
    using HandlerFunc = std::function<std::string(HttpRqNode)>;

    HttpHandler(std::string rootDir)
    {

        _endpoints["/"sv] = [this](HttpRqNode &&rq) -> std::string
        {
            return "HTTP/1.1 200 OK\r\n\r\n";
        };
        _endpoints["/echo"sv] = std::bind(&HttpHandler::HandleEcho, this, std::placeholders::_1);
        _endpoints["/user-agent"sv] = std::bind(&HttpHandler::HandleUserAgent, this, std::placeholders::_1);

        if (!rootDir.empty())
        {
            SetRootDirectory(std::move(rootDir));
            _endpoints["/files"sv] = std::bind(&HttpHandler::HandleFileReqest, this, std::placeholders::_1);
        }
    }

    std::string ParseRequest(std::string &&rqBody) const
    {
        HttpRqNode node(std::move(rqBody));
        std::string_view endpoint;
        endpoint = node.GetUrl().substr(0, node.GetUrl().find_first_of('/', 1));

        if (auto it = _endpoints.find(endpoint); it != _endpoints.end())
        {
            return it->second(std::move(node));
        }
        else
        {
            return std::string("HTTP/1.1 404 Not Found\r\n\r\n");
        }
    }

private:
    std::vector<uint8_t> compressData(std::string_view data) const
    {
        uLongf compressedSize = compressBound(data.size());
        std::vector<uint8_t> compressedData(compressedSize);

        int res = compress(compressedData.data(), &compressedSize, reinterpret_cast<const Bytef *>(data.data()), data.size());
        if (res != Z_OK)
        {
            return std::vector<uint8_t>();
        }

        compressedData.resize(compressedSize);
        return compressedData;
    }

    std::string decompressData(const std::vector<uint8_t> &compressedData, size_t originalSize) const
    {
        std::vector<uint8_t> decompressedData(originalSize);

        int res = uncompress(decompressedData.data(), &originalSize, compressedData.data(), compressedData.size());
        if (res != Z_OK)
        {
            return std::string();
        }

        return std::string(decompressedData.begin(), decompressedData.end());
    }

    std::string gzip_compress(std::string_view data) const
    {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));
        if (deflateInit2(&zs, Z_BEST_COMPRESSION, Z_DEFLATED, 15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK)
        {
            return std::string{};
        }
        zs.next_in = (Bytef *)data.data();
        zs.avail_in = data.size();
        int ret;
        char outbuffer[32768];
        std::string outstring;
        do
        {
            zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
            zs.avail_out = sizeof(outbuffer);
            ret = deflate(&zs, Z_FINISH);
            if (outstring.size() < zs.total_out)
            {
                outstring.append(outbuffer, zs.total_out - outstring.size());
            }
        } while (ret == Z_OK);
        deflateEnd(&zs);
        if (ret != Z_STREAM_END)
        {
            return std::string{};
        }
        return outstring;
    }

    std::string gzip_decompress(const std::string &compressedData) const
    {
        z_stream zs;
        memset(&zs, 0, sizeof(zs));

        if (inflateInit2(&zs, 15 + 16) != Z_OK)
        {
            return std::string{};
        }

        zs.next_in = (Bytef *)compressedData.data();
        zs.avail_in = compressedData.size();

        int ret;
        char outbuffer[32768];
        std::string outstring;

        do
        {
            zs.next_out = reinterpret_cast<Bytef *>(outbuffer);
            zs.avail_out = sizeof(outbuffer);

            ret = inflate(&zs, 0);

            if (outstring.size() < zs.total_out)
            {
                outstring.append(outbuffer, zs.total_out - outstring.size());
            }
        } while (ret == Z_OK);

        inflateEnd(&zs);

        if (ret != Z_STREAM_END)
        {
            return std::string{};
        }

        return outstring;
    }

    void SetRootDirectory(const std::filesystem::path &root_path)
    {
        auto path = std::filesystem::absolute(std::filesystem::canonical(root_path));
        if (!std::filesystem::exists(path))
        {
            throw std::invalid_argument("The root path does not exist.");
        }
        if (!std::filesystem::is_directory(path))
        {
            throw std::invalid_argument("The root path is not a directory.");
        }
        _root = path;
    }

    std::string HandleEcho(HttpRqNode rq) const
    {
        std::string_view url = rq.GetUrl().substr(rq.GetUrl().find_first_of('/', 1));
        std::string out;
        out = "HTTP/1.1 200 OK\r\n";
        out += "Content-Type: text/plain\r\n";

        std::string_view resp;
        resp = url.substr(1, url.size() - 1);

        if (auto *eq = rq.GetHeader("Accept-Encoding"); eq != nullptr && FindEncodingMetgod(eq))
        {
            out += "Content-Encoding: gzip\r\n";
            std::string compressed = gzip_compress(resp);
            out += "Content-Length: " + std::to_string(compressed.size()) + "\r\n\r\n";
            out += std::move(compressed);
        }
        else
        {
            out += "Content-Length: " + std::to_string(resp.size()) + "\r\n\r\n";
            out += std::string(resp);
        }

        return out;
    }

    std::string HandleUserAgent(HttpRqNode rq) const
    {
        auto *userAgent = rq.GetHeader("User-Agent");
        if (!userAgent)
        {
            return std::string("HTTP/1.1 404 Not Found\r\n\r\n");
        }

        std::string out;
        out = "HTTP/1.1 200 OK\r\n";
        out += "Content-Type: text/plain\r\n";
        out += "Content-Length: " + std::to_string(((*userAgent)[0]).size()) + "\r\n\r\n";
        out += std::string((*userAgent)[0]);

        return out;
    }

    std::string HandleFileReqest(HttpRqNode rq) const
    {
        std::string out;

        if (rq.GetMethod() == HttpRqNode::Method::GET)
        {
            out = HandleReadFile(rq);
        }
        else if (rq.GetMethod() == HttpRqNode::Method::POST)
        {
            if (auto *eq = rq.GetHeader("Content-Type"); (*eq)[0] == "application/octet-stream")
            {
                out = HandleCreateFile(rq);
            }
            else
            {
                out = "HTTP/1.1 400 Bad Request\r\n\r\n";
            }
        }

        return out;
    }

    std::string HandleReadFile(HttpRqNode rq) const
    {
        std::string out;
        std::string_view fileName = rq.GetUrl().substr(rq.GetUrl().find_first_of('/', 1) + 1);
        std::filesystem::path full_path = _root / fileName;

        if (FileCheck(full_path))
        {
            if (auto content = ReadFile(full_path); content)
            {
                out = "HTTP/1.1 200 OK\r\n";
                out += "Content-Type: application/octet-stream\r\n";
                out += "Content-Length: " + std::to_string(content->size()) + "\r\n\r\n";
                out += std::string(*content);
                return out;
            }
        }

        out = "HTTP/1.1 404 Not Found\r\n\r\n";
        return out;
    }

    std::string HandleCreateFile(HttpRqNode rq) const
    {
        std::string out;
        std::string_view fileName = rq.GetUrl().substr(rq.GetUrl().find_first_of('/', 1) + 1);
        std::filesystem::path fullPath = _root / fileName;

        std::ofstream outFile(fullPath);
        if (outFile.is_open())
        {
            outFile << rq.GetPayload();
            outFile.close();
            out = "HTTP/1.1 201 Created\r\n\r\n";
        }
        else
        {
            out = "HTTP/1.1 400 Bad Request\r\n\r\n";
        }
        return out;
    }

    bool FileCheck(const std::filesystem::path &fileName) const
    {
        return std::filesystem::exists(fileName) && std::filesystem::is_regular_file(fileName);
    }

    bool FindEncodingMetgod(const std::vector<std::string_view> *vec) const
    {
        if (vec)
        {
            for (auto &v : *vec)
            {
                if (v == "gzip")
                {
                    return true;
                }
            }
        }

        return false;
    }

    std::optional<std::string> ReadFile(const std::filesystem::path &fileName) const
    {
        std::string out;

        std::ifstream file(fileName, std::ios::binary);
        if (!file.is_open())
        {
            return std::nullopt;
        }

        out = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        return out;
    }

    std::filesystem::path _root;
    std::unordered_map<std::string_view, HandlerFunc> _endpoints;
}; // end class HttpHandler

class ThreadPool
{
public:
    ThreadPool(size_t numThreads)
    {
        start(numThreads);
    }

    ~ThreadPool()
    {
        stop();
    }

    template <class T>
    void enqueue(T task)
    {
        {
            std::unique_lock<std::mutex> lock{mEventMutex};
            mTasks.emplace(std::move(task));
        }

        mEventVar.notify_one();
    }

private:
    std::vector<std::thread> mThreads;
    std::condition_variable mEventVar;
    std::mutex mEventMutex;
    bool mStopping = false;

    std::queue<std::function<void()>> mTasks;

    void start(size_t numThreads)
    {
        for (size_t i = 0; i < numThreads; ++i)
        {
            mThreads.emplace_back([this]
                                  {
                while (true)
                {
                    std::function<void()> task;

                    {
                        std::unique_lock<std::mutex> lock{mEventMutex};

                        mEventVar.wait(lock, [this] { return mStopping || !mTasks.empty(); });

                        if (mStopping && mTasks.empty())
                            break;

                        task = std::move(mTasks.front());
                        mTasks.pop();
                    }

                    task();
                } });
        }
    }

    void stop() noexcept
    {
        {
            std::unique_lock<std::mutex> lock{mEventMutex};
            mStopping = true;
        }

        mEventVar.notify_all();

        for (auto &thread : mThreads)
            thread.join();
    }
};

void HandleClient(int client_socket, const HttpHandler &handler)
{
    std::string st;
    st.resize(1024, '\0');

    int readRez = read(client_socket, st.data(), st.size());
    if (readRez <= 0)
    {
        close(client_socket);
        return;
    }

    std::string response = handler.ParseRequest(std::move(st));

    if (send(client_socket, response.c_str(), response.size(), 0) < 0)
    {
        close(client_socket);
        return;
    }

    // Close the connection socket after sending the response
    close(client_socket);
}

struct Args
{
    Args(int argc, char **argv) : _argc(argc)
    {
        for (int i = 1; i < argc; ++i)
        {
            env[argv[i]] = argv[i + 1];
            ++i;
        }
    }

    bool Check(const std::string &key) const
    {
        return env.find(key) != env.end();
    }

    std::string operator[](const std::string &key) const
    {
        if (auto it = env.find(key); it != env.end())
            return it->second;
        else
            throw std::runtime_error(" No such key, " + key + " env count is " + std::to_string(env.size()));
    }

private:
    int _argc = 0;
    std::unordered_map<std::string, std::string> env;
}; // end struct Args

int main(int argc, char **argv)
{
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    Args args(argc, argv);

    const unsigned num_threads = std::thread::hardware_concurrency();
    ThreadPool pool(num_threads);

    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0)
    {
        std::cerr << "Failed to create server socket\n";
        return 1;
    }

    // Since the tester restarts your program quite often, setting SO_REUSEADDR
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        std::cerr << "setsockopt failed\n";
        close(server_fd);
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(4221);

    if (bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) != 0)
    {
        std::cerr << "Failed to bind to port 4221\n";
        close(server_fd);
        return 1;
    }

    int connection_backlog = 5;
    if (listen(server_fd, connection_backlog) != 0)
    {
        std::cerr << "listen failed\n";
        close(server_fd);
        return 1;
    }

    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);

    HttpHandler handler(args.Check("--directory") ? args["--directory"] : ""s);

    while (true)
    {
        int client_socket = accept(server_fd, (struct sockaddr *)&client_addr, &client_addr_len);
        if (client_socket < 0)
        {
            std::cerr << "Failed to accept connection\n";
            continue;
        }

        pool.enqueue([client_socket, &handler]
                     { HandleClient(client_socket, handler); });
    }

    // Close the server socket
    close(server_fd);

    return 0;
}
