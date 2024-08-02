# tiny_http_server

Tiny HTTP server, solution to a problem from codecrafters.  
The server supports several endpoints:  
`GET /echo/<your text>` - server will respond with the text following after /echo/, if request contains header Accept-Encoding: gzip, then response will encode gzip,  
`GET /user-agent` - response will contain your user-agent,  
`GET /file/<file name>`  - server will send file as octet-stream,  
`POST /file/<file name>` - server will create new file with payload from reqest body, if it is not exist  

Build
```
mkdir build
cd build
cmake -B build -S . -DCMAKE_TOOLCHAIN_FILE=${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake
cmake --build ./build
```

To run
```
./server --directory <root dir for>
```  
Environment:
`g++ (Debian 12.2.0-14) 12.2.0`
`cmake version 3.25.1`