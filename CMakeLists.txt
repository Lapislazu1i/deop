cmake_minimum_required(VERSION 3.9)


project(opde)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
 
#设定编译参数
# set(CMAKE_BUILD_TYPE "Debug")
 


#设定所有源码列表 ：aux_source_directory(<dir> <variable>)
#比如:aux_source_directory(${CMAKE_SOURCE_DIR} DIR)  将${CMAKE_SOURCE_DIR}目录下，也就是最顶级目录下所有的.cpp文件放入DIR变量中，后面的add_executable就可以很简化
#    add_executable(hello_world ${DIR})
 
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
  include_directories(${OPENSSL_INCLUDE_DIRS})
  message(STATUS "OpenSSL Found!")
endif()
 
#设定头文件路径
#include_directories(./vender/include)
#include_directories("路径1"  “路径2”...)
 
 
#设定链接库的路径（一般使用第三方非系统目录下的库）
#link_directories(./vender/lib)
#link_directories(./vender/lib)
#link_directories("路径1"  “路径2”...)
 
 
#添加子目录,作用相当于进入子目录里面，展开子目录的CMakeLists.txt
#同时执行，子目录中的CMakeLists.txt一般是编译成一个库，作为一个模块
#在父目录中可以直接引用子目录生成的库
#add_subdirectory(math)
 #设定源码列表.
aux_source_directory(. SRC_FILES)
 
#生成动/静态库
#add_library(动/静态链接库名称  SHARED/STATIC(可选，默认STATIC)  源码列表)
#可以单独生成多个模块
 
#add_library(dnassl  SHARED  ${SRC_FILES} ${SRC_CERT_FILES})
#生成可执行文件
add_executable(opde ${SRC_FILES} )
#比如：add_executable(hello_world    ${SOURCE_FILES})
 
 
target_link_libraries(opde
pthread
OpenSSL::Crypto
OpenSSL::SSL
dl)#就是g++ 编译选项中-l后的内容，不要有多余空格
