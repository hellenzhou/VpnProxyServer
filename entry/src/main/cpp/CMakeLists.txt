# Copyright (c) 2021 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.



cmake_minimum_required(VERSION 3.5.1)

project(VPNServer)

set(NATIVERENDER_ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR})

include_directories(
  ${NATIVERENDER_ROOT_PATH}
)

add_library(vpn_server SHARED 
    vpn_server.cpp
    protocol_handler.cpp
    packet_forwarder.cpp
    packet_builder.cpp
    nat_table.cpp
    network_diagnostics.cpp
    task_queue.cpp
    udp_retransmit.cpp
    worker_thread_pool.cpp
    thread_pool.cpp  # 🔄 添加线程池实现
)

target_link_libraries(vpn_server PUBLIC libace_napi.z.so libc++.a)
target_link_libraries(vpn_server PUBLIC libhilog_ndk.z.so)
