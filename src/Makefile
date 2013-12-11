# Copyright (c) 2013 Tieto Global Oy
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
# 		http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

include $(RTE_SDK)/mk/rte.vars.mk

APP = edpdk

IDIR = /usr/local/lib/erlang/lib/erl_interface-3.7.14/include/

LDLIBS += -L /usr/local/lib/erlang/lib/erl_interface-3.7.14/lib/ -lei

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(IDIR)
CFLAGS += -g

SRCS-y += edpdk.c
SRCS-y += pmdengine.c

include $(RTE_SDK)/mk/rte.extapp.mk
