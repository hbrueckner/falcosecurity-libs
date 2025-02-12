// SPDX-License-Identifier: Apache-2.0
/*
Copyright (C) 2023 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#pragma once

#include "sinsp_filtercheck.h"

class sinsp_filter_check_syslog : public sinsp_filter_check
{
public:
	enum check_type
	{
		TYPE_FACILITY_STR = 0,
		TYPE_FACILITY,
		TYPE_SEVERITY_STR,
		TYPE_SEVERITY,
		TYPE_MESSAGE,
	};

	sinsp_filter_check_syslog();

	sinsp_filter_check* allocate_new() override;
	uint8_t* extract(sinsp_evt*, OUT uint32_t* len, bool sanitize_strings = true) override;

	uint32_t m_storageu32;
	std::string m_name;
};
