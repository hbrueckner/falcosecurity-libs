/*
Copyright (C) 2022 The Falco Authors.

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

void set_syscall_of_interest(uint32_t ppm_sc, bool *syscalls_of_interest, bool enable);
void fill_syscalls_of_interest(interesting_ppm_sc_set *ppm_sc_of_interest, bool *syscalls_of_interest);
int32_t check_api_compatibility(scap_t *handle, char *error);
