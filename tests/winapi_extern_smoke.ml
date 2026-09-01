/*
   Copyright 2026 Nils Kopal

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

package winapi_extern_smoke
// Minimal module for regression tests of:
// - import-as alias resolution
// - namespaced extern calls (alias.MemberCall)

// Windows DLL identity is case-insensitive; label generation must match the
// normalized import-table key even when source spelling uses uppercase.
extern function GetTickCount() from "KERNEL32.DLL" returns u32

