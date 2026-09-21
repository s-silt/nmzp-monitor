# WFP 常数来源（Windows SDK 10.0.22621.0）

不猜 GUID/offset。本机头文件：

- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/fwpmu.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/fwptypes.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/fwpmtypes.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/um/networkisolation.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/rpcdce.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/ws2def.h`
- `C:/Program Files (x86)/Windows Kits/10/Include/10.0.22621.0/shared/winerror.h`

摘录：

| 符号 | 值 |
|---|---|
| FWPM_LAYER_ALE_AUTH_CONNECT_V4 | c38d57d1-05a7-4c33-904f-7fbceee60e82 |
| FWPM_LAYER_ALE_AUTH_CONNECT_V6 | 4a72393b-319f-44bc-84c3-ba54dcb3b6b4 |
| FWPM_CONDITION_ALE_PACKAGE_ID | 71bc78fa-f17c-4997-a602-6abb261f351c |
| FWPM_CONDITION_IP_REMOTE_ADDRESS | b235ae9a-1d64-49b8-a44c-5ff3d9095045 |
| FWPM_CONDITION_IP_PROTOCOL | 3971ef2b-623e-4f9a-8cb1-6e79b806b9a7 |
| FWPM_CONDITION_IP_REMOTE_PORT | c35a604d-d22b-4e1a-91b4-68f674ee674b |
| FWP_ACTION_BLOCK | 0x00001001 |
| FWP_ACTION_PERMIT | 0x00001002 |
| FWPM_FILTER_FLAG_PERSISTENT | 0x1 |
| FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT | 0x8 |
| FWPM_SESSION_FLAG_DYNAMIC | 0x1（本 helper 不置位） |
| RPC_C_AUTHN_WINNT | 10 |
| IPPROTO_TCP | 6 |
| FWP_E_ALREADY_EXISTS | 0x80320009 |

Filter arbitration: https://learn.microsoft.com/en-us/windows/win32/fwp/filter-arbitration  
默认 filter permit = soft permit；filter block = hard block。本 allow 不置 `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`。

NetworkIsolationGetAppContainerConfig 返回的 SID 数组按官方 sample 用 `HeapFree(GetProcessHeap())` 释放 SID 与数组。该 API 写的是整表，不是 CAS。
