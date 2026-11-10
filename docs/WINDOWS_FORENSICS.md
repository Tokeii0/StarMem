# Windows 内存取证

以下 PowerShell 示例沿用 [README 的快速开始](../README.md#快速开始) 中的 `$starmem` 和 `$windowsImage`。符号根可以用 `--symbol-path` 按命令指定，也可以在当前终端统一配置。

```powershell
$env:STARMEM_SYMBOL_PATH = $windowsSymbols
```

## 建立系统和进程基线

```powershell
& $starmem --json system-info $windowsImage
& $starmem --json acquisition-info $windowsImage
& $starmem pstree $windowsImage
& $starmem check-pslist $windowsImage
& $starmem psxview $windowsImage
```

- `system-info` 分别保留内核版本、注册表版本、安装时间、启动时间和关机时间。历史时间的本地显示使用镜像采集时的时区偏差，跨夏令时边界时以 UTC 为准。
- `acquisition-info` 区分容器元数据、镜像时钟与采集工具活动。只有采集工具的 RAM 输出句柄与当前检材文件名一致时才建立活动区间。`--include-host-times` 额外列出分析主机文件时间，供管理检材时参考。
- `psxview` 比较活动链、内存池和线程证据。`check-pslist` 保留 EPROCESS 原有 PPID，以最早活动线程、跨进程句柄及创建权限报告可能的其他创建者或 PPID 欺骗。句柄关闭或初始线程退出会削弱阴性结论。

## 核对进程内存与驱动

```powershell
& $starmem malfind $windowsImage
& $starmem injected-regions $windowsImage --pid 2932
& $starmem vaddump $windowsImage --pid 2932 -o .\vaddump
& $starmem cobaltstrikescan $windowsImage --pid 2932
& $starmem driver-inspect $windowsImage --name '\Driver\Example'
```

将 `2932` 换成已核对的 PID，驱动名换成镜像中的对象名。`injected-regions` 查找声明可写、实际驻留 PTE 为只读的私有已提交 VAD，可用 `--include-executable` 同时检查可执行区域。默认只报告完全驻留的候选。`--include-partial` 可纳入缺页候选，并保留 `pages_missing`。保护位差异是异常线索，需要结合区段字节和其他进程证据判断。

`vaddump` 按虚拟地址范围命名导出。含缺页的区段发布为 `.dmp.partial`，布局中的零填充不计入 `recovered_bytes`，缺口记入 `missing_ranges`。`cobaltstrikescan` 验证 Beacon TLV 配置并保留 VAD 地址、配置哈希和重复副本地址。`driver-inspect` 的模块归属来自镜像里的活动模块，磁盘文件和签名需要独立检材核对。

## 定位文件、进程归属与网络端点

```powershell
& $starmem filescan $windowsImage --csv .\files.csv
& $starmem --json windows.open-files $windowsImage --path-contains 'Chrome\User Data\Default\History'
& $starmem --json windows.process-string $windowsImage --text "要查找的文本" --encoding both
& $starmem netscan $windowsImage
& $starmem pipescan $windowsImage
& $starmem packetscan $windowsImage -o .\recovered.pcapng
```

- `windows.open-files` 将驻留 `FILE_OBJECT` 与活动句柄相连。已知对象地址时，可用 `handles --object <地址>` 反查。活动句柄只能证明采集时的对象持有关系。
- `windows.process-string` 在已采集的物理区间搜索字节，再用页表和虚拟地址回读验证活动进程归属。共享页可有多个已验证的进程或虚拟地址。跨不连续物理页的命中、换出页、隐藏或已退出进程均在该搜索范围之外。
- `netscan` 验证 TCP/UDP 池对象，无法核对的地址或进程归属保留为未知。`pipescan` 通过 NPFS 设备链和活动句柄区分正在使用的端点与池对象残留。
- `packetscan` 恢复有边界校验的实际 IP 包，按字节哈希去重。PID 与方向来自端点关联，时间戳不可验证时在 PCAPNG 中写零并加注释。

## 恢复驻留文件

```powershell
# 把示例地址替换成 filescan 返回的 FILE_OBJECT 虚拟地址
$fileObject = "0xfffffa801a6cedd0"
& $starmem --json dumpfile $windowsImage --address $fileObject --source auto -o .\recovered.bin

# 把示例地址替换成 mftscan 返回的 MFT 记录物理地址
& $starmem mftscan $windowsImage --csv .\mft.csv
$mftAddress = "0x100000"
& $starmem --json mftdump $windowsImage --address $mftAddress -o .\resident.bin
```

`dumpfile` 可从 Cache、Data 或 Image 恢复，`--source auto` 会按可用证据选择来源。检查报告中的实际来源、逻辑大小、恢复字节和缺页。`mftdump` 只能导出记录中完整驻留的 `$DATA`。备用数据流用 `--stream <名称>` 或 `--attribute-id <ID>` 定位。

```powershell
& $starmem --json sqlite-recover $windowsImage --path-contains 'Chrome\User Data\Default\History' --output-dir .\history
```

`sqlite-recover` 独立恢复主库及 `-wal`、`-shm`、`-journal`，保留每个文件的缺页清单和哈希。主库不完整时使用 `.partial.sqlite`。默认表检查只读恢复出的主库，sidecar 单独保存且不会自动回放。匹配路径不唯一时，改用核对过的 `--file-object`。

## 重建执行、日志与交互活动

```powershell
& $starmem windows.execution $windowsImage --exact-only --csv .\execution.csv
& $starmem windows.timeline $windowsImage --source process,thread --pid 2932
& $starmem windows.recent-files $windowsImage --source wps
& $starmem usb-history $windowsImage --strict-last-arrival
& $starmem dump-logs $windowsImage -o .\logs
& $starmem terminal-history $windowsImage
& $starmem --json browser-history $windowsImage --view visits --owners
& $starmem --json browser-session $windowsImage
& $starmem clipboardscan $windowsImage
```

| 证据 | 阅读要点 |
| --- | --- |
| 程序执行 | `windows.execution --exact-only` 保留 Prefetch、BAM/DAM 和 UserAssist 提供的直接执行时间。Shimcache 的文件修改时间、Amcache 的键写入时间属于上下文。`--aggregate` 聚合同一活动的证据，仍保留原始事件。 |
| 内存时间线 | `windows.timeline` 区分进程、线程、MFT 与注册表各自的时间语义。MFT 的 `$STANDARD_INFORMATION` 与 `$FILE_NAME` 分别保留。`--pid` 只筛选有 PID 的进程或线程事件。恢复的 EVTX 等日志可单独交给 `event-timeline`。 |
| 最近文件与 USB | WPS 逐文件时间与注册表容器键的 LastWrite 分开。Explorer RecentDocs 的 MRU 表示顺序。`usb-history` 按 ContainerID 聚合接口，`--strict-last-arrival` 仅采用显式 `LastArrivalDate`。 |
| 控制台与剪贴板 | `terminal-history` 结合 conhost/OpenConsole 结构与驻留 PSReadLine 文件。`clipboardscan` 使用 Window Station、格式数组与数据句柄恢复活动剪贴板。`residualscan` 单独报告文本残留，归属进程的文本仍需结构证据才能关联剪贴板。 |
| 浏览器 | `browser-history` 区分 URL 累计次数、恢复到的逐次访问和源数据库完整性。采集时的数据库句柄 owner 只证明打开关系。`browser-session` 关联配置目录、Cookie、下载和登录站点等驻留证据。`cookiescan` 会显式标记 Chromium 密文。 |
| GUI 与桌面 | `gui-windows` 和 `windowtitles` 依赖现场 GUI 对象关系。`desktop-reconstruct` 依赖驻留图形数据，可恢复的显示帧范围取决于实际采集页面。 |

持久化可以用 `svcdiff`、`scheduled-tasks` 和 `autoruns` 排查。`accountscan` 报告账号操作痕迹，`hashdump` 从驻留 SYSTEM/SAM Hive 恢复密码哈希。`wechatscan` 输出微信数据库密钥候选，`--verify-db-root` 可用相应数据库复核。

- [验证方法与覆盖范围](VALIDATION.md)
