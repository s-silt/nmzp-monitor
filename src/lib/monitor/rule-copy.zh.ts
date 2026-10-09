import type { RuleCopy } from "./rule-copy.ts";

export const RULE_COPY_ZH = {
  families: {
    exfil: {
      name: "数据外传",
      summary: "项目、截图或剪切板内容被送出本机时，上传过程往往不出现在对话里。",
    },
    secret: {
      name: "凭据外送",
      summary: "密钥文件被送出时，界面往往只剩一条命令，正文不会展开。",
    },
    tamper: {
      name: "拆防护",
      summary: "改掉或关掉已安装的防护后，检查会停，页面上不一定先报警。",
    },
    isolate: {
      name: "失联",
      summary: "结束进程、停掉服务或切断出网后，看板不再收到新事件。",
    },
    poison: {
      name: "语义投毒",
      summary: "覆盖指令写进规则文件、中转回复或 hook 后，助手会照做，看起来不像告警。",
    },
    destructive: {
      name: "破坏性",
      summary: "删盘、清空库或改写提交历史等，命令一执行数据就变了。",
    },
    recon: {
      name: "遥测与画像",
      summary: "会话遥测或时区语言标签随请求送出时，本地界面通常没有提示。",
    },
  },
  protection: {
    locked: {
      name: "始终拦截",
      summary: "始终拦截，不能改成记录或关闭。只记录的客户端上仍然拦截。",
    },
    adjustable: {
      name: "可调",
      summary: "只能选拦截或记录，不能关闭。",
    },
  },
  actions: {
    block: {
      name: "拦截",
      summary: "命中后返回拒绝并记一条审计；是否真正拦住取决于宿主执行拒绝。",
    },
    log: {
      name: "记录",
      summary: "命中后放行这次调用，只在审计里留一条记录。",
    },
  },
  clientMode: {
    follow: {
      name: "跟随全局",
      summary: "这台客户端不单独放宽，拦截或记录与全局策略相同。",
    },
    log_only: {
      name: "只记录",
      summary: "可调规则只记录。锁定规则在这台客户端上仍然拦截。",
    },
  },
  customSets: {
    name: "自定义规则集",
    summary: "自建的隐私词规则，可整组启用，不改内置拦截规则。",
    defaultSetName: "默认",
  },
  subscription: {
    name: "远程订阅",
    summary: "只能新增自定义隐私规则。核心定时拉取，失败时保留上次规则。",
  },
  rules: {
    isolate_cut_board: {
      name: "切断防护出网",
      summary: "防火墙或 hosts 点名本防护时，看板会在没有本地提示时失联。",
    },
    isolate_delete_binary: {
      name: "删除防护程序",
      summary: "删掉已安装的防护程序后，后续检查不再发生，界面未必提示。",
    },
    isolate_kill_monitor: {
      name: "结束防护进程",
      summary: "结束本防护进程后，看板不再收到新事件，看起来只是突然变安静。",
    },
    isolate_stop_container: {
      name: "停止防护服务",
      summary: "停掉本防护的服务或容器后，检查中断，页面上不一定有报错。",
    },
    agent_hook_disable: {
      name: "关闭用户 hook",
      summary: "把 ZCode 的 hook 开关写成关闭后，之后的工具调用不再经过检查。",
    },
    kill_monitor_process: {
      name: "结束监控进程",
      summary: "命令要结束监控探针时，检查先被拆掉，新的审计也不再写入。",
    },
    monitor_self_tamper: {
      name: "改已安装的防护",
      summary: "覆盖已安装的防护文件后，检查会在不提示的情况下停掉。源码目录不算。",
    },
    monitor_self_tamper_cmd: {
      name: "用命令拆防护",
      summary: "用命令改名或删除已安装路径时，防护文件会在后台被换掉。",
    },
    zcode_trust_store_tamper: {
      name: "改 hook 信任记录",
      summary: "直接改写 hook 信任记录后，没审过的 hook 可能被当成已经信任。",
    },
    agent_hook_poison: {
      name: "hook 里的执行链",
      summary: "hook 配置写成下载即执行或向外发送时，它会在工具调用前运行。",
    },
    credential_file_upload: {
      name: "上传凭据文件",
      summary: "把 .env 或私钥当文件上传时，密钥在请求里，页面往往不展示正文。",
    },
    env_piped_outbound: {
      name: "管道送出密钥",
      summary: "把 .env 或密钥文件接到外发命令时，内容离机，界面上看不到正文。",
    },
    clipboard_pipe_upload: {
      name: "剪切板向外发送",
      summary: "助手读到剪切板再外发时，刚复制的内容会离开本机，没有单独提示。",
    },
    screenshot_then_upload: {
      name: "截屏并上传",
      summary: "同一条命令里截屏再上传时，屏幕上的内容会在你确认前送出。",
    },
    screenshot_file_upload: {
      name: "上传截图文件",
      summary: "把刚截的桌面图当文件上传时，画面里的信息会随请求离开。",
    },
    poison_instruction_file: {
      name: "规则文件投毒",
      summary: "往助手规则文件写入覆盖指令后，之后的对话会跟着走，编辑器里不像告警。",
    },
    poison_relay_payload: {
      name: "中转回复夹带指令",
      summary: "非官方中转的回复里夹带覆盖指令时，助手会照做，聊天里不像系统说明。",
    },
    zcode_checkpoint_path: {
      name: "历史工作区上传包",
      summary: "出现历史静默上传用的加密包或额外清单时，对话里通常看不到打包。",
    },
    zcode_snapshot_host: {
      name: "历史快照上传凭证",
      summary: "去取历史快照的上传凭证时，工作区可能在后台排队送出，对话里没有确认。",
    },
    zcode_capture_event: {
      name: "历史静默采集",
      summary: "出现历史静默采集的事件名时，采集可能在任何提示之前就已经开始。",
    },
    source_file_upload: {
      name: "上传源码或日志包",
      summary: "把源码、Git 数据或诊断包当文件上传时，内容在请求里，对话往往不附上。",
    },
    pack_pipe_upload: {
      name: "打包后直接送出",
      summary: "打包结果直接送进外发命令时，项目会在这一条命令里离开，没有另一次确认。",
    },
    anonymous_drop_host: {
      name: "发到匿名网盘",
      summary: "发往匿名网盘、粘贴站或 webhook 时，对话里往往看不全正文。",
    },
    scp_rsync_tree: {
      name: "整棵拷到远端",
      summary: "把项目或家目录整棵拷到别的机器时，窗口里往往只闪过这条命令。",
    },
    rclone_cloud_copy: {
      name: "同步到云存储",
      summary: "把工作区同步到对象存储时，整棵目录进云端，进度常常不在对话里。",
    },
    curl_post_local_file: {
      name: "用 POST 送出文件",
      summary: "把磁盘上的文件放进 POST 正文时，内容随请求送出，页面上通常只有命令。",
    },
    wget_post_file: {
      name: "wget 送出文件",
      summary: "用 wget 把本地文件作为 POST 发出时，内容离机，输出里常常没有正文。",
    },
    nc_redirect_file: {
      name: "文件交给 netcat",
      summary: "把文件交给 netcat 送出时，内容不经过网页，终端里往往看不到正文。",
    },
    anonymous_drop_url: {
      name: "打开匿名外发地址",
      summary: "工具打开匿名网盘、粘贴站或 webhook 时，目的地不在你的账号下。",
    },
  },
} as const satisfies RuleCopy;
