# MapAPI-Leak-Debugger
MapAPI Leak Debugger V1.0

# MapAPI Leak Debugger - Burp Suite Plugin

**MapAPI Leak Debugger** 是一款专为渗透测试工程师以及企业安全研发打造的**地图MAPAPIKEY泄露滥用**的 Burp Suite 深度集成插件。它实现了从 **被动流量特征提取** 到 **一键越权（跨平台滥用）深度探测** 的完整安全测试闭环，并全面采用了 Burp 原生 HTTP 引擎进行底层驱动与报文渲染。
<img width="1800" height="1125" alt="1" src="https://github.com/user-attachments/assets/09bcd53a-e91c-4dcf-b56f-834933da4575" />

## 核心特性 (Core Features)

* **被动流量清洗与染色预警 (Passive Monitoring)**
  
  * 静默监听流经 Burp 的所有 HTTP/HTTPS 流量，利用高精度正则自动化提取 **高德 (Amap)**、**百度 (Baidu)**、**腾讯 (Tencent)**、**谷歌 (Google)** 的 API Key。
 
  * 自动在 `Proxy -> HTTP history` 中对包含敏感 Key 的请求进行红色高亮染色，并附加精准的特征 Comment，方便溯源。
    
* **资产面板与无缝联动 (Asset Management)**
  
  * 独立的 `MapAPI Tester` UI 标签页，提取的 Key 会自动去重并展示在居中对齐的数据表格中。
    
  * **一键填充**：在表格中单击任意“待测试”记录，即可自动将 Key 与归属服务商智能填充至下方的测试面板。
    
* **高级安全绕过引擎 (Advanced Bypass Engine)**
  
  * **平台特征伪造**：内置现代浏览器及微信小程序专属 User-Agent 池，支持一键注入并绕过前端 `Referer` 防盗链白名单。
    
  * **降级越权测试**：尝试利用移动端 (Android/iOS) 专属 Key 裸调 Web 服务，检测服务端是否存在平台限制泛化漏洞。
    
  * **自动化签名计算**：内置百度 MD5 (SN) 与 腾讯 MD5 (SIG) 计算逻辑，全自动补全复杂签名参数。
    
* **原生报文呈现与结果回写 (Native IMessageEditor & Closed-loop)**
  
  * **状态自动回写**：测试完毕后，自动在上方数据表格的“调试结果”列回写状态（如：`🚨 存在滥用`、`拦截/校验失败`、`安全`）。
    
* **右键菜单智能协同 (Context Menu)**
  
  * 在任何 Burp 报文视图中高亮选中疑似 Key 的字符串 -> 右键 -> `发送至 MapAPI Tester`，插件将智能猜测 Key 归属并自动转入调试流程。

---

##  编译与安装指南 (Installation)

本插件基于 Java 8 构建，依托 PortSwigger 官方的 Extender API。推荐使用 Maven 进行自动化依赖解析与编译。

### 1.克隆与编译
```bash
git clone https://github.com/YourName/MapAPI-Security-Tester.git
cd MapAPI-Leak-Debugger
```
# 强制更新依赖并打包包含所有组件的 Fat JAR
```
mvn clean package -U
```

*编译成功后，将在 `target/` 目录下生成 `MapAPI-Leak-Debugger-1.0-jar-with-dependencies.jar`。*

### 2.加载至 Burp Suite
1. 打开 Burp Suite，导航至 `Extensions` (或 `Extender`) -> `Installed` 标签页。
2. 点击 `Add`。
3. `Extension Type` 选择 `Java`。
4. `Extension file` 选择刚刚编译生成的 **带有 `MapAPI-Leak-Debugger-1.0` 后缀** 的 `.jar` 文件。
5. 点击 `Next`，控制台输出 `[+] T00ls MapAPI Leak Debugger Loaded.` 即代表成功。

## 实战工作流 (Workflow)

1. **被动收集**：正常配置浏览器/手机代理，访问目标应用。插件将在后台静默工作，将被动提取的 Key 集中展示在 `MapAPI` 顶部的列表中。
2. **选择目标**：在表格中点击一条记录，下方控制台将自动填入参数。
3. **环境配置 (可选)**：如果目标是前端 JSAPI，可在“伪造 Referer”处填入被信任的域名。
4. **一键发包**：点击 `发送测试` 或 `随机 ReGeo 逆解析测试`。
5. **审计定性**：
   * 观察底部原生的 `HTTP Response` 面板。
   * 如果响应体成功返回了真实的业务 JSON 数据，且顶部表格回显 `🚨 存在滥用`，说明该 Key 存在严重的未授权调用/配置失误漏洞。

## ⚠️ 免责声明 (Disclaimer)

本工具仅限于在取得**合法授权**的安全渗透测试、漏洞挖掘 (Bug Bounty) 以及企业内部的安全审计中使用。
请勿使用本工具对未授权的第三方服务商接口进行恶意的并发重放攻击或额度盗刷。使用者因不当或非法使用本工具造成的一切直接或间接后果，由使用者自行承担，与工具开发者无关。
