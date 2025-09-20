"""
样例日志数据生成器

生成多种格式的样例日志数据，用于测试和演示系统功能
"""

import json
import random
from datetime import datetime, timedelta
from typing import List


def generate_sample_logs() -> List[str]:
    """生成样例日志数据"""
    
    # 基础数据
    ips = [
        "192.168.1.100", "192.168.1.101", "192.168.1.102", "10.0.0.50",
        "172.16.0.10", "203.0.113.1", "198.51.100.2", "127.0.0.1"
    ]
    
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "curl/7.68.0",
        "python-requests/2.25.1"
    ]
    
    # 正常日志样例
    normal_logs = []
    
    # JSON格式日志
    for i in range(20):
        timestamp = (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat()
        log = {
            "timestamp": timestamp,
            "ip": random.choice(ips),
            "level": random.choice(["INFO", "DEBUG", "WARN"]),
            "message": random.choice([
                "User login successful",
                "File uploaded successfully",
                "Database connection established",
                "Cache cleared",
                "Backup completed",
                "Session started",
                "Configuration loaded",
                "Service started"
            ]),
            "status_code": random.choice([200, 201, 304]),
            "response_time": random.randint(50, 500)
        }
        normal_logs.append(json.dumps(log, ensure_ascii=False))
    
    # Apache格式日志
    for i in range(15):
        ip = random.choice(ips)
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        request = random.choice([
            "GET /api/users HTTP/1.1",
            "POST /api/login HTTP/1.1",
            "GET /dashboard HTTP/1.1",
            "PUT /api/profile HTTP/1.1",
            "GET /static/css/style.css HTTP/1.1"
        ])
        status = random.choice([200, 201, 304, 404])
        size = random.randint(500, 5000)
        user_agent = random.choice(user_agents)
        
        log = f'{ip} - - [{timestamp}] "{request}" {status} {size} "-" "{user_agent}"'
        normal_logs.append(log)
    
    # 普通文本日志
    for i in range(10):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip = random.choice(ips)
        level = random.choice(["INFO", "DEBUG"])
        message = random.choice([
            "Request processed successfully",
            "User session validated",
            "Database query executed",
            "File system check completed"
        ])
        log = f"{timestamp} {level} [{ip}] {message}"
        normal_logs.append(log)
    
    # 恶意日志样例
    malicious_logs = []
    
    # SQL注入攻击
    sql_attacks = [
        "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
        "admin' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
        "UNION SELECT username, password FROM admin WHERE '1'='1",
        "1; DELETE FROM products WHERE 1=1",
        "' OR 1=1 LIMIT 1 OFFSET 0 --"
    ]
    
    for attack in sql_attacks:
        ip = random.choice(ips)
        timestamp = datetime.now().isoformat()
        
        # JSON格式
        log = {
            "timestamp": timestamp,
            "ip": ip,
            "level": "ERROR",
            "message": f"SQL query: {attack}",
            "status_code": 500
        }
        malicious_logs.append(json.dumps(log, ensure_ascii=False))
        
        # Apache格式
        timestamp_apache = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        log = f'{ip} - - [{timestamp_apache}] "GET /search?q={attack} HTTP/1.1" 500 0 "-" "curl/7.68.0"'
        malicious_logs.append(log)
    
    # XSS攻击
    xss_attacks = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<iframe src='javascript:alert(1)'></iframe>",
        "<svg onload=alert('xss')>",
        "eval('alert(1)')",
        "<body onload=alert('xss')>"
    ]
    
    for attack in xss_attacks:
        ip = random.choice(ips)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log = f"{timestamp} WARN [{ip}] User input: {attack}"
        malicious_logs.append(log)
    
    # 敏感信息泄露
    sensitive_data = [
        "User email: john.doe@example.com, phone: 13812345678",
        "API key: sk-1234567890abcdef, secret: abcd1234",
        "Password reset: user@test.com password=newpass123",
        "Credit card: 4532-1234-5678-9012 exp: 12/25",
        "ID card: 123456789012345678 belongs to Zhang Wei",
        "Database credentials: user=admin password=secret123"
    ]
    
    for data in sensitive_data:
        ip = random.choice(ips)
        timestamp = datetime.now().isoformat()
        log = {
            "timestamp": timestamp,
            "ip": ip,
            "level": "INFO",
            "message": data
        }
        malicious_logs.append(json.dumps(log, ensure_ascii=False))
    
    # 路径遍历和命令注入
    path_attacks = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "/etc/shadow",
        "127.0.0.1; cat /etc/passwd",
        "| whoami",
        "&& ls -la /",
        "`id`",
        "$(cat /etc/hosts)"
    ]
    
    for attack in path_attacks:
        ip = random.choice(ips)
        timestamp = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
        log = f'{ip} - - [{timestamp}] "GET /files/{attack} HTTP/1.1" 403 0 "-" "curl/7.68.0"'
        malicious_logs.append(log)
    
    # 合并并打乱顺序
    all_logs = normal_logs + malicious_logs
    random.shuffle(all_logs)
    
    return all_logs


def save_sample_logs():
    """保存样例日志到文件"""
    logs = generate_sample_logs()
    
    # 保存所有日志
    with open("sample_logs.log", "w", encoding="utf-8") as f:
        for log in logs:
            f.write(log + "\n")
    
    # 保存正常日志
    normal_logs = []
    malicious_logs = []
    
    # 重新生成并分类保存
    logs = generate_sample_logs()
    
    # 这里简化处理，实际应该根据内容判断
    for i, log in enumerate(logs):
        if i % 3 == 0:  # 简单的恶意日志标记
            malicious_logs.append(log)
        else:
            normal_logs.append(log)
    
    with open("normal_logs.log", "w", encoding="utf-8") as f:
        for log in normal_logs:
            f.write(log + "\n")
    
    with open("malicious_logs.log", "w", encoding="utf-8") as f:
        for log in malicious_logs:
            f.write(log + "\n")
    
    print(f"样例日志已生成:")
    print(f"  - sample_logs.log: {len(logs)} 条混合日志")
    print(f"  - normal_logs.log: {len(normal_logs)} 条正常日志")
    print(f"  - malicious_logs.log: {len(malicious_logs)} 条恶意日志")


if __name__ == "__main__":
    save_sample_logs()