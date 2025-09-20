"""
日志解析器模块

支持多种格式的日志解析：
- JSON格式日志
- 普通文本日志  
- 半结构化字段日志

提供健壮的日志解析功能，能处理空日志、格式异常等情况。
"""

import json
import re
import logging
from datetime import datetime
from typing import Dict, List, Optional, Union, Any
from dataclasses import dataclass


@dataclass
class LogEntry:
    """日志条目数据结构"""
    timestamp: Optional[str] = None
    ip_address: Optional[str] = None
    request_content: Optional[str] = None
    error_level: Optional[str] = None
    raw_content: str = ""
    log_format: str = "unknown"
    parsed_fields: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parsed_fields is None:
            self.parsed_fields = {}


class LogParser:
    """日志解析器类"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # 常见的时间戳正则模式
        self.timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?',  # ISO格式
            r'\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}',  # Apache格式
            r'\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}',  # Syslog格式
            r'\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2}',  # 常见格式
        ]
        
        # IP地址正则模式
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        
        # 错误等级模式
        self.error_level_patterns = [
            r'\b(DEBUG|INFO|WARN|WARNING|ERROR|FATAL|TRACE)\b',
            r'\b(debug|info|warn|warning|error|fatal|trace)\b',
        ]
        
    def parse_log_file(self, file_path: str, encoding: str = 'utf-8') -> List[LogEntry]:
        """解析日志文件"""
        log_entries = []
        
        try:
            with open(file_path, 'r', encoding=encoding) as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line = line.strip()
                if not line:  # 跳过空行
                    continue
                    
                try:
                    entry = self.parse_log_line(line)
                    entry.parsed_fields['line_number'] = line_num
                    log_entries.append(entry)
                except Exception as e:
                    self.logger.warning(f"解析第{line_num}行时出错: {e}")
                    # 即使解析失败也创建一个基础条目
                    entry = LogEntry(raw_content=line, log_format="error")
                    entry.parsed_fields['line_number'] = line_num
                    entry.parsed_fields['parse_error'] = str(e)
                    log_entries.append(entry)
                    
        except Exception as e:
            self.logger.error(f"读取日志文件失败: {e}")
            raise
            
        return log_entries
    
    def parse_log_line(self, line: str) -> LogEntry:
        """解析单条日志"""
        line = line.strip()
        if not line:
            return LogEntry(raw_content=line, log_format="empty")
        
        # 尝试JSON格式解析
        json_entry = self._try_parse_json(line)
        if json_entry:
            return json_entry
            
        # 尝试结构化文本解析
        structured_entry = self._try_parse_structured(line)
        if structured_entry:
            return structured_entry
            
        # 尝试普通文本解析
        text_entry = self._try_parse_plain_text(line)
        return text_entry
    
    def _try_parse_json(self, line: str) -> Optional[LogEntry]:
        """尝试JSON格式解析"""
        try:
            data = json.loads(line)
            if not isinstance(data, dict):
                return None
                
            entry = LogEntry(raw_content=line, log_format="json")
            
            # 提取标准字段
            entry.timestamp = self._extract_timestamp_from_dict(data)
            entry.ip_address = self._extract_ip_from_dict(data)
            entry.request_content = self._extract_request_from_dict(data)
            entry.error_level = self._extract_level_from_dict(data)
            
            # 保存所有字段
            entry.parsed_fields.update(data)
            
            return entry
            
        except (json.JSONDecodeError, TypeError):
            return None
    
    def _try_parse_structured(self, line: str) -> Optional[LogEntry]:
        """尝试结构化文本解析（如 key=value 格式）"""
        # 检查是否包含key=value模式
        if '=' not in line:
            return None
            
        try:
            entry = LogEntry(raw_content=line, log_format="structured")
            fields = {}
            
            # 解析key=value对
            # 支持引号包围的值
            pattern = r'(\w+)=(?:"([^"]*)"|\'([^\']*)\'|([^\s]+))'
            matches = re.findall(pattern, line)
            
            for match in matches:
                key = match[0]
                value = match[1] or match[2] or match[3]
                fields[key] = value
            
            entry.parsed_fields.update(fields)
            
            # 提取标准字段
            entry.timestamp = self._extract_timestamp_from_dict(fields)
            entry.ip_address = self._extract_ip_from_dict(fields)
            entry.request_content = self._extract_request_from_dict(fields)
            entry.error_level = self._extract_level_from_dict(fields)
            
            # 如果没有从字段中提取到，尝试从原始文本提取
            if not entry.timestamp:
                entry.timestamp = self._extract_timestamp_from_text(line)
            if not entry.ip_address:
                entry.ip_address = self._extract_ip_from_text(line)
            if not entry.error_level:
                entry.error_level = self._extract_level_from_text(line)
                
            return entry
            
        except Exception:
            return None
    
    def _try_parse_plain_text(self, line: str) -> LogEntry:
        """解析普通文本日志"""
        entry = LogEntry(raw_content=line, log_format="plain_text")
        
        # 从文本中提取字段
        entry.timestamp = self._extract_timestamp_from_text(line)
        entry.ip_address = self._extract_ip_from_text(line)
        entry.error_level = self._extract_level_from_text(line)
        entry.request_content = line  # 整行作为请求内容
        
        # 尝试识别一些常见的日志格式
        self._parse_common_formats(line, entry)
        
        return entry
    
    def _extract_timestamp_from_dict(self, data: dict) -> Optional[str]:
        """从字典中提取时间戳"""
        timestamp_keys = [
            'timestamp', 'time', 'datetime', 'date', 'created_at', 
            'log_time', '@timestamp', 'ts', 'time_stamp'
        ]
        
        for key in timestamp_keys:
            if key in data:
                return str(data[key])
        return None
    
    def _extract_ip_from_dict(self, data: dict) -> Optional[str]:
        """从字典中提取IP地址"""
        ip_keys = [
            'ip', 'ip_address', 'client_ip', 'remote_ip', 'src_ip', 
            'source_ip', 'host', 'remote_addr', 'x_forwarded_for'
        ]
        
        for key in ip_keys:
            if key in data:
                ip_str = str(data[key])
                # 验证IP格式
                if re.match(self.ip_pattern, ip_str):
                    return ip_str
        return None
    
    def _extract_request_from_dict(self, data: dict) -> Optional[str]:
        """从字典中提取请求内容"""
        request_keys = [
            'request', 'message', 'msg', 'content', 'query', 
            'sql', 'command', 'url', 'path', 'endpoint'
        ]
        
        for key in request_keys:
            if key in data:
                return str(data[key])
        return None
    
    def _extract_level_from_dict(self, data: dict) -> Optional[str]:
        """从字典中提取错误等级"""
        level_keys = ['level', 'log_level', 'severity', 'priority', 'type']
        
        for key in level_keys:
            if key in data:
                return str(data[key]).upper()
        return None
    
    def _extract_timestamp_from_text(self, text: str) -> Optional[str]:
        """从文本中提取时间戳"""
        for pattern in self.timestamp_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group()
        return None
    
    def _extract_ip_from_text(self, text: str) -> Optional[str]:
        """从文本中提取IP地址"""
        match = re.search(self.ip_pattern, text)
        return match.group() if match else None
    
    def _extract_level_from_text(self, text: str) -> Optional[str]:
        """从文本中提取错误等级"""
        for pattern in self.error_level_patterns:
            match = re.search(pattern, text)
            if match:
                return match.group().upper()
        return None
    
    def _parse_common_formats(self, line: str, entry: LogEntry):
        """解析常见日志格式"""
        # Apache Combined Log Format
        apache_pattern = r'^(\S+) \S+ \S+ \[(.*?)\] "(.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
        match = re.match(apache_pattern, line)
        if match:
            entry.log_format = "apache_combined"
            entry.ip_address = match.group(1)
            entry.timestamp = match.group(2)
            entry.request_content = match.group(3)
            entry.parsed_fields.update({
                'status_code': match.group(4),
                'response_size': match.group(5),
                'referer': match.group(6),
                'user_agent': match.group(7)
            })
            return
        
        # Nginx格式
        nginx_pattern = r'^(\S+) - - \[(.*?)\] "(.*?)" (\d+) (\d+)'
        match = re.match(nginx_pattern, line)
        if match:
            entry.log_format = "nginx"
            entry.ip_address = match.group(1)
            entry.timestamp = match.group(2)
            entry.request_content = match.group(3)
            entry.parsed_fields.update({
                'status_code': match.group(4),
                'response_size': match.group(5)
            })
            return
    
    def get_statistics(self, log_entries: List[LogEntry]) -> Dict[str, Any]:
        """获取日志解析统计信息"""
        if not log_entries:
            return {"total": 0}
        
        stats = {
            "total": len(log_entries),
            "formats": {},
            "error_levels": {},
            "unique_ips": set(),
            "parse_errors": 0
        }
        
        for entry in log_entries:
            # 统计格式分布
            stats["formats"][entry.log_format] = stats["formats"].get(entry.log_format, 0) + 1
            
            # 统计错误等级分布
            if entry.error_level:
                stats["error_levels"][entry.error_level] = stats["error_levels"].get(entry.error_level, 0) + 1
            
            # 统计唯一IP
            if entry.ip_address:
                stats["unique_ips"].add(entry.ip_address)
            
            # 统计解析错误
            if entry.log_format == "error" or "parse_error" in entry.parsed_fields:
                stats["parse_errors"] += 1
        
        stats["unique_ips"] = len(stats["unique_ips"])
        return stats


def test_parser():
    """测试日志解析器"""
    parser = LogParser()
    
    # 测试样例日志
    test_logs = [
        # JSON格式
        '{"timestamp": "2024-01-01T10:00:00Z", "ip": "192.168.1.100", "level": "ERROR", "message": "SELECT * FROM users WHERE id=1"}',
        
        # 结构化格式
        'timestamp="2024-01-01 10:01:00" ip=192.168.1.101 level=WARN message="DROP TABLE users"',
        
        # Apache格式
        '192.168.1.102 - - [01/Jan/2024:10:02:00 +0000] "GET /admin?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "-" "Mozilla/5.0"',
        
        # 普通文本
        '2024-01-01 10:03:00 ERROR [192.168.1.103] User attempted: <script>alert("xss")</script>',
        
        # 空行和异常格式
        '',
        'invalid json {broken'
    ]
    
    print("=== 日志解析器测试 ===")
    for i, log_line in enumerate(test_logs, 1):
        print(f"\n测试 {i}: {log_line[:50]}...")
        try:
            entry = parser.parse_log_line(log_line)
            print(f"  格式: {entry.log_format}")
            print(f"  时间戳: {entry.timestamp}")
            print(f"  IP地址: {entry.ip_address}")
            print(f"  错误等级: {entry.error_level}")
            print(f"  请求内容: {entry.request_content}")
        except Exception as e:
            print(f"  解析失败: {e}")


if __name__ == "__main__":
    test_parser()