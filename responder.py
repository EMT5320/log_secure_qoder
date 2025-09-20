"""
修复与响应模块

当检测到风险时，提供自动修复功能：
1. 敏感信息脱敏处理
2. 生成告警信息
3. 记录风险事件
4. 触发响应动作
"""

import re
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict

try:
    from parser import LogEntry
    from detector import RiskResult
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from parser import LogEntry
    from detector import RiskResult


@dataclass
class Alert:
    """告警信息数据结构"""
    level: str  # low, medium, high, critical
    ip: str
    action: str  # logged, blocked, sanitized
    reason: str
    timestamp: str
    details: Dict[str, Any] = None
    original_content: str = ""
    sanitized_content: str = ""
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
    
    def to_json(self) -> str:
        """转换为JSON格式"""
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


class SensitiveDataSanitizer:
    """敏感数据脱敏处理器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._init_patterns()
    
    def _init_patterns(self):
        """初始化脱敏规则"""
        self.patterns = {
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'replacement': '***@***.***'
            },
            'phone': {
                'pattern': r'\b(?:\+86[\s-]?)?1[3-9]\d{9}\b',
                'replacement': '***'
            },
            'id_card': {
                'pattern': r'\b\d{17}[\dXx]\b',
                'replacement': '***'
            },
            'credit_card': {
                'pattern': r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                'replacement': '****-****-****-****'
            },
            'password': {
                'pattern': r'(password|passwd|pwd)\s*[:=]\s*\S+',
                'replacement': r'\1=***',
                'flags': re.IGNORECASE
            },
            'api_key': {
                'pattern': r'(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+',
                'replacement': r'\1=***',
                'flags': re.IGNORECASE
            },
            'ip_address': {
                'pattern': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'replacement': '***.***.***.***',
                'selective': True  # 可选择性脱敏
            }
        }
    
    def sanitize(self, content: str, selective: bool = False) -> tuple[str, List[str]]:
        """
        脱敏处理
        
        Args:
            content: 要处理的内容
            selective: 是否选择性脱敏（如IP地址）
        
        Returns:
            tuple: (脱敏后的内容, 脱敏类型列表)
        """
        sanitized_content = content
        sanitized_types = []
        
        for data_type, config in self.patterns.items():
            pattern = config['pattern']
            replacement = config['replacement']
            flags = config.get('flags', 0)
            is_selective = config.get('selective', False)
            
            # 如果是选择性脱敏且未启用选择性模式，跳过
            if is_selective and not selective:
                continue
            
            try:
                if re.search(pattern, sanitized_content, flags):
                    sanitized_types.append(data_type)
                    sanitized_content = re.sub(pattern, replacement, sanitized_content, flags=flags)
            except re.error as e:
                self.logger.warning(f"脱敏规则 {data_type} 正则表达式错误: {e}")
        
        return sanitized_content, sanitized_types
    
    def sanitize_log_entry(self, log_entry: LogEntry) -> LogEntry:
        """脱敏处理日志条目"""
        sanitized_entry = LogEntry(
            timestamp=log_entry.timestamp,
            ip_address=log_entry.ip_address,
            error_level=log_entry.error_level,
            log_format=log_entry.log_format,
            parsed_fields=log_entry.parsed_fields.copy() if log_entry.parsed_fields else {}
        )
        
        # 脱敏原始内容
        sanitized_content, types = self.sanitize(log_entry.raw_content)
        sanitized_entry.raw_content = sanitized_content
        
        # 脱敏请求内容
        if log_entry.request_content:
            sanitized_request, request_types = self.sanitize(log_entry.request_content)
            sanitized_entry.request_content = sanitized_request
            types.extend(request_types)
        
        # 脱敏解析字段中的敏感信息
        if log_entry.parsed_fields:
            for key, value in log_entry.parsed_fields.items():
                if isinstance(value, str):
                    sanitized_value, field_types = self.sanitize(value)
                    sanitized_entry.parsed_fields[key] = sanitized_value
                    types.extend(field_types)
        
        # 记录脱敏信息
        sanitized_entry.parsed_fields['_sanitized'] = True
        sanitized_entry.parsed_fields['_sanitized_types'] = list(set(types))
        
        return sanitized_entry


class ResponseAction:
    """响应动作处理器"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or self._default_config()
        self.sanitizer = SensitiveDataSanitizer()
    
    def _default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            'auto_sanitize': True,
            'log_alerts': True,
            'alert_file': 'security_alerts.log',
            'response_rules': {
                'critical': 'block',
                'high': 'sanitize',
                'medium': 'log',
                'low': 'log'
            }
        }
    
    def process_risk(self, log_entry: LogEntry, risk_result: RiskResult) -> Alert:
        """处理风险检测结果"""
        # 确定响应动作
        action = self._determine_action(risk_result)
        
        # 创建告警
        alert = Alert(
            level=risk_result.risk_level,
            ip=log_entry.ip_address or "unknown",
            action=action,
            reason=self._generate_reason(risk_result),
            timestamp=datetime.now().isoformat(),
            original_content=log_entry.raw_content,
            details={
                'risk_type': risk_result.risk_type,
                'confidence': risk_result.confidence,
                'matched_rules': risk_result.matched_rules,
                'log_format': log_entry.log_format,
                'timestamp': log_entry.timestamp
            }
        )
        
        # 执行响应动作
        self._execute_action(log_entry, risk_result, alert)
        
        # 记录告警
        if self.config.get('log_alerts', True):
            self._log_alert(alert)
        
        return alert
    
    def _determine_action(self, risk_result: RiskResult) -> str:
        """确定响应动作"""
        rules = self.config.get('response_rules', {})
        return rules.get(risk_result.risk_level, 'log')
    
    def _generate_reason(self, risk_result: RiskResult) -> str:
        """生成告警原因"""
        reasons = []
        
        if risk_result.risk_type == 'sql_injection':
            reasons.append("SQL Injection")
        elif risk_result.risk_type == 'xss':
            reasons.append("XSS Attack")
        elif risk_result.risk_type == 'sensitive_info':
            reasons.append("Sensitive Information Disclosure")
        elif risk_result.risk_type == 'anomaly':
            reasons.append("Anomalous Request Pattern")
        elif risk_result.risk_type == 'ml_detected':
            reasons.append("ML Detected Malicious Pattern")
        else:
            reasons.append("Security Risk Detected")
        
        if risk_result.matched_rules:
            reasons.append(f"Rules: {', '.join(risk_result.matched_rules[:3])}")
        
        return "; ".join(reasons)
    
    def _execute_action(self, log_entry: LogEntry, risk_result: RiskResult, alert: Alert):
        """执行响应动作"""
        action = alert.action
        
        if action in ['sanitize', 'block']:
            # 执行脱敏处理
            sanitized_entry = self.sanitizer.sanitize_log_entry(log_entry)
            alert.sanitized_content = sanitized_entry.raw_content
            
            # 记录脱敏信息
            if sanitized_entry.parsed_fields.get('_sanitized'):
                alert.details['sanitized_types'] = sanitized_entry.parsed_fields.get('_sanitized_types', [])
        
        if action == 'block':
            # 模拟阻断操作
            alert.details['blocked'] = True
            self.logger.warning(f"[BLOCKED] 阻断恶意请求: {log_entry.ip_address}")
        
        # 记录处理结果
        self.logger.info(f"[{action.upper()}] 风险处理完成: {risk_result.risk_type} - {risk_result.risk_level}")
    
    def _log_alert(self, alert: Alert):
        """记录告警到文件"""
        try:
            alert_file = self.config.get('alert_file', 'security_alerts.log')
            with open(alert_file, 'a', encoding='utf-8') as f:
                f.write(alert.to_json() + '\n')
        except Exception as e:
            self.logger.error(f"记录告警失败: {e}")


class RiskResponseSystem:
    """风险响应系统"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        self.response_action = ResponseAction(config)
        self.sanitizer = SensitiveDataSanitizer()
        
        # 统计信息
        self.stats = {
            'total_processed': 0,
            'risks_detected': 0,
            'sanitized': 0,
            'blocked': 0,
            'alerts_generated': 0
        }
    
    def process_log_entry(self, log_entry: LogEntry, risk_result: RiskResult) -> Dict[str, Any]:
        """处理日志条目和风险检测结果"""
        self.stats['total_processed'] += 1
        
        result = {
            'log_entry': log_entry,
            'risk_result': risk_result,
            'alert': None,
            'sanitized_entry': None,
            'action_taken': 'none'
        }
        
        if risk_result.is_risk:
            self.stats['risks_detected'] += 1
            
            # 生成告警和执行响应
            alert = self.response_action.process_risk(log_entry, risk_result)
            result['alert'] = alert
            result['action_taken'] = alert.action
            
            self.stats['alerts_generated'] += 1
            
            # 更新统计
            if alert.action == 'sanitize':
                self.stats['sanitized'] += 1
            elif alert.action == 'block':
                self.stats['blocked'] += 1
        
        return result
    
    def batch_process(self, log_entries: List[LogEntry], risk_results: List[RiskResult]) -> List[Dict[str, Any]]:
        """批量处理日志条目"""
        if len(log_entries) != len(risk_results):
            raise ValueError("日志条目和风险检测结果数量不匹配")
        
        results = []
        for log_entry, risk_result in zip(log_entries, risk_results):
            result = self.process_log_entry(log_entry, risk_result)
            results.append(result)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取处理统计信息"""
        stats = self.stats.copy()
        
        if stats['total_processed'] > 0:
            stats['risk_detection_rate'] = stats['risks_detected'] / stats['total_processed']
            stats['sanitization_rate'] = stats['sanitized'] / stats['total_processed']
            stats['block_rate'] = stats['blocked'] / stats['total_processed']
        else:
            stats['risk_detection_rate'] = 0.0
            stats['sanitization_rate'] = 0.0
            stats['block_rate'] = 0.0
        
        return stats
    
    def export_alerts(self, output_file: str, format: str = 'json'):
        """导出告警信息"""
        alert_file = self.config.get('alert_file', 'security_alerts.log')
        
        try:
            alerts = []
            with open(alert_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        alerts.append(json.loads(line))
            
            if format == 'json':
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(alerts, f, ensure_ascii=False, indent=2)
            elif format == 'csv':
                import csv
                if alerts:
                    with open(output_file, 'w', newline='', encoding='utf-8') as f:
                        writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
                        writer.writeheader()
                        writer.writerows(alerts)
            
            self.logger.info(f"告警导出完成: {output_file}")
            
        except Exception as e:
            self.logger.error(f"导出告警失败: {e}")


def test_responder():
    """测试响应系统"""
    print("=== 响应系统测试 ===")
    
    from parser import LogEntry
    from detector import RiskResult
    
    # 创建响应系统
    response_system = RiskResponseSystem()
    
    # 测试案例
    test_cases = [
        {
            'name': '高风险SQL注入',
            'log_entry': LogEntry(
                ip_address="192.168.1.100",
                request_content="SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
                raw_content="2024-01-01 10:00:00 [192.168.1.100] SQL: SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"
            ),
            'risk_result': RiskResult(
                is_risk=True,
                risk_type='sql_injection',
                risk_level='high',
                confidence=0.95,
                matched_rules=['sql_injection.union_select']
            )
        },
        {
            'name': '敏感信息泄露',
            'log_entry': LogEntry(
                ip_address="192.168.1.101",
                request_content="User info: email=test@example.com phone=13812345678",
                raw_content="2024-01-01 10:01:00 [192.168.1.101] User info: email=test@example.com phone=13812345678"
            ),
            'risk_result': RiskResult(
                is_risk=True,
                risk_type='sensitive_info',
                risk_level='medium',
                confidence=0.85,
                matched_rules=['sensitive_info.email', 'sensitive_info.phone']
            )
        },
        {
            'name': '正常请求',
            'log_entry': LogEntry(
                ip_address="192.168.1.102",
                request_content="GET /api/users?page=1",
                raw_content="2024-01-01 10:02:00 [192.168.1.102] GET /api/users?page=1 200 OK"
            ),
            'risk_result': RiskResult(
                is_risk=False,
                risk_type='none',
                risk_level='low',
                confidence=0.1
            )
        }
    ]
    
    # 处理测试案例
    for i, case in enumerate(test_cases, 1):
        print(f"\n--- 测试案例 {i}: {case['name']} ---")
        
        result = response_system.process_log_entry(case['log_entry'], case['risk_result'])
        
        print(f"采取动作: {result['action_taken']}")
        
        if result['alert']:
            alert = result['alert']
            print(f"告警等级: {alert.level}")
            print(f"告警原因: {alert.reason}")
            print(f"原始内容: {alert.original_content[:50]}...")
            if alert.sanitized_content:
                print(f"脱敏内容: {alert.sanitized_content[:50]}...")
        
        print("处理完成")
    
    # 显示统计信息
    print(f"\n=== 处理统计 ===")
    stats = response_system.get_statistics()
    for key, value in stats.items():
        print(f"{key}: {value}")


if __name__ == "__main__":
    test_responder()