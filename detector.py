"""
风险检测模块

提供两种风险检测方式：
1. 规则检测：基于预定义规则检测恶意模式
2. 机器学习检测：使用轻量级模型区分正常请求和恶意请求

支持检测的风险类型：
- SQL注入
- XSS攻击  
- 敏感信息泄露
- 异常请求模式
"""

import re
import logging
import pickle
import os
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import numpy as np

try:
    from parser import LogEntry
except ImportError:
    import sys
    import os
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from parser import LogEntry


@dataclass
class RiskResult:
    """风险检测结果"""
    is_risk: bool = False
    risk_type: str = "none"
    risk_level: str = "low"  # low, medium, high, critical
    confidence: float = 0.0
    matched_rules: List[str] = None
    details: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []
        if self.details is None:
            self.details = {}


class RuleBasedDetector:
    """基于规则的风险检测器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._init_rules()
    
    def _init_rules(self):
        """初始化检测规则"""
        
        # SQL注入检测规则
        self.sql_injection_rules = {
            'union_select': {
                'pattern': r'\bunion\s+select\b',
                'flags': re.IGNORECASE,
                'level': 'high',
                'description': 'UNION SELECT SQL注入'
            },
            'drop_table': {
                'pattern': r'\bdrop\s+table\b',
                'flags': re.IGNORECASE,
                'level': 'critical',
                'description': 'DROP TABLE危险操作'
            },
            'delete_from': {
                'pattern': r'\bdelete\s+from\b',
                'flags': re.IGNORECASE,
                'level': 'high',
                'description': 'DELETE FROM危险操作'
            },
            'or_1_equals_1': {
                'pattern': r"(\'|\")?\s*or\s+1\s*=\s*1\s*(\'|\")?",
                'flags': re.IGNORECASE,
                'level': 'high',
                'description': 'OR 1=1 SQL注入'
            },
            'sql_comment': {
                'pattern': r'(--|\#|/\*)',
                'flags': re.IGNORECASE,
                'level': 'medium',
                'description': 'SQL注释符'
            },
            'hex_encoding': {
                'pattern': r'0x[0-9a-f]+',
                'flags': re.IGNORECASE,
                'level': 'medium',
                'description': '十六进制编码可能的SQL注入'
            }
        }
        
        # XSS攻击检测规则
        self.xss_rules = {
            'script_tag': {
                'pattern': r'<script[^>]*>.*?</script>',
                'flags': re.IGNORECASE | re.DOTALL,
                'level': 'high',
                'description': 'Script标签XSS'
            },
            'javascript_scheme': {
                'pattern': r'javascript\s*:',
                'flags': re.IGNORECASE,
                'level': 'high',
                'description': 'JavaScript伪协议'
            },
            'on_event': {
                'pattern': r'\bon\w+\s*=',
                'flags': re.IGNORECASE,
                'level': 'medium',
                'description': '事件处理器XSS'
            },
            'eval_function': {
                'pattern': r'\beval\s*\(',
                'flags': re.IGNORECASE,
                'level': 'high',
                'description': 'eval函数调用'
            },
            'iframe_tag': {
                'pattern': r'<iframe[^>]*>',
                'flags': re.IGNORECASE,
                'level': 'medium',
                'description': 'iframe标签'
            }
        }
        
        # 敏感信息泄露检测规则
        self.sensitive_info_rules = {
            'email': {
                'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'flags': 0,
                'level': 'medium',
                'description': '邮箱地址泄露'
            },
            'phone': {
                'pattern': r'\b(?:\+86[\s-]?)?1[3-9]\d{9}\b',
                'flags': 0,
                'level': 'medium',
                'description': '手机号码泄露'
            },
            'id_card': {
                'pattern': r'\b\d{17}[\dXx]\b',
                'flags': 0,
                'level': 'high',
                'description': '身份证号码泄露'
            },
            'credit_card': {
                'pattern': r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                'flags': 0,
                'level': 'high',
                'description': '信用卡号码泄露'
            },
            'password': {
                'pattern': r'\b(password|passwd|pwd)\s*[:=]\s*\S+',
                'flags': re.IGNORECASE,
                'level': 'critical',
                'description': '密码泄露'
            },
            'api_key': {
                'pattern': r'\b(api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*\S+',
                'flags': re.IGNORECASE,
                'level': 'critical',
                'description': 'API密钥泄露'
            }
        }
        
        # 异常请求模式
        self.anomaly_rules = {
            'path_traversal': {
                'pattern': r'\.\./|\.\.\\',
                'flags': 0,
                'level': 'high',
                'description': '路径遍历攻击'
            },
            'command_injection': {
                'pattern': r'[;&|`]|\$\(',
                'flags': 0,
                'level': 'high',
                'description': '命令注入'
            },
            'null_byte': {
                'pattern': r'%00',
                'flags': 0,
                'level': 'medium',
                'description': '空字节注入'
            },
            'long_request': {
                'pattern': r'.{1000,}',  # 超长请求
                'flags': 0,
                'level': 'low',
                'description': '异常长请求'
            }
        }
        
        # 合并所有规则
        self.all_rules = {
            'sql_injection': self.sql_injection_rules,
            'xss': self.xss_rules,
            'sensitive_info': self.sensitive_info_rules,
            'anomaly': self.anomaly_rules
        }
    
    def detect(self, log_entry: LogEntry) -> RiskResult:
        """检测日志条目的风险"""
        result = RiskResult()
        
        # 获取要检测的内容
        content_to_check = []
        if log_entry.request_content:
            content_to_check.append(log_entry.request_content)
        content_to_check.append(log_entry.raw_content)
        
        # 如果有解析字段，也检查关键字段
        if log_entry.parsed_fields:
            for key, value in log_entry.parsed_fields.items():
                if isinstance(value, str) and key in ['message', 'msg', 'query', 'url', 'path']:
                    content_to_check.append(value)
        
        content = ' '.join(content_to_check)
        
        max_risk_level = 'low'
        max_confidence = 0.0
        matched_rules = []
        details = {}
        
        # 检查所有规则类别
        for category, rules in self.all_rules.items():
            category_matches = []
            
            for rule_name, rule_config in rules.items():
                pattern = rule_config['pattern']
                flags = rule_config.get('flags', 0)
                level = rule_config['level']
                description = rule_config['description']
                
                try:
                    matches = re.findall(pattern, content, flags)
                    if matches:
                        rule_id = f"{category}.{rule_name}"
                        matched_rules.append(rule_id)
                        category_matches.append({
                            'rule': rule_id,
                            'level': level,
                            'description': description,
                            'matches': matches[:5]  # 限制匹配结果数量
                        })
                        
                        # 更新最高风险等级
                        if self._compare_risk_level(level, max_risk_level) > 0:
                            max_risk_level = level
                            
                except re.error as e:
                    self.logger.warning(f"规则 {rule_name} 正则表达式错误: {e}")
            
            if category_matches:
                details[category] = category_matches
        
        # 设置检测结果
        result.is_risk = len(matched_rules) > 0
        result.matched_rules = matched_rules
        result.details = details
        
        if result.is_risk:
            result.risk_level = max_risk_level
            result.risk_type = self._determine_primary_risk_type(details)
            result.confidence = self._calculate_rule_confidence(matched_rules, max_risk_level)
        
        return result
    
    def _compare_risk_level(self, level1: str, level2: str) -> int:
        """比较风险等级，返回1表示level1更高，-1表示level2更高，0表示相等"""
        levels = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        return levels.get(level1, 0) - levels.get(level2, 0)
    
    def _determine_primary_risk_type(self, details: Dict) -> str:
        """确定主要风险类型"""
        # 按优先级排序
        priority = ['sensitive_info', 'sql_injection', 'xss', 'anomaly']
        
        for risk_type in priority:
            if risk_type in details:
                return risk_type
        
        return 'unknown'
    
    def _calculate_rule_confidence(self, matched_rules: List[str], max_level: str) -> float:
        """计算规则检测的置信度"""
        base_confidence = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 0.95
        }
        
        confidence = base_confidence.get(max_level, 0.5)
        
        # 多个规则匹配增加置信度
        if len(matched_rules) > 1:
            confidence += min(0.1 * (len(matched_rules) - 1), 0.2)
        
        return min(confidence, 1.0)


class MLDetector:
    """基于机器学习的风险检测器"""
    
    def __init__(self, model_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.model_path = model_path or "ml_detector_model.pkl"
        self.model = None
        self.is_trained = False
        
        # 尝试加载已有模型
        self._load_model()
    
    def train(self, training_data: List[Tuple[str, int]], test_size: float = 0.2):
        """训练机器学习模型
        
        Args:
            training_data: 训练数据，格式为[(text, label), ...]，label: 0=正常, 1=恶意
            test_size: 测试集比例
        """
        if len(training_data) < 10:
            self.logger.warning("训练数据量太少，建议至少100条")
        
        # 准备数据
        texts = [item[0] for item in training_data]
        labels = [item[1] for item in training_data]
        
        # 划分训练集和测试集
        X_train, X_test, y_train, y_test = train_test_split(
            texts, labels, test_size=test_size, random_state=42, stratify=labels
        )
        
        # 创建模型管道
        self.model = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 3),
                lowercase=True,
                stop_words=None
            )),
            ('classifier', LogisticRegression(
                random_state=42,
                max_iter=1000
            ))
        ])
        
        # 训练模型
        self.logger.info("开始训练机器学习模型...")
        self.model.fit(X_train, y_train)
        
        # 评估模型
        y_pred = self.model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        self.logger.info(f"模型训练完成，测试准确率: {accuracy:.3f}")
        self.logger.info(f"分类报告:\n{classification_report(y_test, y_pred)}")
        
        self.is_trained = True
        
        # 保存模型
        self._save_model()
    
    def detect(self, log_entry: LogEntry) -> RiskResult:
        """使用机器学习模型检测风险"""
        if not self.is_trained or self.model is None:
            return RiskResult(details={'error': '模型未训练'})
        
        # 准备检测内容
        content = self._prepare_content(log_entry)
        
        try:
            # 预测
            prediction = self.model.predict([content])[0]
            probabilities = self.model.predict_proba([content])[0]
            
            # 构建结果
            result = RiskResult()
            result.is_risk = prediction == 1
            result.confidence = float(probabilities[1])  # 恶意类别的概率
            
            if result.is_risk:
                result.risk_type = 'ml_detected'
                if result.confidence >= 0.8:
                    result.risk_level = 'high'
                elif result.confidence >= 0.6:
                    result.risk_level = 'medium'
                else:
                    result.risk_level = 'low'
            
            result.details = {
                'ml_prediction': int(prediction),
                'probabilities': {
                    'normal': float(probabilities[0]),
                    'malicious': float(probabilities[1])
                }
            }
            
            return result
            
        except Exception as e:
            self.logger.error(f"ML检测失败: {e}")
            return RiskResult(details={'error': str(e)})
    
    def _prepare_content(self, log_entry: LogEntry) -> str:
        """准备用于ML检测的内容"""
        content_parts = []
        
        if log_entry.request_content:
            content_parts.append(log_entry.request_content)
        
        # 添加其他相关字段
        if log_entry.parsed_fields:
            for key, value in log_entry.parsed_fields.items():
                if isinstance(value, str) and key in ['message', 'msg', 'query', 'url', 'path']:
                    content_parts.append(value)
        
        if not content_parts:
            content_parts.append(log_entry.raw_content)
        
        return ' '.join(content_parts)
    
    def _save_model(self):
        """保存模型"""
        try:
            with open(self.model_path, 'wb') as f:
                pickle.dump(self.model, f)
            self.logger.info(f"模型已保存到: {self.model_path}")
        except Exception as e:
            self.logger.error(f"保存模型失败: {e}")
    
    def _load_model(self):
        """加载模型"""
        try:
            if os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.is_trained = True
                self.logger.info(f"已加载模型: {self.model_path}")
        except Exception as e:
            self.logger.warning(f"加载模型失败: {e}")


class RiskDetector:
    """综合风险检测器，结合规则检测和机器学习检测"""
    
    def __init__(self, ml_model_path: str = None):
        self.logger = logging.getLogger(__name__)
        self.rule_detector = RuleBasedDetector()
        self.ml_detector = MLDetector(ml_model_path)
    
    def detect(self, log_entry: LogEntry, use_ml: bool = True) -> RiskResult:
        """综合检测风险"""
        # 规则检测
        rule_result = self.rule_detector.detect(log_entry)
        
        # 如果不使用ML或ML未训练，直接返回规则检测结果
        if not use_ml or not self.ml_detector.is_trained:
            return rule_result
        
        # ML检测
        ml_result = self.ml_detector.detect(log_entry)
        
        # 融合结果
        return self._merge_results(rule_result, ml_result)
    
    def _merge_results(self, rule_result: RiskResult, ml_result: RiskResult) -> RiskResult:
        """融合规则检测和ML检测结果"""
        merged = RiskResult()
        
        # 如果任一检测器认为有风险，则认为有风险
        merged.is_risk = rule_result.is_risk or ml_result.is_risk
        
        # 选择置信度更高的结果作为主要结果
        if rule_result.confidence >= ml_result.confidence:
            merged.risk_type = rule_result.risk_type
            merged.risk_level = rule_result.risk_level
            merged.confidence = rule_result.confidence
            merged.matched_rules = rule_result.matched_rules
        else:
            merged.risk_type = ml_result.risk_type
            merged.risk_level = ml_result.risk_level
            merged.confidence = ml_result.confidence
        
        # 如果都检测到风险，提升置信度
        if rule_result.is_risk and ml_result.is_risk:
            merged.confidence = min(1.0, merged.confidence + 0.1)
            merged.risk_level = self._elevate_risk_level(merged.risk_level)
        
        # 合并详细信息
        merged.details = {}
        merged.details.update(rule_result.details)
        merged.details.update(ml_result.details)
        
        return merged
    
    def _elevate_risk_level(self, level: str) -> str:
        """提升风险等级"""
        elevation = {
            'low': 'medium',
            'medium': 'high',
            'high': 'critical',
            'critical': 'critical'
        }
        return elevation.get(level, level)
    
    def train_ml_model(self, training_data: List[Tuple[str, int]]):
        """训练ML模型"""
        self.ml_detector.train(training_data)


def generate_sample_training_data() -> List[Tuple[str, int]]:
    """生成样例训练数据"""
    # 恶意请求样例 (label=1)
    malicious_samples = [
        "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
        "DROP TABLE users; --",
        "admin' OR '1'='1",
        "<script>alert('xss')</script>",
        "javascript:alert('xss')",
        "<img src=x onerror=alert('xss')>",
        "email@example.com password=123456",
        "api_key=abc123def456",
        "../../../etc/passwd",
        "127.0.0.1; cat /etc/passwd",
        "DELETE FROM users WHERE 1=1",
        "'; DROP TABLE students; --",
        "eval('alert(1)')",
        "<iframe src='javascript:alert(1)'></iframe>",
        "phone: 13812345678 id_card: 123456789012345678"
    ]
    
    # 正常请求样例 (label=0)
    normal_samples = [
        "GET /api/users?page=1&limit=10",
        "POST /login username=john password=***",
        "User logged in successfully",
        "Database connection established",
        "File uploaded: document.pdf",
        "Cache cleared successfully",
        "Backup completed at 2024-01-01 10:00:00",
        "System startup completed",
        "Memory usage: 85%",
        "Request processed in 150ms",
        "User preferences updated",
        "Email sent to notification@company.com",
        "Session timeout after 30 minutes",
        "API rate limit: 1000 requests/hour",
        "SSL certificate valid until 2025-01-01"
    ]
    
    # 构建训练数据
    training_data = []
    training_data.extend([(sample, 1) for sample in malicious_samples])
    training_data.extend([(sample, 0) for sample in normal_samples])
    
    # 添加更多变体
    import random
    
    # 为恶意样例添加变体
    for sample in malicious_samples[:5]:
        # 大小写变体
        training_data.append((sample.upper(), 1))
        training_data.append((sample.lower(), 1))
        # 添加前缀后缀
        training_data.append((f"INFO: {sample}", 1))
        training_data.append((f"{sample} - Request failed", 1))
    
    # 为正常样例添加变体
    for sample in normal_samples[:5]:
        training_data.append((f"[INFO] {sample}", 0))
        training_data.append((f"{sample} - Status: OK", 0))
    
    random.shuffle(training_data)
    return training_data


def test_detector():
    """测试风险检测器"""
    print("=== 风险检测器测试 ===")
    
    # 创建检测器
    detector = RiskDetector()
    
    # 生成训练数据并训练ML模型
    print("\n训练机器学习模型...")
    training_data = generate_sample_training_data()
    detector.train_ml_model(training_data)
    
    # 测试样例
    from parser import LogEntry
    
    test_cases = [
        {
            'name': 'SQL注入攻击',
            'content': "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin"
        },
        {
            'name': 'XSS攻击',
            'content': "<script>alert('xss attack')</script>"
        },
        {
            'name': '敏感信息泄露',
            'content': "User email: test@example.com, phone: 13812345678"
        },
        {
            'name': '正常请求',
            'content': "GET /api/users?page=1&limit=10 HTTP/1.1 200 OK"
        },
        {
            'name': '路径遍历',
            'content': "GET /files/../../../etc/passwd HTTP/1.1"
        }
    ]
    
    for case in test_cases:
        print(f"\n--- 测试: {case['name']} ---")
        
        # 创建日志条目
        log_entry = LogEntry(
            request_content=case['content'],
            raw_content=case['content']
        )
        
        # 检测风险
        result = detector.detect(log_entry)
        
        print(f"有风险: {result.is_risk}")
        print(f"风险类型: {result.risk_type}")
        print(f"风险等级: {result.risk_level}")
        print(f"置信度: {result.confidence:.3f}")
        print(f"匹配规则: {result.matched_rules}")
        
        if result.details:
            print("详细信息:")
            for key, value in result.details.items():
                print(f"  {key}: {value}")


if __name__ == "__main__":
    test_detector()