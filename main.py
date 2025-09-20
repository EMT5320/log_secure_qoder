"""
日志风险检测与自动修复系统 - 主程序

提供CLI和REST API接口：
- 命令行工具：处理日志文件或文本
- Web API服务：RESTful接口
- 配置管理和日志记录
"""

import os
import sys
import json
import argparse
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from flask import Flask, request, jsonify, render_template_string
import threading
import time

# 导入自定义模块
try:
    from parser import LogParser, LogEntry
    from detector import RiskDetector, generate_sample_training_data
    from responder import RiskResponseSystem, Alert
except ImportError:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from parser import LogParser, LogEntry
    from detector import RiskDetector, generate_sample_training_data
    from responder import RiskResponseSystem, Alert


class LogSecuritySystem:
    """日志安全系统主类"""
    
    def __init__(self, config_path: str = None):
        self.config = self._load_config(config_path)
        self._setup_logging()
        
        # 初始化组件
        self.parser = LogParser()
        self.detector = RiskDetector()
        self.responder = RiskResponseSystem(self.config.get('responder', {}))
        
        # 训练ML模型（如果需要）
        self._initialize_ml_model()
    
    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """加载配置文件"""
        default_config = {
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                'file': 'log_security.log'
            },
            'ml_model': {
                'auto_train': True,
                'model_path': 'ml_detector_model.pkl'
            },
            'responder': {
                'auto_sanitize': True,
                'log_alerts': True,
                'alert_file': 'security_alerts.log'
            },
            'api': {
                'host': '127.0.0.1',
                'port': 5000,
                'debug': False
            }
        }
        
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"加载配置文件失败: {e}")
        
        return default_config
    
    def _setup_logging(self):
        """设置日志记录"""
        log_config = self.config.get('logging', {})
        
        level = getattr(logging, log_config.get('level', 'INFO'))
        format_str = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        log_file = log_config.get('file', 'log_security.log')
        
        logging.basicConfig(
            level=level,
            format=format_str,
            handlers=[
                logging.FileHandler(log_file, encoding='utf-8'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger(__name__)
    
    def _initialize_ml_model(self):
        """初始化机器学习模型"""
        ml_config = self.config.get('ml_model', {})
        
        if ml_config.get('auto_train', True) and not self.detector.ml_detector.is_trained:
            self.logger.info("自动训练机器学习模型...")
            try:
                training_data = generate_sample_training_data()
                self.detector.train_ml_model(training_data)
                self.logger.info("机器学习模型训练完成")
            except Exception as e:
                self.logger.error(f"机器学习模型训练失败: {e}")
    
    def process_log_file(self, file_path: str) -> Dict[str, Any]:
        """处理日志文件"""
        self.logger.info(f"开始处理日志文件: {file_path}")
        
        try:
            # 解析日志文件
            log_entries = self.parser.parse_log_file(file_path)
            
            # 检测风险
            results = []
            for log_entry in log_entries:
                risk_result = self.detector.detect(log_entry)
                response_result = self.responder.process_log_entry(log_entry, risk_result)
                results.append(response_result)
            
            # 生成报告
            report = self._generate_report(results, file_path)
            
            self.logger.info(f"日志文件处理完成: {len(log_entries)} 条记录")
            return report
            
        except Exception as e:
            self.logger.error(f"处理日志文件失败: {e}")
            raise
    
    def process_log_text(self, text: str) -> Dict[str, Any]:
        """处理单条日志文本"""
        try:
            # 解析日志
            log_entry = self.parser.parse_log_line(text)
            
            # 检测风险
            risk_result = self.detector.detect(log_entry)
            
            # 处理响应
            response_result = self.responder.process_log_entry(log_entry, risk_result)
            
            return {
                'success': True,
                'log_entry': {
                    'timestamp': log_entry.timestamp,
                    'ip_address': log_entry.ip_address,
                    'request_content': log_entry.request_content,
                    'error_level': log_entry.error_level,
                    'log_format': log_entry.log_format
                },
                'risk_result': {
                    'is_risk': risk_result.is_risk,
                    'risk_type': risk_result.risk_type,
                    'risk_level': risk_result.risk_level,
                    'confidence': risk_result.confidence,
                    'matched_rules': risk_result.matched_rules
                },
                'alert': response_result['alert'].to_json() if response_result['alert'] else None,
                'action_taken': response_result['action_taken']
            }
            
        except Exception as e:
            self.logger.error(f"处理日志文本失败: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_report(self, results: List[Dict[str, Any]], file_path: str = None) -> Dict[str, Any]:
        """生成处理报告"""
        total_logs = len(results)
        risks_detected = sum(1 for r in results if r['risk_result'].is_risk)
        alerts_generated = sum(1 for r in results if r['alert'] is not None)
        
        # 统计风险类型
        risk_types = {}
        risk_levels = {}
        actions_taken = {}
        
        for result in results:
            if result['risk_result'].is_risk:
                risk_type = result['risk_result'].risk_type
                risk_level = result['risk_result'].risk_level
                action = result['action_taken']
                
                risk_types[risk_type] = risk_types.get(risk_type, 0) + 1
                risk_levels[risk_level] = risk_levels.get(risk_level, 0) + 1
                actions_taken[action] = actions_taken.get(action, 0) + 1
        
        # 获取响应系统统计
        responder_stats = self.responder.get_statistics()
        
        report = {
            'summary': {
                'file_path': file_path,
                'total_logs': total_logs,
                'risks_detected': risks_detected,
                'alerts_generated': alerts_generated,
                'risk_detection_rate': risks_detected / total_logs if total_logs > 0 else 0
            },
            'risk_analysis': {
                'risk_types': risk_types,
                'risk_levels': risk_levels,
                'actions_taken': actions_taken
            },
            'system_stats': responder_stats,
            'high_risk_alerts': [
                {
                    'ip': result['log_entry'].ip_address,
                    'risk_type': result['risk_result'].risk_type,
                    'risk_level': result['risk_result'].risk_level,
                    'confidence': result['risk_result'].confidence,
                    'content': result['log_entry'].request_content[:100] + '...' if result['log_entry'].request_content and len(result['log_entry'].request_content) > 100 else result['log_entry'].request_content
                }
                for result in results
                if result['risk_result'].is_risk and result['risk_result'].risk_level in ['high', 'critical']
            ][:10]  # 只显示前10个高风险告警
        }
        
        return report


def create_flask_app(system: LogSecuritySystem) -> Flask:
    """创建Flask Web应用"""
    app = Flask(__name__)
    
    # 简单的HTML模板
    HTML_TEMPLATE = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>日志风险检测系统</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 1200px; margin: 0 auto; }
            .form-group { margin: 20px 0; }
            label { display: block; margin-bottom: 5px; font-weight: bold; }
            input, textarea { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; }
            button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
            button:hover { background: #0056b3; }
            .result { margin-top: 20px; padding: 20px; background: #f8f9fa; border-radius: 4px; }
            .alert { padding: 15px; margin: 10px 0; border-radius: 4px; }
            .alert-danger { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .alert-warning { background: #fff3cd; color: #856404; border: 1px solid #ffeeba; }
            .alert-info { background: #d1ecf1; color: #0c5460; border: 1px solid #bee5eb; }
            pre { background: #f8f9fa; padding: 15px; border-radius: 4px; overflow-x: auto; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>日志风险检测与自动修复系统</h1>
            
            <div class="form-group">
                <h2>单条日志检测</h2>
                <form id="logForm">
                    <label for="logText">日志内容:</label>
                    <textarea id="logText" rows="4" placeholder="输入日志内容，如：192.168.1.1 - - [01/Jan/2024:10:00:00 +0000] &quot;GET /admin?id=1' OR '1'='1 HTTP/1.1&quot; 200 1234"></textarea>
                    <button type="submit">检测风险</button>
                </form>
            </div>
            
            <div class="form-group">
                <h2>日志文件检测</h2>
                <form id="fileForm" enctype="multipart/form-data">
                    <label for="logFile">选择日志文件:</label>
                    <input type="file" id="logFile" accept=".log,.txt">
                    <button type="submit">上传并检测</button>
                </form>
            </div>
            
            <div id="result" class="result" style="display: none;">
                <h3>检测结果</h3>
                <div id="resultContent"></div>
            </div>
        </div>
        
        <script>
            document.getElementById('logForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const logText = document.getElementById('logText').value;
                if (!logText.trim()) {
                    alert('请输入日志内容');
                    return;
                }
                
                try {
                    const response = await fetch('/api/detect', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({text: logText})
                    });
                    const result = await response.json();
                    displayResult(result);
                } catch (error) {
                    alert('检测失败: ' + error.message);
                }
            });
            
            document.getElementById('fileForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                const fileInput = document.getElementById('logFile');
                if (!fileInput.files[0]) {
                    alert('请选择文件');
                    return;
                }
                
                const formData = new FormData();
                formData.append('file', fileInput.files[0]);
                
                try {
                    const response = await fetch('/api/detect-file', {
                        method: 'POST',
                        body: formData
                    });
                    const result = await response.json();
                    displayResult(result);
                } catch (error) {
                    alert('检测失败: ' + error.message);
                }
            });
            
            function displayResult(result) {
                const resultDiv = document.getElementById('result');
                const contentDiv = document.getElementById('resultContent');
                
                if (result.success === false) {
                    contentDiv.innerHTML = `<div class="alert alert-danger">错误: ${result.error}</div>`;
                } else if (result.summary) {
                    // 文件检测结果
                    contentDiv.innerHTML = `
                        <div class="alert alert-info">
                            <strong>文件处理完成</strong><br>
                            总日志数: ${result.summary.total_logs}<br>
                            检测到风险: ${result.summary.risks_detected}<br>
                            风险检出率: ${(result.summary.risk_detection_rate * 100).toFixed(2)}%
                        </div>
                        <pre>${JSON.stringify(result, null, 2)}</pre>
                    `;
                } else {
                    // 单条日志检测结果
                    const isRisk = result.risk_result?.is_risk;
                    const alertClass = isRisk ? 'alert-danger' : 'alert-info';
                    const status = isRisk ? '检测到风险' : '未检测到风险';
                    
                    contentDiv.innerHTML = `
                        <div class="alert ${alertClass}">
                            <strong>${status}</strong>
                            ${isRisk ? `<br>风险类型: ${result.risk_result.risk_type}<br>风险等级: ${result.risk_result.risk_level}<br>置信度: ${(result.risk_result.confidence * 100).toFixed(1)}%` : ''}
                        </div>
                        <pre>${JSON.stringify(result, null, 2)}</pre>
                    `;
                }
                
                resultDiv.style.display = 'block';
            }
        </script>
    </body>
    </html>
    """
    
    @app.route('/')
    def index():
        """主页"""
        return render_template_string(HTML_TEMPLATE)
    
    @app.route('/api/detect', methods=['POST'])
    def detect_log():
        """检测单条日志"""
        try:
            data = request.get_json()
            if not data or 'text' not in data:
                return jsonify({'success': False, 'error': '缺少日志文本'}), 400
            
            result = system.process_log_text(data['text'])
            return jsonify(result)
            
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/detect-file', methods=['POST'])
    def detect_file():
        """检测日志文件"""
        try:
            if 'file' not in request.files:
                return jsonify({'success': False, 'error': '缺少文件'}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({'success': False, 'error': '未选择文件'}), 400
            
            # 保存临时文件
            temp_file = f"temp_{int(time.time())}_{file.filename}"
            file.save(temp_file)
            
            try:
                # 处理文件
                result = system.process_log_file(temp_file)
                result['success'] = True
                return jsonify(result)
            finally:
                # 清理临时文件
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                    
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 500
    
    @app.route('/api/stats')
    def get_stats():
        """获取系统统计信息"""
        return jsonify(system.responder.get_statistics())
    
    return app


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='日志风险检测与自动修复系统')
    parser.add_argument('--config', '-c', help='配置文件路径')
    
    subparsers = parser.add_subparsers(dest='command', help='命令')
    
    # CLI模式
    cli_parser = subparsers.add_parser('cli', help='命令行模式')
    cli_parser.add_argument('--file', '-f', help='日志文件路径')
    cli_parser.add_argument('--text', '-t', help='日志文本')
    cli_parser.add_argument('--output', '-o', help='输出报告文件路径')
    
    # API模式
    api_parser = subparsers.add_parser('api', help='Web API模式')
    api_parser.add_argument('--host', default='127.0.0.1', help='服务器地址')
    api_parser.add_argument('--port', type=int, default=5000, help='服务器端口')
    api_parser.add_argument('--debug', action='store_true', help='开启调试模式')
    
    # 训练模式
    train_parser = subparsers.add_parser('train', help='训练机器学习模型')
    
    args = parser.parse_args()
    
    # 创建系统实例
    system = LogSecuritySystem(args.config)
    
    if args.command == 'cli':
        # CLI模式
        if args.file:
            result = system.process_log_file(args.file)
            output = json.dumps(result, ensure_ascii=False, indent=2)
            
            if args.output:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(output)
                print(f"结果已保存到: {args.output}")
            else:
                print(output)
                
        elif args.text:
            result = system.process_log_text(args.text)
            print(json.dumps(result, ensure_ascii=False, indent=2))
            
        else:
            print("请指定 --file 或 --text 参数")
            sys.exit(1)
    
    elif args.command == 'api':
        # API模式
        app = create_flask_app(system)
        host = args.host
        port = args.port
        debug = args.debug
        
        print(f"启动Web服务: http://{host}:{port}")
        app.run(host=host, port=port, debug=debug)
    
    elif args.command == 'train':
        # 训练模式
        print("生成训练数据并训练机器学习模型...")
        training_data = generate_sample_training_data()
        system.detector.train_ml_model(training_data)
        print("训练完成!")
    
    else:
        parser.print_help()


if __name__ == '__main__':
    main()