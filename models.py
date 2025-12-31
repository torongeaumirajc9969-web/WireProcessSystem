from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
# 初始化数据库组件py
db = SQLAlchemy()

# 定义“工艺记录单”的样子
class ProblemRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    # 机台号
    machine_model = db.Column(db.String(20))
    # 问题描述 (比如：炉口断线、收线排线不良、表面有粒子)
    issue_desc = db.Column(db.String(200))
    # 解决措施 (比如：降低炉温、更换导轮、清理模具)
    solution = db.Column(db.String(200))
    # 发生时间
    create_time = db.Column(db.DateTime, default=datetime.now)
class ProcessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_model = db.Column(db.String(50))   # 机型 (高速/低速)
    product_type = db.Column(db.String(50))    # 产品 (铜/铝)
    wire_speed = db.Column(db.String(20))      # 线速 (允许输入文本，如 "40m/min")
    coating_method = db.Column(db.String(20))  # 涂覆方式
    remark = db.Column(db.Text)                # 备注/日志
    # 机台号 (存字符串，如 "1号机")
    machine_model = db.Column(db.String(20))
    # 产品型号 (如 "QA-1/155", "UEW")
    product_type = db.Column(db.String(50))
    # 规格/线径 (如 "0.15mm")
    wire_spec = db.Column(db.String(20))
    # default=datetime.now 表示：只要不特意填，就自动填入当前时间
    create_time = db.Column(db.DateTime, default=datetime.now)