from flask import Flask, render_template, request, redirect, url_for, make_response
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os
import csv
import io

app = Flask(__name__)

# 配置数据库地址
basedir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)


# ================= 数据库模型 =================

# 1. 正常的工艺记录表
class ProcessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_model = db.Column(db.String(20))  # 机台
    product_type = db.Column(db.String(50))  # 型号
    wire_spec = db.Column(db.String(20))  # 规格
    wire_speed = db.Column(db.String(20))  # 线速
    create_time = db.Column(db.DateTime, default=datetime.now)


# 2. 异常问题记录表
class ProblemRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    machine_model = db.Column(db.String(20))  # 机台
    # === 新增的关键字段 ===
    product_type = db.Column(db.String(50))  # 产品型号 (新增)
    wire_spec = db.Column(db.String(20))  # 规格 (新增)
    # ====================
    issue_desc = db.Column(db.String(200))  # 问题描述
    solution = db.Column(db.String(200))  # 解决措施
    create_time = db.Column(db.DateTime, default=datetime.now)


# ================= 路由逻辑 =================

@app.route('/', methods=['GET', 'POST'])
def index():
    # 处理添加“工艺记录”的请求
    if request.method == 'POST':
        machine = request.form.get('machine_model')
        p_type = request.form.get('product_type')
        spec = request.form.get('wire_spec')
        speed = request.form.get('wire_speed')

        new_record = ProcessRecord(
            machine_model=machine,
            product_type=p_type,
            wire_spec=spec,
            wire_speed=speed
        )
        db.session.add(new_record)
        db.session.commit()
        return redirect(url_for('index'))

    # GET请求：查出所有数据传给网页
    process_records = ProcessRecord.query.order_by(ProcessRecord.create_time.desc()).all()
    problem_records = ProblemRecord.query.order_by(ProblemRecord.create_time.desc()).all()

    return render_template('index.html', records=process_records, problems=problem_records)


# 处理“提交异常”的接口
@app.route('/add_problem', methods=['POST'])
def add_problem():
    machine = request.form.get('machine_model')
    p_type = request.form.get('product_type')  # 获取型号
    spec = request.form.get('wire_spec')  # 获取规格
    issue = request.form.get('issue_desc')
    solve = request.form.get('solution')

    new_problem = ProblemRecord(
        machine_model=machine,
        product_type=p_type,
        wire_spec=spec,
        issue_desc=issue,
        solution=solve
    )

    db.session.add(new_problem)
    db.session.commit()

    return redirect(url_for('index'))


# 删除工艺记录
@app.route('/delete_process/<int:id>')
def delete_process(id):
    record = ProcessRecord.query.get_or_404(id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('index'))


# 删除异常记录
@app.route('/delete_problem/<int:id>')
def delete_problem(id):
    record = ProblemRecord.query.get_or_404(id)
    db.session.delete(record)
    db.session.commit()
    return redirect(url_for('index'))


# ================= 导出功能 (核心修改) =================
@app.route('/export_all')
def export_all():
    processes = ProcessRecord.query.all()
    problems = ProblemRecord.query.all()

    combined_list = []

    # 1. 处理正常工艺 (循环1)
    for p in processes:
        combined_list.append({
            'timestamp': p.create_time,
            'time_str': p.create_time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': '正常工艺',
            'machine': p.machine_model,
            'model': p.product_type,
            'spec': p.wire_spec,
            'speed': p.wire_speed,
            'issue': '',
            'solution': ''
        })

    # 2. 处理异常记录 (循环2 - 注意：这里必须和上面的for对齐，不能缩进在里面！)
    for e in problems:
        combined_list.append({
            'timestamp': e.create_time,
            'time_str': e.create_time.strftime('%Y-%m-%d %H:%M:%S'),
            'type': '【异常问题】',
            'machine': e.machine_model,
            'model': e.product_type,  # 现在有型号了
            'spec': e.wire_spec,  # 现在有规格了
            'speed': '',
            'issue': e.issue_desc,
            'solution': e.solution
        })

    # 按时间倒序
    combined_list.sort(key=lambda x: x['timestamp'], reverse=True)

    # 写入 CSV
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['时间', '记录类型', '机台', '产品型号', '规格', '线速', '异常描述', '解决措施'])

    for item in combined_list:
        cw.writerow([
            item['time_str'],
            item['type'],
            item['machine'],
            item['model'],
            item['spec'],
            item['speed'],
            item['issue'],
            item['solution']
        ])

    output = make_response(si.getvalue().encode('utf-8-sig'))
    output.headers["Content-Disposition"] = "attachment; filename=production_log.csv"
    output.headers["Content-type"] = "text/csv"

    return output


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)