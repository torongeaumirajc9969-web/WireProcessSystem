from flask import Flask, render_template, request, redirect, url_for, make_response, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy import func, or_, and_
from datetime import datetime
import os
import csv
import io
import json
import re

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ================= 配置部分 =================
basedir = os.path.abspath(os.path.dirname(__file__))
# 数据库文件路径
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data_v5.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-123456'

db = SQLAlchemy(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ================= 工艺标准参数库 =================
STD_PARAMS = {
    "L1": {
        "normal": {"进口": "170", "下层一": "280", "下层二": "360", "蒸发区": "380", "固化区": "420", "催化前": "420",
                   "催化后": "460", "软化一": "560", "软化二": "580", "排废": "800"}, "self_bonding": {}},
    "L2": {"normal": {"进口": "170", "下层": "280", "蒸发区": "380", "固化区": "420", "一次催化前": "390",
                      "二次催化前": "380", "排废": "1300"}},
    "L5": {"normal": {},
           "self_bonding": {"进口": "110", "下层一": "260", "下层二": "360", "固化区": "440", "软化一": "200",
                            "软化二": "200", "排废": "1500"}},
    "L6": {
        "normal": {"进口A": "160", "下层一": "280", "下层二": "380", "固化区": "470", "软化一": "200", "软化二": "200",
                   "排废": "1500"},
        "self_bonding": {"进口A": "90", "下层一": "250", "下层二": "330", "固化区": "470", "软化一": "200",
                         "软化二": "200", "排废": "1500"}},
    "L7": {
        "normal": {"进口A": "130", "下层一": "260", "下层二": "360", "固化区": "430", "软化一": "200", "软化二": "200",
                   "排废": "1500"},
        "self_bonding": {"进口A": "90", "下层一": "250", "下层二": "330", "固化区": "470", "软化一": "200",
                         "软化二": "200", "排废": "1500"}}
}
STD_PARAMS["L3"] = STD_PARAMS["L2"]
STD_PARAMS["L4"] = STD_PARAMS["L2"]


# ================= 数据库模型 =================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='operator')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# 1. 裸线实验室记录表 (独立表，扁线专用版)
class RawWireRecord(db.Model):
    __tablename__ = 'raw_wire_record'
    id = db.Column(db.Integer, primary_key=True)
    create_time = db.Column(db.DateTime, default=datetime.now)
    operator_name = db.Column(db.String(50))

    # 实验环境
    machine_model = db.Column(db.String(20))
    ref_speed = db.Column(db.String(20))

    # 核心数据 (输入 - 投料)
    raw_size_a = db.Column(db.Float)  # 投料 A (宽)
    raw_size_b = db.Column(db.Float)  # 投料 B (厚)
    yield_strength = db.Column(db.Integer)

    # 核心数据 (输出 - 去漆)
    stripped_size_a = db.Column(db.Float)  # 去漆 A
    stripped_size_b = db.Column(db.Float)  # 去漆 B

    # 计算结果 (吃丝量)
    draw_down_a = db.Column(db.Float)  # A面吃丝
    draw_down_b = db.Column(db.Float)  # B面吃丝

    remark = db.Column(db.Text)


# 2. 生产工艺记录表 (原有)
class ProcessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    create_time = db.Column(db.DateTime, default=datetime.now)
    operator_name = db.Column(db.String(50))

    # 提交状态: False=草稿, True=已提交
    is_submitted = db.Column(db.Boolean, default=False)

    machine_model = db.Column(db.String(20))
    product_type = db.Column(db.String(50))
    wire_spec = db.Column(db.String(20))
    ref_speed = db.Column(db.String(20))
    is_self_bonding = db.Column(db.Boolean, default=False)

    base_coat_type = db.Column(db.String(20))
    base_coat_pass = db.Column(db.String(10))
    mid_coat_type = db.Column(db.String(20))
    mid_coat_pass = db.Column(db.String(10))
    top_coat_type = db.Column(db.String(20))
    top_coat_pass = db.Column(db.String(10))

    tol_a_bare = db.Column(db.String(50))
    tol_a_finished = db.Column(db.String(50))
    tol_a_thickness = db.Column(db.String(50))
    tol_b_bare = db.Column(db.String(50))
    tol_b_finished = db.Column(db.String(50))
    tol_b_thickness = db.Column(db.String(50))
    remark = db.Column(db.Text)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def get_std_context(machine_full, is_sb, remark_text):
    if not machine_full or not remark_text: return []
    m_type = machine_full.split('-')[0]
    if m_type not in STD_PARAMS: return []
    param_set = STD_PARAMS[m_type].get('self_bonding' if is_sb else 'normal') or STD_PARAMS[m_type].get('normal')
    if not param_set: return []
    matches = []
    for key, val in param_set.items():
        if key in remark_text: matches.append({'name': key, 'std_val': val})
    return matches


# ================= 路由逻辑 =================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('用户名或密码错误', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@app.route('/manage_users', methods=['GET', 'POST'])
@login_required
def manage_users():
    if current_user.role != 'admin':
        flash('您没有权限访问人员管理页面', 'warning')
        return redirect(url_for('index'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            new_username = request.form.get('username')
            new_password = request.form.get('password')
            new_role = request.form.get('role')
            if User.query.filter_by(username=new_username).first():
                flash(f'用户 {new_username} 已存在', 'danger')
            else:
                new_user = User(username=new_username, role=new_role)
                new_user.set_password(new_password)
                db.session.add(new_user)
                db.session.commit()
                flash(f'用户 {new_username} 创建成功', 'success')
        elif action == 'delete':
            user_id = request.form.get('user_id')
            user_to_delete = User.query.get(user_id)
            if user_to_delete:
                if user_to_delete.username == 'admin':
                    flash('无法删除超级管理员账号', 'danger')
                elif user_to_delete.id == current_user.id:
                    flash('无法删除自己', 'warning')
                else:
                    db.session.delete(user_to_delete)
                    db.session.commit()
                    flash('用户已删除', 'success')
        return redirect(url_for('manage_users'))
    users = User.query.all()
    return render_template('manage_users.html', users=users, current_user=current_user)


@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        # 保存记录逻辑
        m_type = request.form.get('machine_type')
        m_num = request.form.get('machine_num')
        machine_full = f"L{m_type}-{m_num}" if m_type and m_num else ""

        # 处理自粘
        is_sb = True if request.form.get('is_self_bonding') == 'on' else False
        if m_type in ['2', '3', '4']:
            is_sb = False
        elif m_type == '5':
            is_sb = True

        def fmt_range(min, max):
            return f"{min}~{max}" if min and max else ""

        def fmt_le(val):
            return f"≤{val}" if val else ""

        def fmt_ge(val):
            return f"≥{val}" if val else ""

        new_record = ProcessRecord(
            operator_name=current_user.username,
            is_submitted=False,
            machine_model=machine_full,
            product_type=request.form.get('product_type'),
            wire_spec=request.form.get('wire_spec'),
            ref_speed=request.form.get('ref_speed'),
            is_self_bonding=is_sb,
            base_coat_type=request.form.get('base_coat_type'),
            base_coat_pass=request.form.get('base_coat_pass'),
            mid_coat_type=request.form.get('mid_coat_type'),
            mid_coat_pass=request.form.get('mid_coat_pass'),
            top_coat_type=request.form.get('top_coat_type'),
            top_coat_pass=request.form.get('top_coat_pass'),
            tol_a_bare=fmt_range(request.form.get('tol_a_bare_min'), request.form.get('tol_a_bare_max')),
            tol_a_finished=fmt_le(request.form.get('tol_a_finished_val')),
            tol_a_thickness=fmt_ge(request.form.get('tol_a_thickness_val')),
            tol_b_bare=fmt_range(request.form.get('tol_b_bare_min'), request.form.get('tol_b_bare_max')),
            tol_b_finished=fmt_le(request.form.get('tol_b_finished_val')),
            tol_b_thickness=fmt_ge(request.form.get('tol_b_thickness_val')),
            remark=request.form.get('remark')
        )
        db.session.add(new_record)
        db.session.commit()

        # === 关键修改：把表单数据存入 Session，方便下次自动回填 ===
        session['last_form_data'] = request.form.to_dict()

        flash('记录已保存 (草稿)，数据已保留方便您继续录入', 'success')
        return redirect(url_for('index'))

    # GET 请求：尝试从 Session 获取上次的数据
    last_data = session.get('last_form_data', {})

    # 查询逻辑
    if current_user.role == 'admin':
        records = ProcessRecord.query.filter(
            or_(ProcessRecord.is_submitted == True, ProcessRecord.operator_name == current_user.username)
        ).order_by(ProcessRecord.create_time.desc()).limit(50).all()
    else:
        records = ProcessRecord.query.filter_by(
            operator_name=current_user.username
        ).order_by(ProcessRecord.create_time.desc()).limit(20).all()

    # 将 last_data 传给前端
    return render_template('index.html', records=records, current_user=current_user, last_data=last_data)


@app.route('/submit/<int:id>')
@login_required
def submit_record(id):
    record = ProcessRecord.query.get_or_404(id)
    if record.operator_name != current_user.username:
        flash('您只能提交自己的记录', 'danger')
        return redirect(url_for('index'))
    record.is_submitted = True
    db.session.commit()
    flash('记录已正式提交至总数据库', 'success')
    return redirect(url_for('index'))


@app.route('/delete/<int:id>')
@login_required
def delete_record(id):
    record = ProcessRecord.query.get_or_404(id)
    if current_user.role == 'admin':
        db.session.delete(record)
        db.session.commit()
        flash('管理员操作：记录已删除', 'success')
        return redirect(url_for('index'))
    if record.operator_name == current_user.username:
        if not record.is_submitted:
            db.session.delete(record)
            db.session.commit()
            flash('草稿已删除', 'success')
        else:
            flash('无法删除：该记录已提交，请联系管理员处理', 'warning')
    else:
        flash('权限不足', 'danger')
    return redirect(url_for('index'))


@app.route('/analysis')
@login_required
def analysis():
    # 1. 获取最近 100 条已提交的记录
    records = ProcessRecord.query.filter(ProcessRecord.is_submitted == True) \
        .order_by(ProcessRecord.create_time.asc()).limit(100).all()

    # === 数据清洗与准备 (用于图表) ===
    chart_dates = []  # X轴：时间
    chart_speeds = []  # Y轴：速度
    chart_thickness = []  # Y轴：漆膜厚度 (取A面)
    machine_counts = {}  # 饼图：机台统计

    for r in records:
        # 1. 提取时间 (只取 月-日 时:分)
        d_str = r.create_time.strftime('%m-%d %H:%M')
        chart_dates.append(d_str)

        # 2. 提取速度 (把 "20.0±0.5" 变成 20.0)
        try:
            sp = float(r.ref_speed.split('±')[0]) if r.ref_speed else 0
        except:
            sp = 0
        chart_speeds.append(sp)

        # 3. 提取漆膜厚度 (A面)
        try:
            # 假设数据是纯数字，如果为空则为0
            th = float(r.tol_a_thickness_val) if r.tol_a_thickness_val else 0
        except:
            th = 0
        chart_thickness.append(th)

        # 4. 统计机台产量
        m_name = r.machine_model.split('-')[0] if r.machine_model else "未知"
        machine_counts[m_name] = machine_counts.get(m_name, 0) + 1

    # === 异常记录分析 (保持原逻辑) ===
    raw_issues = ProcessRecord.query.filter(
        ProcessRecord.is_submitted == True,
        ProcessRecord.remark != None,
        ProcessRecord.remark != ""
    ).order_by(ProcessRecord.create_time.desc()).limit(10).all()

    analyzed_issues = []
    for issue in raw_issues:
        std_info = get_std_context(issue.machine_model, issue.is_self_bonding, issue.remark)
        analyzed_issues.append({'record': issue, 'std_matches': std_info})

    return render_template('analysis.html',
                           current_user=current_user,
                           # 传递图表数据 (必须转为 json 字符串)
                           dates_json=json.dumps(chart_dates),
                           speeds_json=json.dumps(chart_speeds),
                           thickness_json=json.dumps(chart_thickness),
                           machine_labels_json=json.dumps(list(machine_counts.keys())),
                           machine_data_json=json.dumps(list(machine_counts.values())),
                           analyzed_issues=analyzed_issues)


@app.route('/search_history', methods=['POST'])
@login_required
def search_history():
    keyword = request.form.get('keyword')
    if not keyword: return redirect(url_for('analysis'))
    results = ProcessRecord.query.filter(
        and_(
            ProcessRecord.is_submitted == True,
            or_(
                ProcessRecord.remark.contains(keyword),
                ProcessRecord.product_type.contains(keyword),
                ProcessRecord.machine_model.contains(keyword)
            )
        )
    ).order_by(ProcessRecord.create_time.desc()).all()

    analyzed_results = []
    for r in results:
        std_info = get_std_context(r.machine_model, r.is_self_bonding, r.remark)
        analyzed_results.append({'record': r, 'std_matches': std_info})

    return render_template('analysis.html', search_results=analyzed_results, keyword=keyword, current_user=current_user)


@app.route('/export_all')
@login_required
def export_all():
    records = ProcessRecord.query.filter(ProcessRecord.is_submitted == True).all()
    si = io.StringIO()
    cw = csv.writer(si)
    headers = ['时间', '操作员', '机台', '产品型号', '自粘/缩醛', '规格', '速度', '底漆', '中漆', '面漆', 'A面成品',
               '备注']
    cw.writerow(headers)
    for r in records:
        sb_text = "是" if r.is_self_bonding else "否"
        cw.writerow([
            r.create_time.strftime('%Y-%m-%d %H:%M'),
            r.operator_name,
            r.machine_model, r.product_type, sb_text, r.wire_spec, r.ref_speed,
            r.base_coat_type, r.mid_coat_type, r.top_coat_type,
            r.tol_a_finished, r.remark
        ])
    output = make_response(si.getvalue().encode('utf-8-sig'))
    output.headers["Content-Disposition"] = "attachment; filename=production_log_v5.csv"
    output.headers["Content-type"] = "text/csv"
    return output


# ==========================================
#           模块二：裸线标准实验室 (扁线版)
# ==========================================

# 1. 实验室录入页面
@app.route('/raw_lab', methods=['GET', 'POST'])
@login_required
def raw_lab():
    if request.method == 'POST':
        try:
            # 获取 A/B 面数据
            ra = float(request.form.get('raw_size_a'))
            rb = float(request.form.get('raw_size_b'))
            sa = float(request.form.get('stripped_size_a'))
            sb = float(request.form.get('stripped_size_b'))

            # 分别计算吃丝量
            draw_a = ra - sa
            draw_b = rb - sb
        except:
            draw_a = 0
            draw_b = 0

        new_test = RawWireRecord(
            operator_name=current_user.username,
            machine_model=request.form.get('machine_model'),
            ref_speed=request.form.get('ref_speed'),
            raw_size_a=ra,
            raw_size_b=rb,
            yield_strength=request.form.get('yield_strength'),
            stripped_size_a=sa,
            stripped_size_b=sb,
            draw_down_a=draw_a,
            draw_down_b=draw_b,
            remark=request.form.get('remark')
        )
        db.session.add(new_test)
        db.session.commit()
        flash('扁线样本数据已录入', 'success')
        return redirect(url_for('raw_lab'))

    records = RawWireRecord.query.order_by(RawWireRecord.create_time.desc()).limit(20).all()
    return render_template('raw_lab.html', records=records, current_user=current_user)


# 2. 实验室分析看板
@app.route('/raw_analysis')
@login_required
def raw_analysis():
    records = RawWireRecord.query.all()

    # 准备散点图数据 (分为 A组 和 B组)
    # 屈服强度 vs 吃丝量
    yield_data_a = []
    yield_data_b = []

    # 速度 vs 吃丝量
    speed_data_a = []
    speed_data_b = []

    for r in records:
        # 过滤无效数据
        if r.draw_down_a is not None and r.draw_down_b is not None:
            # 强度分析
            if r.yield_strength:
                yield_data_a.append({'x': r.yield_strength, 'y': round(r.draw_down_a, 4)})
                yield_data_b.append({'x': r.yield_strength, 'y': round(r.draw_down_b, 4)})

            # 速度分析
            if r.ref_speed:
                try:
                    sp = float(r.ref_speed)
                    speed_data_a.append({'x': sp, 'y': round(r.draw_down_a, 4)})
                    speed_data_b.append({'x': sp, 'y': round(r.draw_down_b, 4)})
                except:
                    pass

    return render_template('raw_analysis.html',
                           current_user=current_user,
                           yield_a=json.dumps(yield_data_a),
                           yield_b=json.dumps(yield_data_b),
                           speed_a=json.dumps(speed_data_a),
                           speed_b=json.dumps(speed_data_b))


# 3. 删除实验记录
@app.route('/delete_raw/<int:id>')
@login_required
def delete_raw(id):
    r = RawWireRecord.query.get_or_404(id)
    db.session.delete(r)
    db.session.commit()
    flash('实验记录已删除', 'warning')
    return redirect(url_for('raw_lab'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            print("初始化：正在创建默认管理员 admin / 123456")
            admin = User(username='admin', role='admin')
            admin.set_password('123456')
            db.session.add(admin)
            db.session.commit()

    # host='0.0.0.0' 表示允许任何IP访问
    app.run(host='0.0.0.0', port=5000, debug=True)