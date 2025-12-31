from flask import Flask, render_template, request, redirect, url_for, make_response, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, or_, and_
from datetime import datetime
import os
import csv
import io
import json

from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# ================= 配置部分 =================
basedir = os.path.abspath(os.path.dirname(__file__))
# 升级数据库到 V5 (包含提交状态字段)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'data_v5.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your-secret-key-123456'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# ================= 工艺标准参数库 (保持不变) =================
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


class ProcessRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    create_time = db.Column(db.DateTime, default=datetime.now)
    operator_name = db.Column(db.String(50))

    # --- V6.3 新增：提交状态 ---
    is_submitted = db.Column(db.Boolean, default=False)  # False=草稿(仅自己见), True=已提交(进总库)

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
        # 保存记录逻辑 (默认 is_submitted=False)
        m_type = request.form.get('machine_type')
        m_num = request.form.get('machine_num')
        machine_full = f"L{m_type}-{m_num}" if m_type and m_num else ""
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
            is_submitted=False,  # 默认为草稿
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
        flash('记录已保存为草稿，请在列表中确认无误后点击“提交”', 'info')
        return redirect(url_for('index'))

    # --- 查询逻辑升级 ---
    if current_user.role == 'admin':
        # 管理员：看所有已提交 + 自己未提交的
        records = ProcessRecord.query.filter(
            or_(
                ProcessRecord.is_submitted == True,
                ProcessRecord.operator_name == current_user.username
            )
        ).order_by(ProcessRecord.create_time.desc()).limit(50).all()
    else:
        # 普通用户：只能看自己的 (无论是否提交)
        records = ProcessRecord.query.filter_by(
            operator_name=current_user.username
        ).order_by(ProcessRecord.create_time.desc()).limit(20).all()

    return render_template('index.html', records=records, current_user=current_user)


# --- V6.3 新增：提交记录路由 ---
@app.route('/submit/<int:id>')
@login_required
def submit_record(id):
    record = ProcessRecord.query.get_or_404(id)

    # 只有记录的拥有者才能提交
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

    # --- 删除权限逻辑 ---
    # 1. 管理员可以删除任何记录
    if current_user.role == 'admin':
        db.session.delete(record)
        db.session.commit()
        flash('管理员操作：记录已删除', 'success')
        return redirect(url_for('index'))

    # 2. 普通用户只能删除自己 "未提交" 的记录
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
    # 分析页面只统计 "已提交" 的数据
    base_query = ProcessRecord.query.filter(ProcessRecord.is_submitted == True)

    machine_stats = db.session.query(
        ProcessRecord.machine_model, func.count(ProcessRecord.id)
    ).filter(ProcessRecord.is_submitted == True).group_by(ProcessRecord.machine_model).order_by(
        func.count(ProcessRecord.id).desc()).limit(8).all()

    raw_issues = base_query.filter(ProcessRecord.remark != None, ProcessRecord.remark != "").order_by(
        ProcessRecord.create_time.desc()).limit(15).all()

    analyzed_issues = []
    for issue in raw_issues:
        std_info = get_std_context(issue.machine_model, issue.is_self_bonding, issue.remark)
        analyzed_issues.append({'record': issue, 'std_matches': std_info})

    chart_labels = [m[0] for m in machine_stats if m[0]]
    chart_data = [m[1] for m in machine_stats if m[0]]

    return render_template('analysis.html',
                           analyzed_issues=analyzed_issues,
                           chart_labels=json.dumps(chart_labels),
                           chart_data=json.dumps(chart_data),
                           current_user=current_user)


@app.route('/search_history', methods=['POST'])
@login_required
def search_history():
    keyword = request.form.get('keyword')
    if not keyword: return redirect(url_for('analysis'))
    # 搜索也只搜已提交的
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
    # 导出所有已提交的数据
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


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='admin').first():
            print("初始化：正在创建默认管理员 admin / 123456")
            admin = User(username='admin', role='admin')
            admin.set_password('123456')
            db.session.add(admin)
            db.session.commit()
    if __name__ == '__main__':
        with app.app_context():
            db.create_all()
            # ... (管理员初始化的代码保持不变) ...
            if not User.query.filter_by(username='admin').first():
                # ...
                db.session.commit()

        # === 关键修改在这里 ===
        # host='0.0.0.0' 表示允许任何IP访问
        # port=5000 是端口号，你可以改成别的，比如 80
        app.run(host='0.0.0.0', port=5000, debug=True)