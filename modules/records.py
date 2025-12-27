from flask import Blueprint, render_template, request, redirect, send_file
from models import db, ProcessRecord
import pandas as pd
import io

# 创建一个名为 'records' 的模块
records_bp = Blueprint('records', __name__)


# 1. 首页：显示表格
@records_bp.route('/')
def index():
    # 从数据库查出所有记录
    all_data = ProcessRecord.query.order_by(ProcessRecord.id.desc()).all()
    return render_template('index.html', records=all_data)


# 2. 添加功能：接收网页填写的表单
@records_bp.route('/add', methods=['POST'])
def add_record():
    machine = request.form.get('machine')
    product = request.form.get('product')
    speed = request.form.get('speed')
    method = request.form.get('method')
    note = request.form.get('note')

    # 存入数据库
    new_data = ProcessRecord(
        machine_model=machine,
        product_type=product,
        wire_speed=speed,
        coating_method=method,
        remark=note
    )
    db.session.add(new_data)
    db.session.commit()

    return redirect('/')  # 存完后刷新页面


# 3. 导出功能：生成 Excel
@records_bp.route('/export')
def export_data():
    query = ProcessRecord.query.all()

    data_list = [{
        "ID": r.id,
        "记录时间": r.create_time.strftime('%Y-%m-%d %H:%M') if r.create_time else "",  # 新增这一行
        "机型": r.machine_model,
        "产品": r.product_type,
        "线速": r.wire_speed,
        "涂覆方式": r.coating_method,
        "备注/问题": r.remark
    } for r in query]

    # 用 Pandas 生成 Excel
    df = pd.DataFrame(data_list)

    # 在内存中创建文件（不占用硬盘垃圾）
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='工艺数据')
    output.seek(0)

    return send_file(output, download_name="工艺数据表.xlsx", as_attachment=True)


# 4. 删除功能：接收 ID 并删除对应记录
@records_bp.route('/delete/<int:record_id>')
def delete_record(record_id):
    # 根据 ID 查找记录，如果找不到会报错 404 (比较严谨的做法)
    record = ProcessRecord.query.get_or_404(record_id)

    try:
        # 在数据库会话中标记删除
        db.session.delete(record)
        # 提交更改，使其生效
        db.session.commit()
    except Exception as e:
        # 如果出错了（比如数据库锁死），回滚操作以免影响其他数据
        db.session.rollback()
        print(f"删除出错: {e}")

    # 删完后，还是回到首页看结果
    return redirect('/')