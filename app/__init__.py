import os, secrets, csv, io, json
from datetime import datetime, date, timedelta
from functools import wraps
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import func, or_

db = SQLAlchemy()
csrf = CSRFProtect()
ALLOWED_UPLOADS = {"pdf", "png", "jpg", "jpeg", "txt", "csv"}

class User(db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), unique=True, nullable=False); password_hash=db.Column(db.String(255), nullable=False); role=db.Column(db.String(20), default="analyst", nullable=False)
class Control(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(180), nullable=False); description=db.Column(db.Text, default=""); framework=db.Column(db.String(100), default="Internal Baseline"); category=db.Column(db.String(80), default="Access Control"); owner=db.Column(db.String(100), default="Unassigned"); status=db.Column(db.String(40), default="Not Assessed"); risk=db.Column(db.String(20), default="Medium"); next_review=db.Column(db.Date, nullable=True); created_at=db.Column(db.DateTime, default=datetime.utcnow)
class Evidence(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(180), nullable=False); control_id=db.Column(db.Integer, db.ForeignKey('control.id'), nullable=True); evidence_type=db.Column(db.String(60), default="Other"); submitted_by=db.Column(db.String(100), default=""); status=db.Column(db.String(40), default="Pending Review"); notes=db.Column(db.Text, default=""); filename=db.Column(db.String(255), default=""); review_date=db.Column(db.Date, nullable=True); created_at=db.Column(db.DateTime, default=datetime.utcnow); control=db.relationship('Control')
class Gap(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(180), nullable=False); control_id=db.Column(db.Integer, db.ForeignKey('control.id'), nullable=True); risk=db.Column(db.String(20), default="Medium"); impact=db.Column(db.Text, default=""); action=db.Column(db.Text, default=""); owner=db.Column(db.String(100), default="Unassigned"); due_date=db.Column(db.Date, nullable=True); status=db.Column(db.String(40), default="Open"); resolution=db.Column(db.Text, default=""); created_at=db.Column(db.DateTime, default=datetime.utcnow); control=db.relationship('Control')
class Risk(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(180), nullable=False); control_id=db.Column(db.Integer, db.ForeignKey('control.id'), nullable=True); cause=db.Column(db.Text, default=""); likelihood=db.Column(db.Integer, default=3); impact=db.Column(db.Integer, default=3); safeguards=db.Column(db.Text, default=""); treatment=db.Column(db.Text, default=""); owner=db.Column(db.String(100), default="Unassigned"); residual_rating=db.Column(db.String(20), default="Not assessed"); review_date=db.Column(db.Date, nullable=True); status=db.Column(db.String(40), default="Planned"); created_at=db.Column(db.DateTime, default=datetime.utcnow); control=db.relationship('Control')
    @property
    def score(self): return int(self.likelihood or 1)*int(self.impact or 1)
    @property
    def rating(self): return "High" if self.score>=15 else ("Medium" if self.score>=8 else "Low")
class Task(db.Model):
    id=db.Column(db.Integer, primary_key=True); title=db.Column(db.String(180), nullable=False); gap_id=db.Column(db.Integer, db.ForeignKey('gap.id'), nullable=True); description=db.Column(db.Text, default=""); owner=db.Column(db.String(100), default="Unassigned"); priority=db.Column(db.String(20), default="Medium"); due_date=db.Column(db.Date, nullable=True); status=db.Column(db.String(40), default="To Do"); notes=db.Column(db.Text, default=""); created_at=db.Column(db.DateTime, default=datetime.utcnow); gap=db.relationship('Gap')
class AuditLog(db.Model):
    id=db.Column(db.Integer, primary_key=True); username=db.Column(db.String(80), default="system"); action=db.Column(db.String(100), nullable=False); record_type=db.Column(db.String(60), default=""); record_id=db.Column(db.Integer, nullable=True); details=db.Column(db.Text, default=""); created_at=db.Column(db.DateTime, default=datetime.utcnow)

def audit(action, typ="", rid=None, details=""):
    db.session.add(AuditLog(username=session.get('username','system'), action=action, record_type=typ, record_id=rid, details=details[:1000]))

def login_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if not session.get('user_id'): return redirect(url_for('login', next=request.path))
        return fn(*a, **kw)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*a, **kw):
        if session.get('role') != 'admin': abort(403)
        return fn(*a, **kw)
    return wrapped

def parse_date(value):
    if not value: return None
    try: return date.fromisoformat(value)
    except ValueError: return None

def create_app(test_config=None):
    app=Flask(__name__)
    app.config.update(SECRET_KEY=os.getenv('SECRET_KEY','dev-only-change-me'), SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL','sqlite:///auditmate.db'), SQLALCHEMY_TRACK_MODIFICATIONS=False, MAX_CONTENT_LENGTH=5*1024*1024, UPLOAD_FOLDER=str(Path(app.root_path)/'static'/'uploads'), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax', SESSION_COOKIE_SECURE=False)
    if test_config: app.config.update(test_config)
    db.init_app(app); csrf.init_app(app)
    app.jinja_env.globals["getattr"] = getattr
    Path(app.config['UPLOAD_FOLDER']).mkdir(parents=True, exist_ok=True)
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username=os.getenv('ADMIN_USERNAME','admin')).first():
            db.session.add(User(username=os.getenv('ADMIN_USERNAME','admin'), password_hash=generate_password_hash(os.getenv('ADMIN_PASSWORD','ChangeMe123!')), role='admin'))
            db.session.commit()
        if Control.query.count()==0:
            demo=[('Require MFA for staff accounts','Access Control','Not Implemented','High'),('Quarterly access reviews','Access Control','Partially Implemented','Medium'),('Maintain asset inventory','Asset Management','Implemented','Medium'),('Test incident response plan','Incident Management','Partially Implemented','High'),('Apply critical security patches promptly','Vulnerability Management','Not Implemented','High'),('Test backups and restoration','Backup and Recovery','Pending Review','High')]
            for title,cat,status,risk in demo: db.session.add(Control(title=title,description='Illustrative demo control. Assess using your organisation evidence.',category=cat,status=status,risk=risk,framework='Internal Baseline',owner='IT Admin'))
            db.session.commit()
    @app.after_request
    def headers(resp):
        resp.headers['X-Content-Type-Options']='nosniff'; resp.headers['X-Frame-Options']='DENY'; resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'; resp.headers['Content-Security-Policy']="default-src 'self' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; img-src 'self' data:;"
        return resp
    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method=='POST':
            u=User.query.filter_by(username=request.form.get('username','').strip()).first()
            if u and check_password_hash(u.password_hash, request.form.get('password','')):
                session.clear(); session['user_id']=u.id; session['username']=u.username; session['role']=u.role
                audit('Login','User',u.id,'Successful login'); db.session.commit(); return redirect(request.args.get('next') or url_for('dashboard'))
            flash('Invalid username or password.','error')
        return render_template('login.html')
    @app.route('/logout', methods=['POST'])
    @login_required
    def logout():
        audit('Logout','User',session.get('user_id'),'User logged out'); db.session.commit(); session.clear(); return redirect(url_for('login'))
    @app.route('/')
    @login_required
    def dashboard():
        counts={'controls':Control.query.count(),'compliant':Control.query.filter_by(status='Implemented').count(),'gaps':Gap.query.filter(Gap.status.notin_(['Closed','Accepted Risk'])).count(),'evidence_pending':Evidence.query.filter_by(status='Pending Review').count(),'tasks_open':Task.query.filter(Task.status!='Completed').count(),'tasks_overdue':Task.query.filter(Task.due_date < date.today(),Task.status!='Completed').count()}
        statuses=db.session.query(Control.status,func.count(Control.id)).group_by(Control.status).all()
        recent=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all()
        return render_template('dashboard.html',counts=counts,statuses=statuses,recent=recent)
    specs={
      'controls':('Security Controls',Control,[('title','Title','text'),('description','Description','textarea'),('framework','Framework','text'),('category','Category','text'),('owner','Owner','text'),('status','Status','select:Not Assessed|Implemented|Partially Implemented|Not Implemented|Not Applicable|Pending Review'),('risk','Risk','select:Low|Medium|High'),('next_review','Next review','date')]),
      'evidence':('Evidence Management',Evidence,[('title','Title','text'),('control_id','Related control','control'),('evidence_type','Evidence type','text'),('submitted_by','Submitted by','text'),('status','Review status','select:Pending Review|Approved|Rejected'),('notes','Review notes','textarea'),('review_date','Review date','date')]),
      'gaps':('Compliance Gaps',Gap,[('title','Title','text'),('control_id','Related control','control'),('risk','Risk','select:Low|Medium|High'),('impact','Business impact','textarea'),('action','Recommended action','textarea'),('owner','Assigned owner','text'),('due_date','Due date','date'),('status','Status','select:Open|Triaged|In Progress|Pending Verification|Closed|Accepted Risk'),('resolution','Resolution / risk acceptance reason','textarea')]),
      'risks':('Risk Register',Risk,[('title','Risk title','text'),('control_id','Related control','control'),('cause','Threat or cause','textarea'),('likelihood','Likelihood (1–5)','number'),('impact','Impact (1–5)','number'),('safeguards','Existing safeguards','textarea'),('treatment','Proposed treatment','textarea'),('owner','Risk owner','text'),('residual_rating','Residual rating','select:Not assessed|Low|Medium|High'),('review_date','Review date','date'),('status','Treatment status','select:Planned|In Progress|Treated|Accepted')]),
      'tasks':('Remediation Tasks',Task,[('title','Task title','text'),('gap_id','Related gap','gap'),('description','Description','textarea'),('owner','Assigned owner','text'),('priority','Priority','select:Low|Medium|High'),('due_date','Due date','date'),('status','Status','select:To Do|In Progress|Blocked|Pending Review|Completed'),('notes','Completion notes','textarea')])}
    @app.route('/<kind>')
    @login_required
    def listing(kind):
        if kind not in specs: abort(404)
        title,model,fields=specs[kind]; q=request.args.get('q','').strip()
        query=model.query
        if q:
            searchable=[]
            for col in model.__table__.columns:
                if str(col.type).upper().startswith(('VARCHAR','TEXT')): searchable.append(col.ilike(f'%{q}%'))
            if searchable: query=query.filter(or_(*searchable))
        rows=query.order_by(model.id.desc()).all()
        return render_template('listing.html',kind=kind,title=title,fields=fields,rows=rows,controls=Control.query.order_by(Control.title).all(),gaps=Gap.query.order_by(Gap.title).all(),q=q)
    @app.route('/<kind>/new', methods=['GET','POST'])
    @login_required
    def create_record(kind):
        if kind not in specs: abort(404)
        title,model,fields=specs[kind]
        if request.method=='POST':
            obj=model()
            for key,label,typ in fields:
                val=request.form.get(key,'').strip()
                if key in ('likelihood','impact'):
                    try: val=max(1,min(5,int(val or 3)))
                    except ValueError: val=3
                elif key in ('control_id','gap_id'):
                    try: val=int(val) if val else None
                    except ValueError: val=None
                elif typ=='date': val=parse_date(val)
                elif typ.startswith('select:') and val not in typ.split(':',1)[1].split('|'): val=typ.split(':',1)[1].split('|')[0]
                if hasattr(obj,key): setattr(obj,key,val)
            if not getattr(obj,'title',None): flash('Title is required.','error'); return render_template('form.html',kind=kind,title=title,fields=fields,obj=obj,controls=Control.query.all(),gaps=Gap.query.all())
            db.session.add(obj); db.session.flush(); audit('Created',kind,obj.id,f'Created {title.lower()}: {obj.title}'); db.session.commit(); flash(f'{title[:-1] if title.endswith("s") else title} created.','success'); return redirect(url_for('listing',kind=kind))
        return render_template('form.html',kind=kind,title=title,fields=fields,obj=None,controls=Control.query.all(),gaps=Gap.query.all())
    @app.route('/<kind>/<int:rid>/delete', methods=['POST'])
    @login_required
    def delete_record(kind,rid):
        if kind not in specs: abort(404)
        _,model,_=specs[kind]; obj=db.session.get(model,rid)
        if not obj: abort(404)
        if kind=='controls' and (Evidence.query.filter_by(control_id=rid).first() or Gap.query.filter_by(control_id=rid).first() or Risk.query.filter_by(control_id=rid).first()):
            flash('Cannot delete a control that has linked evidence, gaps, or risks.','error'); return redirect(url_for('listing',kind=kind))
        if kind=='gaps' and Task.query.filter_by(gap_id=rid).first(): flash('Cannot delete a gap that has linked tasks.','error'); return redirect(url_for('listing',kind=kind))
        name=getattr(obj,'title',str(rid)); audit('Deleted',kind,rid,f'Deleted record: {name}'); db.session.delete(obj); db.session.commit(); flash('Record deleted.','success'); return redirect(url_for('listing',kind=kind))
    @app.route('/evidence/<int:rid>/upload', methods=['POST'])
    @login_required
    def upload_evidence(rid):
        ev=db.session.get(Evidence,rid)
        if not ev: abort(404)
        f=request.files.get('file')
        if not f or not f.filename: flash('Choose a file first.','error'); return redirect(url_for('listing',kind='evidence'))
        name=secure_filename(f.filename); ext=name.rsplit('.',1)[-1].lower() if '.' in name else ''
        if ext not in ALLOWED_UPLOADS: flash('Unsupported file type. Allowed: PDF, PNG, JPG, TXT, CSV.','error'); return redirect(url_for('listing',kind='evidence'))
        stored=f'{secrets.token_hex(12)}_{name}'; f.save(os.path.join(app.config['UPLOAD_FOLDER'],stored)); ev.filename=stored; audit('Evidence file uploaded','Evidence',ev.id,f'Uploaded file {name}'); db.session.commit(); flash('Evidence file uploaded securely.','success'); return redirect(url_for('listing',kind='evidence'))
    @app.route('/evidence-file/<int:rid>')
    @login_required
    def evidence_file(rid):
        ev=db.session.get(Evidence,rid)
        if not ev or not ev.filename: abort(404)
        return send_file(os.path.join(app.config['UPLOAD_FOLDER'],ev.filename), as_attachment=True, download_name=ev.filename.split('_',1)[-1])
    @app.route('/audit')
    @login_required
    def audit_page(): return render_template('audit.html',rows=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(250).all())
    @app.route('/reports')
    @login_required
    def reports(): return render_template('reports.html')
    @app.route('/reports.csv')
    @login_required
    def report_csv():
        output=io.StringIO(); w=csv.writer(output); w.writerow(['Control ID','Control','Category','Status','Risk','Owner','Next review'])
        for c in Control.query.order_by(Control.id).all(): w.writerow([c.id,c.title,c.category,c.status,c.risk,c.owner,c.next_review or ''])
        resp=make_response('\ufeff'+output.getvalue()); resp.headers['Content-Type']='text/csv; charset=utf-8'; resp.headers['Content-Disposition']='attachment; filename=auditmate-controls-report.csv'; audit('Exported CSV report','Report',None,'Controls report'); db.session.commit(); return resp
    @app.route('/reports.pdf')
    @login_required
    def report_pdf():
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet
        mem=io.BytesIO(); doc=SimpleDocTemplate(mem,pagesize=landscape(A4)); styles=getSampleStyleSheet(); story=[Paragraph('AuditMate — Security Controls Summary',styles['Title']),Paragraph(f'Generated {datetime.utcnow():%Y-%m-%d %H:%M} UTC. Illustrative management report; not a certification.',styles['Normal']),Spacer(1,12)]
        data=[['ID','Control','Category','Status','Risk','Owner']]
        for c in Control.query.order_by(Control.id).all(): data.append([str(c.id),c.title[:55],c.category,c.status,c.risk,c.owner])
        t=Table(data,repeatRows=1,colWidths=[35,250,120,110,55,100]); t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),colors.HexColor('#172554')),('TEXTCOLOR',(0,0),(-1,0),colors.white),('GRID',(0,0),(-1,-1),.3,colors.grey),('VALIGN',(0,0),(-1,-1),'TOP'),('FONTSIZE',(0,0),(-1,-1),8)])); story.append(t); doc.build(story); mem.seek(0); audit('Exported PDF report','Report',None,'Controls summary PDF'); db.session.commit(); return send_file(mem,as_attachment=True,download_name='auditmate-controls-report.pdf',mimetype='application/pdf')
    @app.route('/settings',methods=['GET','POST'])
    @login_required
    def settings():
        if request.method=='POST': session['org_name']=request.form.get('org_name','AuditMate Demo Workspace')[:120]; flash('Workspace setting saved for this session.','success'); return redirect(url_for('settings'))
        return render_template('settings.html',org_name=session.get('org_name','AuditMate Demo Workspace'))
    @app.errorhandler(403)
    def forbidden(e): return render_template('error.html',code=403,message='You do not have permission to view this page.'),403
    @app.errorhandler(413)
    def too_large(e): return render_template('error.html',code=413,message='Upload exceeds the 5 MB limit.'),413
    return app
