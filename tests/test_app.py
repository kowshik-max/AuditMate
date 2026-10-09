import os, tempfile, pytest
from app import create_app, db, User, Control, Gap, Evidence, Risk, Task
@pytest.fixture()
def app():
    fd,path=tempfile.mkstemp(suffix='.db'); os.close(fd)
    app=create_app({'TESTING':True,'WTF_CSRF_ENABLED':False,'SQLALCHEMY_DATABASE_URI':'sqlite:///'+path,'SECRET_KEY':'test-secret','UPLOAD_FOLDER':tempfile.mkdtemp()})
    yield app
    with app.app_context(): db.session.remove(); db.drop_all()
    os.unlink(path)
@pytest.fixture()
def client(app): return app.test_client()
def login(client): return client.post('/login',data={'username':'admin','password':'ChangeMe123!'},follow_redirects=True)
def test_login_and_dashboard(client):
    r=login(client); assert r.status_code==200; assert b'Overview Dashboard' in r.data
    assert client.get('/').status_code==200
def test_login_rejects_wrong_password(client):
    r=client.post('/login',data={'username':'admin','password':'wrong'},follow_redirects=True); assert b'Invalid username or password' in r.data
def test_control_create_and_csv(client,app):
    login(client)
    r=client.post('/controls/new',data={'title':'Require MFA','description':'Enable MFA','framework':'Internal Baseline','category':'Access Control','owner':'IT Admin','status':'Implemented','risk':'High','next_review':'2027-01-01'},follow_redirects=True)
    assert r.status_code==200
    with app.app_context(): assert Control.query.filter_by(title='Require MFA').first() is not None
    assert b'Download CSV' in client.get('/reports').data
    assert b'Require MFA' in client.get('/reports.csv').data
def test_gap_task_and_risk_create(client,app):
    login(client)
    client.post('/gaps/new',data={'title':'Missing MFA','risk':'High','impact':'Account compromise','action':'Enable MFA','owner':'IT','due_date':'2027-01-01','status':'Open','resolution':''},follow_redirects=True)
    client.post('/tasks/new',data={'title':'Enable MFA','description':'','owner':'IT','priority':'High','due_date':'2027-01-02','status':'To Do','notes':''},follow_redirects=True)
    client.post('/risks/new',data={'title':'Account takeover','cause':'Phishing','likelihood':'4','impact':'5','safeguards':'Partial','treatment':'MFA','owner':'IT','residual_rating':'Not assessed','review_date':'2027-02-01','status':'Planned'},follow_redirects=True)
    with app.app_context(): assert Gap.query.count()==1 and Task.query.count()==1 and Risk.query.count()==1

def test_protected_routes_redirect(client):
    assert client.get('/controls').status_code==302
    assert client.get('/reports.pdf').status_code==302
